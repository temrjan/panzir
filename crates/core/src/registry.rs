//! Реестр хранилищ `~/.config/panzir/vaults.toml`.
//!
//! Все мутации — через [`Registry::with_write_lock`], который держит
//! exclusive advisory flock на весь интервал load→modify→save.
//! Это предотвращает race, при котором два процесса panzir добавляют
//! записи с одинаковой меткой.

use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt as _;
use tokio::task;

use crate::vault::{DEFAULT_AUTO_CLOSE, Label, VaultKind, VaultState};
use crate::{Error, Result};

/// Запись в реестре. Поля приватные — состояние меняется только методами.
#[derive(Debug, Clone)]
pub struct VaultEntry {
    label: Label,
    kind: VaultKind,
    state: VaultState,
    /// Срок автозакрытия; `None` — не закрывать (спека С-7: «никогда» —
    /// отдельное значение, не сентинел в числе).
    auto_close: Option<Duration>,
    /// Сколько раз подряд автозакрытие отступило перед занятым томом
    /// (спека С-8). Ноль — отложенного закрытия нет.
    close_attempts: u8,
    /// Момент первой неудачи текущей серии, секунды Unix — карточке есть что
    /// показать («не закрывается с …»).
    close_deferred_since: Option<u64>,
}

impl VaultEntry {
    /// Создать новую запись со сроком автозакрытия по умолчанию.
    pub fn new(label: Label, kind: VaultKind, state: VaultState) -> Self {
        Self {
            label,
            kind,
            state,
            auto_close: Some(DEFAULT_AUTO_CLOSE),
            close_attempts: 0,
            close_deferred_since: None,
        }
    }

    /// Сколько раз подряд автозакрытие отступило перед занятым томом.
    pub fn close_attempts(&self) -> u8 {
        self.close_attempts
    }

    /// Момент первой неудачи текущей серии отложенных закрытий.
    pub fn close_deferred_since(&self) -> Option<u64> {
        self.close_deferred_since
    }

    /// Автозакрытие отступило ещё раз: счётчик растёт, момент первой неудачи
    /// не сдвигается.
    pub fn note_close_deferred(&mut self, now: u64) {
        self.close_attempts = self.close_attempts.saturating_add(1);
        self.close_deferred_since.get_or_insert(now);
    }

    /// Серия кончилась — закрылось: и счётчик, и момент первой неудачи снимаются.
    pub fn reset_close_deferral(&mut self) {
        self.close_attempts = 0;
        self.close_deferred_since = None;
    }

    /// Попытки исчерпаны, часы заведены на полный срок: счётчик с нуля, а
    /// момент первой неудачи остаётся — карточке нужно «не закрывается с …».
    pub fn restart_close_attempts(&mut self) {
        self.close_attempts = 0;
    }

    /// Переставить дедлайн автозакрытия у открытого тома (перезавод часов).
    ///
    /// # Errors
    /// [`Error::InvalidState`], если том не открыт: дедлайн есть только у
    /// открытого.
    pub fn set_until(&mut self, until: Option<u64>) -> Result<()> {
        match &mut self.state {
            VaultState::Open { until: slot, .. } => {
                *slot = until;
                Ok(())
            }
            other => Err(Error::InvalidState {
                from: state_name(other),
                to: "open (deadline change)",
            }),
        }
    }

    /// Та же запись с другим сроком автозакрытия.
    #[must_use]
    pub fn with_auto_close(mut self, auto_close: Option<Duration>) -> Self {
        self.auto_close = auto_close;
        self
    }

    /// Срок автозакрытия; `None` — не закрывать.
    pub fn auto_close(&self) -> Option<Duration> {
        self.auto_close
    }

    /// Сменить срок автозакрытия (внутри [`Registry::with_write_lock`]).
    pub fn set_auto_close(&mut self, auto_close: Option<Duration>) {
        self.auto_close = auto_close;
    }

    /// Метка хранилища.
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// Вид хранилища (файл или устройство).
    pub fn kind(&self) -> &VaultKind {
        &self.kind
    }

    /// Текущее состояние хранилища.
    pub fn state(&self) -> &VaultState {
        &self.state
    }

    /// Валидные переходы состояния записи:
    /// - Closed ↔ Open
    /// - Open → Disconnected
    /// - Closed → Disconnected
    /// - Disconnected → Closed
    pub fn set_state(&mut self, state: VaultState) -> Result<()> {
        let from = state_name(&self.state);
        let to = state_name(&state);

        let allowed = matches!(
            (&self.state, &state),
            (VaultState::Closed, VaultState::Open { .. })
                | (VaultState::Disconnected, VaultState::Open { .. })
                | (VaultState::Open { .. }, VaultState::Closed)
                | (VaultState::Open { .. }, VaultState::Disconnected)
                | (VaultState::Closed, VaultState::Disconnected)
                | (VaultState::Disconnected, VaultState::Closed)
        );

        if !allowed {
            return Err(Error::InvalidState { from, to });
        }
        self.state = state;
        Ok(())
    }
}

fn state_name(state: &VaultState) -> &'static str {
    match state {
        VaultState::Closed => "closed",
        VaultState::Open { .. } => "open",
        VaultState::Disconnected => "disconnected",
    }
}

/// Реестр хранилищ.
#[derive(Debug, Clone)]
pub struct Registry {
    path: PathBuf,
    entries: Vec<VaultEntry>,
}

/// Представление реестра на диске.
#[derive(Debug, Serialize, Deserialize)]
struct StoredRegistry {
    vaults: Vec<StoredEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredEntry {
    label: String,
    #[serde(flatten)]
    kind: StoredKind,
    state: StoredState,
    /// Отсутствует в файлах до автозакрытия → срок по умолчанию, миграции нет.
    #[serde(default)]
    auto_close_sec: StoredAutoClose,
    /// Ключи отложенного закрытия пишутся только пока оно идёт: здоровый файл
    /// их не видит, старый — читает без миграции.
    #[serde(default, skip_serializing_if = "is_zero")]
    close_attempts: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    close_deferred_since: Option<u64>,
}

fn is_zero(n: &u8) -> bool {
    *n == 0
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredKind {
    File { path: PathBuf },
    Device { uuid: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredState {
    Closed,
    Open {
        mount_point: PathBuf,
        /// `None` в TOML не выразим — поле просто отсутствует.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        until: Option<u64>,
    },
    Disconnected,
}

/// Срок на диске: число секунд или слово `"never"`. Секунды, а не минуты —
/// живой IT заводит таймер на единицы секунд. Слово вместо нуля — чтобы
/// «не закрывать» читалось глазами и не путалось с опечаткой.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum StoredAutoClose {
    Seconds(u64),
    Never(NeverWord),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum NeverWord {
    Never,
}

impl Default for StoredAutoClose {
    fn default() -> Self {
        Self::Seconds(DEFAULT_AUTO_CLOSE.as_secs())
    }
}

impl From<Option<Duration>> for StoredAutoClose {
    fn from(auto_close: Option<Duration>) -> Self {
        match auto_close {
            Some(d) => Self::Seconds(d.as_secs()),
            None => Self::Never(NeverWord::Never),
        }
    }
}

impl From<StoredAutoClose> for Option<Duration> {
    fn from(stored: StoredAutoClose) -> Self {
        match stored {
            StoredAutoClose::Seconds(s) => Some(Duration::from_secs(s)),
            StoredAutoClose::Never(NeverWord::Never) => None,
        }
    }
}

impl Registry {
    /// Путь к файлу реестра по умолчанию.
    pub fn default_path() -> Result<PathBuf> {
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .ok_or(Error::NoHome)?;
        Ok(PathBuf::from(home)
            .join(".config")
            .join("panzir")
            .join("vaults.toml"))
    }

    /// Загрузить реестр по умолчанию. Если файла нет — вернуть пустой.
    pub async fn load() -> Result<Self> {
        Self::load_from(&Self::default_path()?).await
    }

    /// Загрузить реестр из указанного пути. Если файла нет — вернуть пустой.
    pub async fn load_from(path: &Path) -> Result<Self> {
        match fs::read_to_string(path).await {
            Ok(text) if text.trim().is_empty() => Ok(Self {
                path: path.to_owned(),
                entries: Vec::new(),
            }),
            Ok(text) => Self::parse(path, &text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path: path.to_owned(),
                entries: Vec::new(),
            }),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn parse(path: &Path, text: &str) -> Result<Self> {
        let stored: StoredRegistry = toml::from_str(text)
            .map_err(|e| Error::Registry(format!("cannot parse registry {path:?}: {e}")))?;
        let entries = stored
            .vaults
            .into_iter()
            .map(|v| {
                Ok(VaultEntry {
                    label: Label::new(&v.label)?,
                    kind: match v.kind {
                        StoredKind::File { path } => VaultKind::File(path),
                        StoredKind::Device { uuid } => VaultKind::Device { uuid },
                    },
                    state: match v.state {
                        StoredState::Closed => VaultState::Closed,
                        StoredState::Open { mount_point, until } => {
                            VaultState::Open { mount_point, until }
                        }
                        StoredState::Disconnected => VaultState::Disconnected,
                    },
                    auto_close: v.auto_close_sec.into(),
                    close_attempts: v.close_attempts,
                    close_deferred_since: v.close_deferred_since,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            path: path.to_owned(),
            entries,
        })
    }

    /// Выполнить read-modify-write под exclusive advisory flock.
    ///
    /// Блокировка `LOCK_EX | LOCK_NB`: если другой процесс panzir уже
    /// держит лок, возвращаем [`Error::AlreadyRunning`].
    /// Сохранение происходит автоматически при успешном замыкании.
    pub async fn with_write_lock<F, T>(f: F) -> Result<T>
    where
        F: FnOnce(&mut Registry) -> Result<T>,
    {
        let path = Self::default_path()?;
        Self::with_write_lock_at(&path, f).await
    }

    /// Тоже самое, но с явным путём (для тестов и нестандартных расположений).
    pub async fn with_write_lock_at<F, T>(path: &Path, f: F) -> Result<T>
    where
        F: FnOnce(&mut Registry) -> Result<T>,
    {
        let parent = path
            .parent()
            .ok_or_else(|| Error::Registry("registry path has no parent".to_owned()))?;
        fs::create_dir_all(parent).await.map_err(Error::Io)?;
        fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(Error::Io)?;

        // Открываем файл синхронно — flock работает с fd.
        let file = task::spawn_blocking({
            let path = path.to_owned();
            move || {
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .open(&path)
            }
        })
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))?
        .map_err(Error::Io)?;

        // Берём exclusive non-blocking flock в блокирующем треде.
        let file = task::spawn_blocking(move || {
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => Ok(file),
                Err(_) => Err(Error::AlreadyRunning),
            }
        })
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))?;

        let file = file?;

        // Читаем текущее содержимое под локом.
        let text = task::spawn_blocking({
            let path = path.to_owned();
            move || {
                use std::io::Read;
                let mut f = std::fs::File::open(&path)?;
                let mut text = String::new();
                f.read_to_string(&mut text)?;
                Ok::<_, std::io::Error>(text)
            }
        })
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))?
        .map_err(Error::Io)?;

        let mut registry = if text.trim().is_empty() {
            Self {
                path: path.to_owned(),
                entries: Vec::new(),
            }
        } else {
            Self::parse(path, &text)?
        };

        let result = f(&mut registry);

        if result.is_ok() {
            registry.save_atomic().await?;
        }

        // Лок снимается автоматически при закрытии fd.
        drop(file);

        result
    }

    async fn save_atomic(&self) -> Result<()> {
        let stored = StoredRegistry {
            vaults: self
                .entries
                .iter()
                .map(|e| StoredEntry {
                    label: e.label.as_str().to_owned(),
                    kind: match &e.kind {
                        VaultKind::File(path) => StoredKind::File { path: path.clone() },
                        VaultKind::Device { uuid } => StoredKind::Device { uuid: uuid.clone() },
                    },
                    state: match &e.state {
                        VaultState::Closed => StoredState::Closed,
                        VaultState::Open { mount_point, until } => StoredState::Open {
                            mount_point: mount_point.clone(),
                            until: *until,
                        },
                        VaultState::Disconnected => StoredState::Disconnected,
                    },
                    auto_close_sec: e.auto_close.into(),
                    close_attempts: e.close_attempts,
                    close_deferred_since: e.close_deferred_since,
                })
                .collect(),
        };
        let text = toml::to_string(&stored)
            .map_err(|e| Error::Registry(format!("cannot serialize registry: {e}")))?;

        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp = self
            .path
            .with_extension(format!("tmp.{}-{}", std::process::id(), uniq));

        let write_result = async {
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temp)
                .await?;
            file.write_all(text.as_bytes()).await?;
            file.flush().await?;
            file.sync_all().await?;
            Ok::<(), std::io::Error>(())
        }
        .await;

        if let Err(e) = write_result {
            let _ = fs::remove_file(&temp).await;
            return Err(Error::Io(e));
        }

        if let Err(e) = fs::rename(&temp, &self.path).await {
            let _ = fs::remove_file(&temp).await;
            return Err(Error::Io(e));
        }
        Ok(())
    }

    /// Все записи реестра.
    pub fn entries(&self) -> &[VaultEntry] {
        &self.entries
    }

    /// Все записи реестра для изменения (внутри [`Registry::with_write_lock`]).
    pub fn entries_mut(&mut self) -> &mut [VaultEntry] {
        &mut self.entries
    }

    /// Добавить запись. Ошибка, если метка уже занята.
    pub fn add(&mut self, entry: VaultEntry) -> Result<()> {
        if self.entries.iter().any(|e| e.label == entry.label) {
            return Err(Error::DuplicateLabel(entry.label.as_str().to_owned()));
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Удалить запись по метке. Данные не трогаем.
    pub fn remove(&mut self, label: &Label) -> Result<()> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.label == *label)
            .ok_or_else(|| Error::VaultNotFound(label.as_str().to_owned()))?;
        self.entries.remove(pos);
        Ok(())
    }

    /// Переименовать метку. Санитизация новой метки — через [`Label`].
    pub fn rename(&mut self, old: &Label, new: Label) -> Result<()> {
        if self.entries.iter().any(|e| e.label == new) {
            return Err(Error::DuplicateLabel(new.as_str().to_owned()));
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.label == *old)
            .ok_or_else(|| Error::VaultNotFound(old.as_str().to_owned()))?;
        entry.label = new;
        Ok(())
    }
}

#[cfg(test)]
// expect/unwrap в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn entry(label: &str) -> VaultEntry {
        VaultEntry::new(
            Label::new(label).expect("valid label"),
            VaultKind::File(PathBuf::from(format!("/tmp/{label}.vault"))),
            VaultState::Closed,
        )
    }

    #[test]
    fn add_rejects_duplicate() {
        let mut r = Registry {
            path: PathBuf::from("/tmp/x.toml"),
            entries: Vec::new(),
        };
        r.add(entry("work")).expect("first add");
        assert!(r.add(entry("work")).is_err());
    }

    #[test]
    fn rename_rejects_duplicate() {
        let mut r = Registry {
            path: PathBuf::from("/tmp/x.toml"),
            entries: Vec::new(),
        };
        r.add(entry("a")).expect("add a");
        r.add(entry("b")).expect("add b");
        assert!(
            r.rename(&Label::new("a").unwrap(), Label::new("b").unwrap())
                .is_err()
        );
    }

    #[test]
    fn state_transitions_allowed() {
        let mut e = entry("x");
        e.set_state(VaultState::Open {
            mount_point: PathBuf::from("/run/m"),
            until: None,
        })
        .expect("closed -> open");
        e.set_state(VaultState::Closed).expect("open -> closed");
        e.set_state(VaultState::Disconnected)
            .expect("closed -> disconnected");
        // Переоткрытие после извлечения — штатный путь (спека п.11).
        e.set_state(VaultState::Open {
            mount_point: PathBuf::from("/run/m"),
            until: None,
        })
        .expect("disconnected -> open");
        e.set_state(VaultState::Closed)
            .expect("open -> closed after reconnect");
    }

    #[test]
    fn state_transition_rejected() {
        let mut e = entry("x");
        assert!(e.set_state(VaultState::Disconnected).is_ok());
        // Disconnected -> Disconnected запрещён.
        assert!(e.set_state(VaultState::Disconnected).is_err());
    }

    /// Старый `vaults.toml` (до автозакрытия) читается без миграции: срок —
    /// 15 минут по умолчанию, дедлайна у открытого тома нет.
    #[tokio::test]
    async fn load_registry_without_auto_close_fields_uses_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vaults.toml");
        tokio::fs::write(
            &path,
            "[[vaults]]\nlabel = \"work\"\nkind = \"file\"\npath = \"/tmp/work.vault\"\n\
             [vaults.state]\nopen = { mount_point = \"/run/m\" }\n",
        )
        .await
        .expect("write old-format registry");
        let reg = Registry::load_from(&path)
            .await
            .expect("old file must parse");
        let e = &reg.entries()[0];
        assert_eq!(e.auto_close(), Some(DEFAULT_AUTO_CLOSE));
        assert_eq!(
            e.state(),
            &VaultState::Open {
                mount_point: PathBuf::from("/run/m"),
                until: None,
            }
        );
    }

    /// Срок хранится в секундах (живой IT открывает том на 5 с — минуты
    /// его не выразят); «не закрывать» — явное слово, а не сентинел
    /// (находка 3 ревью спеки): `None` в модели ↔ `"never"` в файле.
    #[tokio::test]
    async fn auto_close_roundtrips_seconds_and_never() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vaults.toml");
        Registry::with_write_lock_at(&path, |r| {
            r.add(entry("a").with_auto_close(Some(Duration::from_secs(30 * 60))))?;
            r.add(entry("b").with_auto_close(None))
        })
        .await
        .expect("write");
        let text = tokio::fs::read_to_string(&path).await.expect("read");
        assert!(
            text.contains("auto_close_sec = 1800"),
            "seconds must be a plain scalar, got:\n{text}"
        );
        assert!(
            text.contains("auto_close_sec = \"never\""),
            "never must be spelled out, got:\n{text}"
        );
        let reg = Registry::load_from(&path).await.expect("reload");
        assert_eq!(
            reg.entries()[0].auto_close(),
            Some(Duration::from_secs(30 * 60))
        );
        assert_eq!(reg.entries()[1].auto_close(), None);
    }

    /// Дедлайн — секунды Unix, плоский скаляр, не вложенная таблица
    /// (находка 5 ревью спеки: `SystemTime` под derive даёт таблицу).
    #[tokio::test]
    async fn until_roundtrips_as_unix_seconds_scalar() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vaults.toml");
        Registry::with_write_lock_at(&path, |r| {
            let mut e = entry("x");
            e.set_state(VaultState::Open {
                mount_point: PathBuf::from("/run/m"),
                until: Some(1_700_000_000),
            })?;
            r.add(e)
        })
        .await
        .expect("write");
        let text = tokio::fs::read_to_string(&path).await.expect("read");
        assert!(
            text.contains("until = 1700000000"),
            "until must be a scalar, got:\n{text}"
        );
        let reg = Registry::load_from(&path).await.expect("reload");
        assert_eq!(
            reg.entries()[0].state(),
            &VaultState::Open {
                mount_point: PathBuf::from("/run/m"),
                until: Some(1_700_000_000),
            }
        );
    }

    /// Отложенное закрытие (спека С-8): счётчик попыток и момент первой
    /// неудачи хранятся плоскими скалярами и отсутствуют, пока не нужны, —
    /// старые и «здоровые» файлы их не видят.
    #[tokio::test]
    async fn close_deferral_roundtrips_and_is_absent_by_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vaults.toml");
        Registry::with_write_lock_at(&path, |r| {
            let mut a = entry("a");
            a.note_close_deferred(1_700_000_000);
            a.note_close_deferred(1_700_000_060);
            r.add(a)?;
            r.add(entry("b"))
        })
        .await
        .expect("write");
        let text = tokio::fs::read_to_string(&path).await.expect("read");
        assert_eq!(
            text.matches("close_attempts = 2").count(),
            1,
            "attempts must be a scalar and appear once, got:\n{text}"
        );
        assert_eq!(
            text.matches("close_deferred_since = 1700000000").count(),
            1,
            "first failure moment must stick, got:\n{text}"
        );
        assert_eq!(
            (
                text.matches("close_attempts").count(),
                text.matches("close_deferred_since").count()
            ),
            (1, 1),
            "a healthy entry must not carry deferral keys, got:\n{text}"
        );
        let reg = Registry::load_from(&path).await.expect("reload");
        let a = &reg.entries()[0];
        assert_eq!(a.close_attempts(), 2);
        assert_eq!(a.close_deferred_since(), Some(1_700_000_000));
        let b = &reg.entries()[1];
        assert_eq!(b.close_attempts(), 0);
        assert_eq!(b.close_deferred_since(), None);

        let mut a = a.clone();
        a.reset_close_deferral();
        assert_eq!((a.close_attempts(), a.close_deferred_since()), (0, None));
    }

    /// Дедлайн переставляется только у открытого тома (перезавод часов при
    /// отложенном закрытии — С-8); закрытому дедлайн не положен.
    #[test]
    fn set_until_requires_open_state() {
        let mut e = entry("x");
        assert!(
            e.set_until(Some(1)).is_err(),
            "closed vault has no deadline"
        );
        e.set_state(VaultState::Open {
            mount_point: PathBuf::from("/run/m"),
            until: Some(1),
        })
        .expect("open");
        e.set_until(Some(2)).expect("open vault: deadline moves");
        assert_eq!(
            e.state(),
            &VaultState::Open {
                mount_point: PathBuf::from("/run/m"),
                until: Some(2),
            }
        );
    }

    /// Серия попыток начинается заново, а момент первой неудачи остаётся —
    /// карточке нужно «не закрывается с …», а не «с последней минуты».
    #[test]
    fn restarting_attempts_keeps_first_failure_moment() {
        let mut e = entry("x");
        e.note_close_deferred(100);
        e.note_close_deferred(160);
        e.restart_close_attempts();
        assert_eq!(
            (e.close_attempts(), e.close_deferred_since()),
            (0, Some(100))
        );
    }

    #[tokio::test]
    async fn load_empty_file_returns_empty_registry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vaults.toml");
        tokio::fs::write(&path, "").await.expect("write empty");
        let reg = Registry::load_from(&path).await.expect("load empty");
        assert!(reg.entries().is_empty());
    }

    #[tokio::test]
    async fn load_corrupted_registry_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vaults.toml");
        tokio::fs::write(&path, "not-valid-toml-at-all")
            .await
            .expect("write garbage");
        let err = Registry::load_from(&path)
            .await
            .expect_err("parse must fail");
        assert!(
            matches!(err, Error::Registry(_)),
            "expected Registry error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn save_atomic_creates_temp_with_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vaults.toml");
        Registry::with_write_lock_at(&path, |r| {
            r.add(VaultEntry::new(
                Label::new("x").expect("label"),
                VaultKind::File(PathBuf::from("/tmp/x.vault")),
                VaultState::Closed,
            ))
        })
        .await
        .expect("write registry");

        let mode = tokio::fs::metadata(&path)
            .await
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "registry file mode is {mode:o}, expected 600");

        // Временный файл не должен остаться рядом.
        let mut leftovers = tokio::fs::read_dir(dir.path()).await.expect("read dir");
        let mut count = 0;
        while let Ok(Some(e)) = leftovers.next_entry().await {
            let name = e.file_name().to_string_lossy().to_string();
            assert!(!name.ends_with(".tmp"), "temp file left behind: {name}");
            count += 1;
        }
        assert_eq!(count, 1, "only vaults.toml should remain");
    }
}
