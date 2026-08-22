//! Реестр хранилищ `~/.config/panzir/vaults.toml`.
//!
//! Все мутации — через [`Registry::with_write_lock`], который держит
//! exclusive advisory flock на весь интервал load→modify→save.
//! Это предотвращает race, при котором два процесса panzir добавляют
//! записи с одинаковой меткой.

use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::task;

use crate::vault::{Label, VaultKind, VaultState};
use crate::{Error, Result};

/// Запись в реестре. Поля приватные — состояние меняется только методами.
#[derive(Debug, Clone)]
pub struct VaultEntry {
    label: Label,
    kind: VaultKind,
    state: VaultState,
}

impl VaultEntry {
    /// Создать новую запись.
    pub fn new(label: Label, kind: VaultKind, state: VaultState) -> Self {
        Self { label, kind, state }
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
    Open { mount_point: PathBuf },
    Disconnected,
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
            Ok(text) => Self::parse(path, &text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path: path.to_owned(),
                entries: Vec::new(),
            }),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn parse(path: &Path, text: &str) -> Result<Self> {
        let stored: StoredRegistry = toml::from_str(text).map_err(|e| {
            Error::UnexpectedUdisksState(format!("cannot parse registry {path:?}: {e}"))
        })?;
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
                        StoredState::Open { mount_point } => VaultState::Open { mount_point },
                        StoredState::Disconnected => VaultState::Disconnected,
                    },
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
        let parent = path.parent().ok_or_else(|| {
            Error::UnexpectedUdisksState("registry path has no parent".to_owned())
        })?;
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

        let mut registry = Self::parse(path, &text).unwrap_or_else(|_| Self {
            path: path.to_owned(),
            entries: Vec::new(),
        });

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
                        VaultState::Open { mount_point } => StoredState::Open {
                            mount_point: mount_point.clone(),
                        },
                        VaultState::Disconnected => StoredState::Disconnected,
                    },
                })
                .collect(),
        };
        let text = toml::to_string(&stored)
            .map_err(|e| Error::UnexpectedUdisksState(format!("cannot serialize registry: {e}")))?;

        let temp = self.path.with_extension("tmp");
        fs::write(&temp, text).await.map_err(Error::Io)?;
        fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(Error::Io)?;
        fs::rename(&temp, &self.path).await.map_err(Error::Io)?;
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
        })
        .expect("closed -> open");
        e.set_state(VaultState::Closed).expect("open -> closed");
        e.set_state(VaultState::Disconnected)
            .expect("closed -> disconnected");
        e.set_state(VaultState::Closed)
            .expect("disconnected -> closed");
    }

    #[test]
    fn state_transition_rejected() {
        let mut e = entry("x");
        assert!(e.set_state(VaultState::Disconnected).is_ok());
        // Disconnected -> Open запрещён.
        assert!(
            e.set_state(VaultState::Open {
                mount_point: PathBuf::from("/run/m")
            })
            .is_err()
        );
    }
}
