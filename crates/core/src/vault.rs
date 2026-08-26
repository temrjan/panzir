//! Модель хранилища: вид, состояние, допустимые переходы.
//!
//! Невалидных состояний не существует: переходы возможны только через
//! методы [`Vault`], каждый проверяет исходное состояние.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Метка хранилища: валидированная пользовательская строка.
///
/// Белый список `[a-z0-9-]` (спека v1.1, п.4 скоупа): метка попадает в путь
/// симлинка `~/panzir-<метка>` и в метку тома — произвольный ввод
/// (`/`, `..`, пустая) отвергается при создании, не постфактум.
/// Длина ограничена 16 байтами — самый тесный предел из двух: метка тома
/// ext4 (`mke2fs -L`) обрезает до 16 байт молча, без ошибки.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Label(String);

impl Label {
    /// Максимальная длина метки в байтах (лимит метки ext4).
    pub const MAX_LEN: usize = 16;

    /// Валидирует и конструирует метку.
    ///
    /// # Errors
    /// [`Error::InvalidLabel`], если строка пуста, длиннее [`Label::MAX_LEN`]
    /// байт, содержит символы вне `[a-z0-9-]` или начинается/заканчивается
    /// дефисом.
    pub fn new(raw: &str) -> Result<Self> {
        let ok = !raw.is_empty()
            && raw.len() <= Self::MAX_LEN
            && raw
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !raw.starts_with('-')
            && !raw.ends_with('-');
        if ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(Error::InvalidLabel(raw.to_owned()))
        }
    }

    /// Метка как строка.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Вид хранилища (спека: файл-контейнер или физический носитель).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VaultKind {
    /// Файл-контейнер на диске.
    File(PathBuf),
    /// Физический носитель (USB), идентифицируется UUID тома LUKS —
    /// переживает смену буквы устройства и переименование.
    Device {
        /// UUID тома LUKS (blkid).
        uuid: String,
    },
}

/// Состояние хранилища.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultState {
    /// Закрыто: том заперт, содержимого ни у кого нет.
    Closed,
    /// Открыто: том смонтирован.
    Open {
        /// Фактическая точка монтирования (из объекта udisks2, не угаданная).
        mount_point: PathBuf,
    },
    /// Носитель извлечён при живом приложении (спека п.11): симлинк снят,
    /// запись помечена. Переоткрытие — через обычный `open`.
    Disconnected,
}

impl VaultState {
    /// Имя состояния для сообщений об ошибках.
    fn name(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open { .. } => "open",
            Self::Disconnected => "disconnected",
        }
    }
}

/// Хранилище: метка, вид, текущее состояние.
#[derive(Debug, Clone)]
pub struct Vault {
    label: Label,
    kind: VaultKind,
    state: VaultState,
}

impl Vault {
    /// Новое хранилище в состоянии `Closed`.
    pub fn new(label: Label, kind: VaultKind) -> Self {
        Self {
            label,
            kind,
            state: VaultState::Closed,
        }
    }

    /// Метка.
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// Вид.
    pub fn kind(&self) -> &VaultKind {
        &self.kind
    }

    /// Текущее состояние.
    pub fn state(&self) -> &VaultState {
        &self.state
    }

    /// Путь симлинка `~/panzir-<метка>`.
    ///
    /// # Errors
    /// [`Error::NoHome`], если HOME не установлен или пуст — иначе получился
    /// бы относительный путь `panzir-<метка>` от случайного CWD процесса.
    pub fn symlink_path(&self) -> Result<PathBuf> {
        Self::symlink_path_in(std::env::var_os("HOME"), &self.label)
    }

    /// Чистая часть построения пути (шов для тестов: env в тесте не
    /// поменять — `set_var` unsafe, а у нас `forbid(unsafe_code)`).
    /// Обёртка над [`crate::mountpoint::symlink_path`], чтобы формула жила
    /// в одном месте.
    fn symlink_path_in(home: Option<std::ffi::OsString>, label: &Label) -> Result<PathBuf> {
        let home = home.filter(|h| !h.is_empty()).ok_or(Error::NoHome)?;
        Ok(crate::mountpoint::symlink_path(&PathBuf::from(home), label))
    }

    /// `Closed | Disconnected -> Open`.
    ///
    /// # Errors
    /// [`Error::InvalidState`], если хранилище уже открыто.
    pub fn mark_open(&mut self, mount_point: PathBuf) -> Result<()> {
        match self.state {
            VaultState::Closed | VaultState::Disconnected => {
                self.state = VaultState::Open { mount_point };
                Ok(())
            }
            VaultState::Open { .. } => Err(Error::InvalidState {
                from: self.state.name(),
                to: "open",
            }),
        }
    }

    /// `Open -> Closed`.
    ///
    /// # Errors
    /// [`Error::InvalidState`], если хранилище не открыто.
    pub fn mark_closed(&mut self) -> Result<()> {
        match self.state {
            VaultState::Open { .. } => {
                self.state = VaultState::Closed;
                Ok(())
            }
            _ => Err(Error::InvalidState {
                from: self.state.name(),
                to: "closed",
            }),
        }
    }

    /// `Open | Closed -> Disconnected` (носитель недоступен в udisks2).
    ///
    /// # Errors
    /// [`Error::InvalidState`], если хранилище уже отключено.
    pub fn mark_disconnected(&mut self) -> Result<()> {
        match self.state {
            VaultState::Open { .. } | VaultState::Closed => {
                self.state = VaultState::Disconnected;
                Ok(())
            }
            VaultState::Disconnected => Err(Error::InvalidState {
                from: self.state.name(),
                to: "disconnected",
            }),
        }
    }
}

/// Путь нового файл-контейнера: `<home>/.local/share/panzir/<метка>.vault`.
///
/// Приложение выбирает путь само (спека среза 1) — пользователь вводит только
/// метку. Чистая функция от `home` и метки; `home` приходит параметром
/// (инвариант 9), env здесь НЕ читается — в отличие от [`Vault::symlink_path`],
/// где обёртка над env нужна, потому что путь строится без готового `home`.
/// Уровень упрощения тот же, что у [`crate::registry::Registry::default_path`]
/// (`$HOME/...`, без разбора `$XDG_*`).
#[must_use]
pub fn container_path(home: &Path, label: &Label) -> PathBuf {
    home.join(".local/share/panzir")
        .join(format!("{}.vault", label.as_str()))
}

#[cfg(test)]
// expect в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn vault() -> Vault {
        Vault::new(
            Label::new("work").expect("valid label"),
            VaultKind::File(PathBuf::from("/tmp/work.vault")),
        )
    }

    #[test]
    fn label_accepts_simple_lowercase() {
        assert!(Label::new("work").is_ok());
        assert!(Label::new("work-2026").is_ok());
        assert!(Label::new("a").is_ok());
    }

    #[test]
    fn label_rejects_dangerous_input() {
        for bad in [
            "",
            "Work",
            "my keys",
            "a/b",
            "..",
            "a..b",
            "-work",
            "work-",
            "ключи",
        ] {
            assert!(Label::new(bad).is_err(), "label {bad:?} must be rejected");
        }
    }

    #[test]
    fn label_max_len_boundary() {
        let max = "a".repeat(Label::MAX_LEN);
        let over = "a".repeat(Label::MAX_LEN + 1);
        assert!(Label::new(&max).is_ok(), "16 bytes must be accepted");
        assert!(Label::new(&over).is_err(), "17 bytes must be rejected");
    }

    #[test]
    fn symlink_path_branches() {
        let label = Label::new("work").expect("valid label");
        // Пустой и отсутствующий HOME — ошибка, а не относительный путь
        // от случайного CWD.
        assert!(Vault::symlink_path_in(None, &label).is_err());
        assert!(Vault::symlink_path_in(Some("".into()), &label).is_err());
        let p = Vault::symlink_path_in(Some("/home/u".into()), &label).expect("ok");
        assert_eq!(p, PathBuf::from("/home/u/panzir-work"));
    }

    #[test]
    fn container_path_is_under_xdg_data_home() {
        let label = Label::new("work").expect("valid label");
        assert_eq!(
            container_path(Path::new("/home/u"), &label),
            PathBuf::from("/home/u/.local/share/panzir/work.vault")
        );
    }

    #[test]
    fn open_close_roundtrip() {
        let mut v = vault();
        assert_eq!(v.state(), &VaultState::Closed);
        v.mark_open(PathBuf::from("/run/media/u/panzir-work"))
            .expect("closed -> open");
        assert!(matches!(v.state(), &VaultState::Open { .. }));
        v.mark_closed().expect("open -> closed");
        assert_eq!(v.state(), &VaultState::Closed);
    }

    #[test]
    fn double_open_is_rejected() {
        let mut v = vault();
        v.mark_open(PathBuf::from("/run/media/u/panzir-work"))
            .expect("first open");
        assert!(v.mark_open(PathBuf::from("/elsewhere")).is_err());
    }

    #[test]
    fn close_when_closed_is_rejected() {
        let mut v = vault();
        assert!(v.mark_closed().is_err());
    }

    #[test]
    fn disconnect_from_open_or_closed() {
        let mut v = vault();
        // Closed -> Disconnected разрешён (PR-2, Н-2).
        v.mark_disconnected().expect("closed -> disconnected");
        assert_eq!(v.state(), &VaultState::Disconnected);

        let mut v = vault();
        v.mark_open(PathBuf::from("/run/media/u/panzir-work"))
            .expect("open");
        v.mark_disconnected().expect("open -> disconnected");
        assert_eq!(v.state(), &VaultState::Disconnected);
        // Переоткрытие после извлечения — штатный путь (спека п.11).
        v.mark_open(PathBuf::from("/run/media/u/panzir-work"))
            .expect("disconnected -> open");
    }

    #[test]
    fn disconnect_from_disconnected_is_rejected() {
        let mut v = vault();
        v.mark_disconnected().expect("closed -> disconnected");
        assert!(v.mark_disconnected().is_err());
    }

    #[test]
    fn symlink_path_uses_label() {
        let v = vault();
        let path = v.symlink_path().expect("HOME is set in tests");
        assert_eq!(path.file_name().expect("has file name"), "panzir-work");
    }
}
