//! Единый тип ошибок panzir-core.

/// Все ошибки core. Секреты в сообщениях не попадают никогда.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Ошибка системного D-Bus / udisks2.
    #[error("udisks2: {0}")]
    Udisks(#[from] zbus::Error),

    /// Ошибка ввода-вывода (файл контейнера, реестр, вызов утилит).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Зависимость не найдена или не работает; подсказка — что установить.
    #[error("dependency missing: {name} — {hint}")]
    MissingDependency {
        /// Имя зависимости (udisks2, cryptsetup, pkexec, stat/chattr/fallocate, polkit agent).
        name: &'static str,
        /// Человеческая подсказка, как починить.
        hint: String,
    },

    /// Невалидная метка хранилища.
    #[error("invalid vault label: {0}")]
    InvalidLabel(String),

    /// Невалидный путь контейнера (нет родителя, пустой HOME и т.п.).
    /// До вызова udisks2 дело не дошло — это входная валидация.
    #[error("invalid container path: {0}")]
    InvalidContainerPath(String),

    /// Недопустимый переход состояния хранилища.
    #[error("invalid vault state transition: {from} -> {to}")]
    InvalidState {
        /// Текущее состояние.
        from: &'static str,
        /// Запрошенное.
        to: &'static str,
    },

    /// Утилита завершилась с ошибкой.
    #[error("command failed: {cmd} (status {status})")]
    Command {
        /// Командная строка без секретов.
        cmd: String,
        /// Код завершения.
        status: String,
    },

    /// udisks2 не вернул ожидаемые данные (например, том заперт, когда ждали
    /// отпертый: сентинел CleartextDevice == "/").
    #[error("unexpected udisks2 state: {0}")]
    UnexpectedUdisksState(String),

    /// HOME не установлен или пуст — путь симлинка построить нельзя.
    #[error("HOME is unset or empty")]
    NoHome,

    /// Другой процесс panzir уже запущен (advisory flock не получен).
    #[error("panzir is already running")]
    AlreadyRunning,

    /// Запись с такой меткой не найдена в реестре.
    #[error("vault not found: {0}")]
    VaultNotFound(String),

    /// Метка уже занята в реестре.
    #[error("duplicate vault label: {0}")]
    DuplicateLabel(String),
}
