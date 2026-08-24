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

    /// udisks2 не вернул ожидаемые данные (объект пропал, поле не того вида
    /// и т.п.). Случай «том заперт» сюда НЕ входит — у него собственный
    /// вариант [`Error::VolumeLocked`], чтобы вызывающий отличал «заперто»
    /// от «шина отвалилась» матчем по типу, а не по тексту сообщения.
    #[error("unexpected udisks2 state: {0}")]
    UnexpectedUdisksState(String),

    /// Ошибка реестра (парсинг, сохранение, повреждение).
    #[error("registry: {0}")]
    Registry(String),

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

    /// Файла контейнера нет на диске: запись в реестре есть, а хранилище
    /// переименовали или удалили мимо приложения.
    #[error("container file is missing: {path}")]
    ContainerMissing {
        /// Путь, по которому контейнер ожидался.
        path: String,
    },

    /// Контейнер уже подключён loop-устройством ДРУГОГО пользователя.
    /// Второй loop на тот же файл поднимать нельзя: это две dm-crypt поверх
    /// одного LUKS-тома, то есть порча данных.
    #[error("container is already attached by uid {uid}: {path}")]
    VaultAlreadyAttached {
        /// Путь контейнера.
        path: String,
        /// Владелец существующего loop (`SetupByUID`).
        uid: u32,
    },

    /// Том заперт: udisks2 отдаёт сентинел `CleartextDevice == "/"`.
    /// Отдельный вариант, а не текст в [`Error::UnexpectedUdisksState`], —
    /// иначе «заперто» неотличимо от сбоя шины (страж на механизм, не на
    /// значение).
    #[error("volume is locked: {object}")]
    VolumeLocked {
        /// Объект блочного устройства с интерфейсом Encrypted.
        object: String,
    },

    /// На одном файле контейнера найдено больше одного loop-устройства.
    /// Это уже случившаяся порча (две dm-crypt поверх одного тома), а не
    /// предупреждение: молчать и брать первый нельзя.
    #[error("container has {count} loop devices attached (data corruption risk): {path}")]
    MultipleLoopsAttached {
        /// Путь контейнера.
        path: String,
        /// Сколько loop-устройств указывают на него.
        count: usize,
    },
}
