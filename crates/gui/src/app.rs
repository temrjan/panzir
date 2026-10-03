//! Состояние окна, мост к ядру и перевод отказов на человеческий язык.
//!
//! Владелец связи «окно ↔ ядро»: всё асинхронное живёт здесь, экраны его не
//! знают. Ядро асинхронное, а [`eframe::App::ui`] синхронна и вызывается
//! десятки раз в секунду, поэтому операции уходят в рантайм tokio, а результат
//! снимается неблокирующе.

use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use eframe::egui;
use panzir_core::create;
use panzir_core::deps::{self, DepsReport};
use panzir_core::keyslot;
use panzir_core::lifecycle::{self, CloseDecision, close_decision};
use panzir_core::passphrase::Passphrase;
use panzir_core::registry::{Registry, SshHost, VaultEntry};
use panzir_core::schedule::SystemdUser;
use panzir_core::ssh::{self, IncludeStatus, SshError};
use panzir_core::udisks::Udisks;
use panzir_core::vault::{DEFAULT_AUTO_CLOSE, Label, VaultKind, VaultState, container_path};
use panzir_core::{AuthRefusal, Error};
use secrecy::SecretString;
use secrecy::zeroize::Zeroize as _;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::theme;
use crate::view_create::{self, CreateAction, CreateDraft};
use crate::view_list::{self, ListAction, ListInput, RenameDraft, SshHostDraft, UnlockDraft};

/// Сколько ждём завершения операции в тестах, прежде чем признать зависание.
/// Не «пауза для стабилизации»: ожидание идёт по настоящему сигналу завершения
/// задачи, а дедлайн только превращает зависание в названный провал теста.
#[cfg(test)]
const TEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Доступна ли шина udisks2 — зависимость, без которой не работает ничего.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdisksStatus {
    /// Подключились; строка — версия демона.
    Available(String),
    /// Не подключились; строка — человеческая подсказка, что делать.
    Missing(String),
}

/// Одна строка плашки окружения.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvLine {
    /// Имя зависимости.
    pub name: String,
    /// Найдена и работает.
    pub ok: bool,
    /// Что сделать, если не работает.
    pub hint: String,
}

/// Итог резолюции одного хоста через `ssh -G` (проверка по результату, К-7).
/// Считается только для открытого хранилища.
#[derive(Clone, Debug)]
pub struct SshResolution {
    /// Алиас хоста.
    pub host: String,
    /// `identitiesonly yes` и наш `identityfile` подтверждены резолюцией.
    pub ok: bool,
    /// Текст отказа `ssh -G` (не запустился/ошибка/таймаут), если был.
    pub detail: Option<String>,
}

/// Статус SSH-связки раскрытой карточки — результат фоновой пробы: чтение
/// `~/.ssh/config` плюс, для открытого хранилища, резолюция `ssh -G`.
#[derive(Clone, Debug)]
pub struct SshCardStatus {
    /// Метка записи, к которой относится статус.
    pub label: Label,
    /// Где строка `Include` в config.
    pub include: IncludeStatus,
    /// Имя нашего хоста, уже занятое в чужом config (ворнинг по чтению).
    pub collision: Option<String>,
    /// Config существует, но не прочитался — отказ показывается, а не
    /// проглатывается как «строки нет» (инвариант 10).
    pub error: Option<String>,
    /// Резолюция по хостам; пусто для закрытого хранилища.
    pub resolutions: Vec<SshResolution>,
}

/// Подтверждение вставки/починки строки `Include`: человек видит точную
/// строку до того, как мы пишем в его config (М-1).
#[derive(Clone, Debug)]
pub struct SshConfirm {
    /// Метка записи.
    pub target: Label,
    /// `true` — починка `Shadowed` (поднять строку первой), `false` — вставка.
    pub repair: bool,
    /// Точная строка `Include` — показывается перед записью.
    pub line: String,
}

/// Начатое удаление записи (спека П-1/П-2): баннер на карточке с текстом
/// «что будет удалено» и, если файл на месте, полем парольной фразы.
/// Случайное нажатие «Удалить из списка» ничего не делает.
/// `Debug` сознательно не выводится — как у `UnlockDraft`: внутри секрет.
pub struct DeleteDraft {
    /// Метка записи.
    pub target: Label,
    /// `true` — файла контейнера нет на месте (сирота): шаг фразы
    /// пропускается, проверять не по чему (гриль 6).
    pub orphan: bool,
    /// Набранная фраза. Обычная `String`, как `UnlockDraft`: другого способа
    /// принять ввод у egui нет. Живёт до нажатия кнопки — [`App`] забирает
    /// содержимое `mem::take` и сразу кладёт в `SecretString`; на остальных
    /// путях выхода затирается (`forget_stale_passphrase`, отмена).
    pub passphrase: String,
}

/// Что окно просит у ядра. Все операции идут через одну дверь — [`App::spawn_op`].
#[derive(Debug)]
enum Op {
    /// Перечитать реестр.
    Reload,
    /// Удалить запись по двухшаговому сценарию (П-1/П-2): фраза → закрытие
    /// (если открыт) → SSH-след → запись. Контейнер на диске не трогается.
    Delete {
        /// Метка записи.
        label: Label,
        /// Путь к файлу-контейнеру; `None` — сирота (файла нет на месте):
        /// шаги фразы и закрытия пропускаются. Носитель сюда не доходит —
        /// отказан ещё в `handle` (`refuse_device`).
        container: Option<PathBuf>,
        /// Фраза с баннера; `None` у сироты. Пара с `container`: файл на
        /// месте без фразы — комбинация, которую окно не строит, и ядро-сторона
        /// обязана отказать, а не молча пропустить проверку.
        passphrase: Option<SecretString>,
    },
    /// Открыть хранилище набранной фразой.
    Open {
        /// Метка записи.
        label: Label,
        /// Путь к файлу-контейнеру.
        container: PathBuf,
        /// Секрет. Дальше окна в открытом виде не живёт: `SecretString`
        /// затирает себя при уничтожении.
        passphrase: SecretString,
        /// Срок автозакрытия из записи; `None` — не закрывать. Читается при
        /// клике, чтобы фоновая задача не открывала реестр второй раз.
        auto_close: Option<Duration>,
    },
    /// Закрыть хранилище: отпереть нельзя без пароля, а запереть — можно.
    Close {
        /// Метка записи.
        label: Label,
        /// Путь к файлу-контейнеру: в реестре объекта loop-устройства нет,
        /// его приходится искать пробой по контейнеру.
        container: PathBuf,
    },
    /// Сменить метку записи.
    Rename {
        /// Текущая метка.
        old: Label,
        /// Новая метка.
        new: Label,
    },
    /// Создать новое файловое хранилище: контейнер (создаётся открытым и
    /// смонтированным ядром), симлинк, запись в реестр.
    Create {
        /// Метка нового хранилища.
        label: Label,
        /// Путь файла-контейнера — выбран приложением (`vault::container_path`).
        container: PathBuf,
        /// Размер контейнера в байтах.
        size_bytes: u64,
        /// Пароль. Дальше окна в открытом виде не живёт: `SecretString`
        /// затирает себя при уничтожении.
        passphrase: SecretString,
    },
    /// Добавить SSH-хоста к записи и перезаписать сниппет (спека Ш-7).
    AddSshHost {
        /// Метка записи.
        label: Label,
        /// Проверенный конструктором хост.
        host: SshHost,
    },
    /// Вставить строку `Include` первой или поднять её (починка `Shadowed`).
    /// Только по подтверждению: человек видел точную строку.
    SshInclude {
        /// Метка записи.
        label: Label,
        /// `true` — починка (М-1), `false` — вставка.
        repair: bool,
    },
}

/// Чем кончилась операция. Список приходит вместе с исходом: правка реестра и
/// чтение результата происходят под одним локом, вторым вызовом не разъезжаются.
#[derive(Debug)]
enum OpOutcome {
    /// Свежий список записей.
    Loaded(Vec<VaultEntry>),
    /// Свежий список плюс ворнинг человеку: операция состоялась, но её
    /// производная часть отказала (например, сниппет при открытии) —
    /// молчать нельзя (инвариант 10), а отказом это не является.
    LoadedWith(Vec<VaultEntry>, String),
    /// Операция отказала; строка уже переведена на человеческий язык.
    Failed(String),
}

/// Разбирает значение `PANZIR_SMOKE_FRAMES`.
///
/// Отделено от чтения окружения намеренно: `std::env::set_var` в edition 2024 —
/// unsafe-функция, а `unsafe_code = "forbid"` из workspace-линтов её не пустит,
/// то есть подсунуть значение тесту иначе нечем. Окружение читает только
/// `main.rs`.
///
/// Отсутствует, пусто или не разбирается → обычный режим. Меньше одного кадра —
/// тоже обычный режим: «нарисовать ноль кадров и закрыться» проверкой не является.
#[must_use]
pub fn smoke_frames_from(raw: Option<&str>) -> Option<u32> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    match raw.parse::<u32>() {
        Ok(n) if n >= 1 => Some(n),
        Ok(_) => {
            tracing::warn!(
                value = raw,
                "PANZIR_SMOKE_FRAMES меньше одного кадра, smoke-режим не включаю"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                value = raw,
                "PANZIR_SMOKE_FRAMES не разбирается как число, работаю обычно"
            );
            None
        }
    }
}

/// Что попросил вызывающий через командную строку.
///
/// Это внутренний контракт «таймер ↔ бинарь», а не пользовательский CLI:
/// таймер автозакрытия запускает этот же бинарь с `--close <метка>`
/// (`SystemdUser`, schedule.rs). Пользовательских флагов нет и не должно
/// появиться без отдельного решения — поэтому никакого парсера аргументов:
/// две формы вызова, три исхода.
#[derive(Debug, PartialEq, Eq)]
pub enum CloseRequest {
    /// Аргументов нет — обычное окно.
    Window,
    /// Ровно `--close <валидная метка>` — headless-закрытие хранилища.
    Close(Label),
    /// Всё остальное — ошибка вызова; причина различима в stderr.
    Usage(UsageReason),
}

/// Почему вызов не разобран. Тексты различаются при одном exit-коде 2:
/// ночной отказ разбирают по journalctl, гадание там недопустимо.
/// Match'и на нём — без ветки `_`.
#[derive(Debug, PartialEq, Eq)]
pub enum UsageReason {
    /// Аргумент не из контракта (опечатка, `--version`, лишний аргумент).
    UnknownArgument(std::ffi::OsString),
    /// `--close` без метки.
    MissingLabel,
    /// Метка не прошла `Label::new`.
    InvalidLabel(String),
}

/// Разбирает argv — полный, включая `argv[0]` с именем бинаря: его ставит ОС,
/// и образец подсчёта в проекте (`close_worker.rs`) считает с ним.
/// `skip(1)`, а не срез `args[1..]`: не паникует даже на теоретически пустом
/// argv. Отделён от чтения argv в `main` по той же причине, что
/// [`smoke_frames_from`]: подменить argv тесту нечем.
#[must_use]
pub fn close_label_from(args: &[std::ffi::OsString]) -> CloseRequest {
    let mut rest = args.iter().skip(1);
    let Some(first) = rest.next() else {
        return CloseRequest::Window;
    };
    if first != "--close" {
        return CloseRequest::Usage(UsageReason::UnknownArgument(first.clone()));
    }
    let Some(label) = rest.next() else {
        return CloseRequest::Usage(UsageReason::MissingLabel);
    };
    if let Some(extra) = rest.next() {
        return CloseRequest::Usage(UsageReason::UnknownArgument(extra.clone()));
    }
    match label.to_str().and_then(|text| Label::new(text).ok()) {
        Some(label) => CloseRequest::Close(label),
        None => CloseRequest::Usage(UsageReason::InvalidLabel(
            label.to_string_lossy().into_owned(),
        )),
    }
}

/// Строка usage — одна на все отказы разбора argv.
#[must_use]
pub fn usage_line() -> &'static str {
    "usage: panzir-gui [--close <label>]"
}

/// Причина отказа разбора — человеку в stderr и journal. Без ветки `_`:
/// новый вариант обязан сломать сборку здесь.
#[must_use]
pub fn usage_reason_text(reason: &UsageReason) -> String {
    match reason {
        UsageReason::UnknownArgument(arg) => {
            format!("unknown argument: {}", arg.to_string_lossy())
        }
        UsageReason::MissingLabel => "--close requires a label".to_owned(),
        UsageReason::InvalidLabel(text) => {
            format!("invalid label: {text} — labels are [a-z0-9-], up to 16 bytes")
        }
    }
}

/// Строка исхода закрытия для stdout/journal. Три исхода обязаны читаться
/// по-разному: «не закрыл» не должен выглядеть как «закрыл» рядом с успешным
/// юнитом. Без ветки `_`: новый вариант `CloseOutcome` обязан сломать сборку
/// здесь (образец — `close_decision` в ядре).
#[must_use]
pub fn outcome_line(label: &Label, outcome: &lifecycle::CloseOutcome) -> String {
    match outcome {
        lifecycle::CloseOutcome::Closed => format!("{label}: closed"),
        lifecycle::CloseOutcome::AlreadyClosed => format!("{label}: already closed"),
        lifecycle::CloseOutcome::Deferred { attempt } => {
            format!("{label}: busy — close deferred (attempt {attempt}), waiting for manual close")
        }
    }
}

/// Переводит отказ ядра на человеческий язык.
///
/// Match намеренно без ветки `_`: новый вариант в ядре обязан сломать сборку
/// здесь, а не молча приехать к человеку сырым `Display` из `thiserror`.
#[must_use]
pub fn error_text(err: &Error) -> String {
    match err {
        Error::AlreadyRunning => "Список хранилищ занят другой операцией. Повторите позже".to_owned(),
        Error::Schedule { cmd, status } => format!(
            "часы автозакрытия не завелись — само хранилище не закроется: «{cmd}» ({status})"
        ),
        Error::MissingDependency { name, hint } => {
            format!("не хватает «{name}»: {hint}")
        }
        Error::NoHome => "не удалось определить домашнюю папку — переменная HOME пуста".to_owned(),
        Error::VaultNotFound(label) => {
            format!("хранилища «{label}» в списке больше нет — список устарел, обновите окно")
        }
        Error::DuplicateLabel(label) => {
            format!("имя «{label}» уже занято — выберите другое")
        }
        Error::InvalidLabel(what) => {
            format!("такое имя не подходит: {what}. Разрешены строчные буквы, цифры и дефис")
        }
        Error::InvalidContainerPath(what) => {
            format!("путь к файлу хранилища не подходит: {what}")
        }
        Error::ContainerMissing { path } => {
            format!(
                "файла хранилища нет на месте: {path}. Запись осталась, а файл переместили или удалили мимо приложения"
            )
        }
        Error::Registry(what) => {
            format!("список хранилищ не удалось прочитать или сохранить: {what}")
        }
        Error::Io(e) => format!("ошибка ввода-вывода: {e}"),
        // Служба ответила ошибкой ИЛИ недоступна — вариант этого не различает,
        // поэтому и текст не утверждает ни того, ни другого (круг H).
        Error::Udisks(e) => {
            format!("служба дисков udisks2 вернула ошибку: {e}")
        }
        // Отказ polkit — не сбой службы: она ответила «нельзя». Три оттенка —
        // три текста; ни один не называет причину, которой имя не несёт.
        Error::NotAuthorized { reason } => match reason {
            AuthRefusal::Denied => {
                "политика системы запрещает эту операцию вашей учётной записи — подтверждение прав здесь не поможет"
                    .to_owned()
            }
            AuthRefusal::NeedsConfirmation => {
                "операция требует подтверждения прав, а спросить его в этом вызове нельзя".to_owned()
            }
            AuthRefusal::Dismissed => "подтверждение прав отменено".to_owned(),
        },
        Error::UnexpectedUdisksState(what) => {
            format!("служба дисков ответила неожиданно: {what}")
        }
        Error::VolumeLocked { object } => {
            format!("хранилище заперто: {object}")
        }
        Error::Command { cmd, status } => {
            format!("команда «{cmd}» завершилась с ошибкой (код {status})")
        }
        Error::InvalidState { from, to } => {
            format!("так переключить хранилище нельзя: {from} → {to}")
        }
        Error::VaultAlreadyAttached { path, uid } => {
            format!(
                "файл {path} уже подключён другим пользователем (uid {uid}). Второе подключение испортило бы данные"
            )
        }
        Error::MultipleLoopsAttached { path, count } => {
            format!(
                "на файле {path} найдено {count} подключений вместо одного — это уже повреждение, закройте хранилище сторонними средствами"
            )
        }
        Error::Ssh(SshError::InvalidField { field, value }) => {
            let rule = match *field {
                "host" => {
                    "разрешены строчные буквы, цифры, точка, дефис и подчёркивание"
                }
                "key_file" => "нужен относительный путь внутри хранилища: строчные буквы, цифры, точка, дефис и подчёркивание; каталоги через /, без пустых частей, . и ..",
                _ => "без пробелов и символа «#»",
            };
            format!("SSH-хост: поле «{field}» не подходит: «{value}» — {rule}")
        }
        Error::Ssh(SshError::Io(e)) => format!("SSH-связка: ошибка ввода-вывода: {e}"),
        Error::Ssh(SshError::Query { host, status }) => {
            format!("ssh -G {host} завершился с ошибкой ({status}) — связку показать не удалось")
        }
        Error::Ssh(SshError::QueryTimeout { host }) => {
            format!("ssh -G {host} не ответил за отведённое время — связку показать не удалось")
        }
    }
}

/// Сообщение об отложенном автозакрытии: кто держит сейф открытым.
///
/// E-minimal: при «занято» автозакрытие ждёт человека, поэтому окно
/// показывает держателей и просит закрыть программу вручную.
#[must_use]
pub fn busy_message(holders: &[String]) -> String {
    if holders.is_empty() {
        "Файлы хранилища заняты. Закройте использующие их программы и нажмите „Закрыть“".to_owned()
    } else {
        format!(
            "Хранилище использует „{}“. Закройте его файлы или выйдите из его папки в этой программе, затем нажмите „Закрыть“",
            holders.join(", ")
        )
    }
}

/// Короткое имя состояния записи для списка.
#[must_use]
pub fn state_text(state: &VaultState) -> &'static str {
    match state {
        VaultState::Closed => "Закрыто",
        VaultState::Open { .. } => "Открыто",
        VaultState::Disconnected => "Отключено",
    }
}

/// Короткое имя типа хранилища для списка.
#[must_use]
pub fn kind_text(kind: &VaultKind) -> &'static str {
    match kind {
        VaultKind::File(_) => "Файл",
        VaultKind::Device { .. } => "Носитель",
    }
}

/// Какой экран показан. Отделён от черновика создания намеренно: черновик
/// живёт в `Option`, а `screen` говорит, показан ли он, — тогда «ушли с формы,
/// а черновик завис» становится ловимым состоянием (условие устаревания для
/// `forget_stale_passphrase`; подробности независимы от Unlock).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Screen {
    /// Список хранилищ.
    List,
    /// Форма создания нового хранилища.
    Create,
}

/// Область текущего пользовательского результата, без журнала истории.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NoticeScope {
    Card(Label),
    Create(Label),
    Global,
}
impl NoticeScope {
    pub(crate) fn key(&self) -> String {
        match self {
            Self::Card(l) => format!("card:{l}"),
            Self::Create(l) => format!("create:{l}"),
            Self::Global => "global".into(),
        }
    }
}

pub(crate) struct Notice {
    pub(crate) scope: NoticeScope,
    pub(crate) title: String,
    pub(crate) text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ListLoad {
    Loading,
    Loaded,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationKind {
    Reload,
    Open,
    Close,
    Delete,
    Rename,
    Create,
    AddSsh,
    Include,
}

/// Метаданные выполняемой операции не содержат секретов.
#[derive(Clone)]
pub(crate) struct Operation {
    kind: OperationKind,
    pub(crate) target: Option<Label>,
    new_label: Option<Label>,
    request: u64,
}
impl Operation {
    fn from_op(op: &Op, request: u64) -> Self {
        let (kind, target, new_label) = match op {
            Op::Reload => (OperationKind::Reload, None, None),
            Op::Open { label, .. } => (OperationKind::Open, Some(label.clone()), None),
            Op::Close { label, .. } => (OperationKind::Close, Some(label.clone()), None),
            Op::Delete { label, .. } => (OperationKind::Delete, Some(label.clone()), None),
            Op::Rename { old, new } => {
                (OperationKind::Rename, Some(old.clone()), Some(new.clone()))
            }
            Op::Create { label, .. } => (OperationKind::Create, Some(label.clone()), None),
            Op::AddSshHost { label, .. } => (OperationKind::AddSsh, Some(label.clone()), None),
            Op::SshInclude { label, .. } => (OperationKind::Include, Some(label.clone()), None),
        };
        Self {
            kind,
            target,
            new_label,
            request,
        }
    }
    fn scope(&self) -> NoticeScope {
        match (&self.kind, &self.target) {
            (OperationKind::Create, Some(l)) => NoticeScope::Create(l.clone()),
            (_, Some(l)) => NoticeScope::Card(l.clone()),
            _ => NoticeScope::Global,
        }
    }
    pub(crate) fn status(&self) -> String {
        let text = match self.kind {
            OperationKind::Reload => "Обновляем список…",
            OperationKind::Open => "Открываем хранилище…",
            OperationKind::Close => "Закрываем хранилище…",
            OperationKind::Delete => "Удаляем запись…",
            OperationKind::Rename => "Сохраняем название…",
            OperationKind::Create => "Создаём хранилище…",
            OperationKind::AddSsh => "Сохраняем SSH-хост…",
            OperationKind::Include => "Настраиваем SSH-подключения…",
        };
        self.target
            .as_ref()
            .map_or(text.to_owned(), |l| format!("{text} {l}"))
    }
    fn error_title(&self) -> String {
        let label = self
            .target
            .as_ref()
            .map_or(String::new(), ToString::to_string);
        match self.kind {
            OperationKind::Reload => "Не удалось прочитать список хранилищ".into(),
            OperationKind::Open => format!("Не удалось открыть „{label}“"),
            OperationKind::Close => format!("Не удалось закрыть „{label}“"),
            OperationKind::Create => format!("Не удалось создать „{label}“"),
            OperationKind::Delete => "Не удалось удалить запись".into(),
            OperationKind::Rename => "Не удалось сохранить название".into(),
            OperationKind::AddSsh => "Не удалось сохранить SSH-хост".into(),
            OperationKind::Include => "Не удалось настроить SSH-подключения".into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SshProbeKey {
    label: Label,
    kind: VaultKind,
    hosts: Vec<SshHost>,
    resolve: bool,
}

/// Кеш одной фоновой /proc-пробы выбранных подробностей.
pub(crate) struct HolderStatus {
    pub(crate) label: Label,
    pub(crate) mount_point: PathBuf,
    pub(crate) names: Vec<String>,
}

/// Состояние главного окна.
pub struct App {
    #[cfg(test)]
    test_operation: Option<fn(Op) -> OpOutcome>,
    #[cfg(test)]
    isolate_vault_io: bool,
    rt: Runtime,
    ctx: egui::Context,
    pending_meta: Option<Operation>,
    sequence: u64,
    load: ListLoad,
    read_error: Option<String>,
    notices: Vec<Notice>,
    interaction: Option<(Label, VaultKind)>,
    origin_role: Option<&'static str>,
    /// Following cards in the order at entry, for focus after target invalidation.
    interaction_following: Vec<Label>,
    ssh_probe_key: Option<SshProbeKey>,
    ssh_status_key: Option<SshProbeKey>,
    holder_probe: Option<JoinHandle<HolderStatus>>,
    holder_status: Option<HolderStatus>,
    holder_next: f64,
    holder_requested: Option<(Label, PathBuf)>,
    create_result_target: Option<Label>,
    registry_path: PathBuf,
    home: PathBuf,
    /// Путь `~/.ssh/config` — параметром (инвариант 9), читает/пишет только
    /// по запросу человека (вставка `Include` — по подтверждению).
    ssh_config: PathBuf,
    /// Часы автозакрытия: окно только передаёт их в ядро.
    scheduler: SystemdUser,
    op_timeout: Duration,
    smoke_frames: Option<u32>,
    frames_drawn: u32,
    entries: Vec<VaultEntry>,
    env: Vec<EnvLine>,
    udisks: Option<UdisksStatus>,
    local_deps: DepsReport,
    pending: Option<JoinHandle<OpOutcome>>,
    /// Периодическая перечитка реестра, пока есть открытые тома (E-minimal).
    /// Не блокирует кнопки: `pending` остаётся свободен для операций человека.
    reload_tick: Option<JoinHandle<OpOutcome>>,
    bus_probe: Option<JoinHandle<UdisksStatus>>,
    /// Проба SSH-связки раскрытой карточки (чтение config).
    ssh_probe: Option<JoinHandle<SshCardStatus>>,
    /// Последний известный статус связки; инвалидируется при смене списка.
    ssh_status: Option<SshCardStatus>,
    /// Локальная валидация отделена от сохранённых исходов операций.
    message: Option<String>,
    validation_scope: NoticeScope,
    rename: Option<RenameDraft>,
    expanded: Option<Label>,
    unlock: Option<UnlockDraft>,
    /// Черновик добавления SSH-хоста (не секрет — затирать не нужно).
    ssh_draft: Option<SshHostDraft>,
    /// Ожидающее подтверждение вставление/починка строки `Include`.
    ssh_confirm: Option<SshConfirm>,
    /// Начатое удаление записи — баннер на карточке (секрет внутри).
    delete: Option<DeleteDraft>,
    screen: Screen,
    /// Черновик формы создания (секреты внутри). `Some` даже после ухода с
    /// формы — затирается единым местом (`forget_stale_passphrase`), когда
    /// `screen != Create`.
    create: Option<CreateDraft>,
}

impl App {
    /// Создаёт окно.
    ///
    /// `registry_path` приходит извне, а не берётся из `HOME`: иначе тесту
    /// нечем подставить свой реестр — подменить `HOME` мешает
    /// `unsafe_code = "forbid"`. `smoke_frames` — см. [`smoke_frames_from`].
    ///
    /// # Panics
    /// Если не удалось создать рантайм tokio — без него окно не может позвать
    /// ядро ни одним вызовом, работать дальше нечем.
    #[expect(
        clippy::expect_used,
        reason = "рантайм — условие работы окна; без него показывать нечего"
    )]
    #[must_use]
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        registry_path: PathBuf,
        home: PathBuf,
        ssh_config: PathBuf,
        closer: PathBuf,
        smoke_frames: Option<u32>,
        op_timeout: Duration,
    ) -> Self {
        theme::apply(&cc.egui_ctx);
        let rt = Runtime::new().expect("не удалось создать рантайм tokio");
        let local_deps = deps::check_local_deps();
        let mut app = Self {
            #[cfg(test)]
            test_operation: None,
            #[cfg(test)]
            isolate_vault_io: false,
            rt,
            ctx: cc.egui_ctx.clone(),
            pending_meta: None,
            sequence: 0,
            load: ListLoad::Loading,
            read_error: None,
            notices: Vec::new(),
            interaction: None,
            origin_role: None,
            interaction_following: Vec::new(),
            ssh_probe_key: None,
            ssh_status_key: None,
            holder_probe: None,
            holder_status: None,
            holder_next: 0.0,
            holder_requested: None,
            create_result_target: None,
            registry_path,
            home,
            ssh_config,
            // Ждать бегущее закрытие в `disarm` — не дольше, чем операцию целиком.
            scheduler: SystemdUser::new(vec![closer.into()], op_timeout),
            op_timeout,
            smoke_frames,
            frames_drawn: 0,
            entries: Vec::new(),
            env: Vec::new(),
            udisks: None,
            local_deps,
            pending: None,
            reload_tick: None,
            bus_probe: None,
            ssh_probe: None,
            ssh_status: None,
            message: None,
            validation_scope: NoticeScope::Global,
            rename: None,
            expanded: None,
            unlock: None,
            ssh_draft: None,
            ssh_confirm: None,
            delete: None,
            screen: Screen::List,
            create: None,
        };
        app.rebuild_env();
        app.spawn_op(&cc.egui_ctx, Op::Reload);
        app.spawn_bus_probe(&cc.egui_ctx);
        app
    }

    /// Единственная дверь для фоновых задач.
    ///
    /// Пробуждение окна вшито сюда намеренно: окно реактивное, и без
    /// `request_repaint` из задачи опрашивать результат было бы некому —
    /// после клика окно стояло бы с неактивными кнопками до случайного
    /// движения мыши. Новая операция не может это забыть, потому что заводится
    /// через ту же дверь.
    fn spawn_waking<F>(&self, ctx: &egui::Context, work: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let out = work.await;
            ctx.request_repaint();
            out
        })
    }

    /// Операции над реестром: одна за раз, иначе двойной клик отправит две правки.
    ///
    /// Возвращает `true`, если операция ушла в работу. Отказ **не молчит**:
    /// в крейте заведено правило «не молчим», а тихий отказ здесь выглядел бы
    /// для человека как «нажал — ничего не произошло».
    fn spawn_op(&mut self, ctx: &egui::Context, op: Op) -> bool {
        if self.pending.is_some() {
            self.message = Some("подождите: предыдущая операция ещё идёт".to_owned());
            return false;
        }
        if let Some(handle) = self.reload_tick.take() {
            handle.abort();
        }
        self.sequence = self.sequence.wrapping_add(1);
        let meta = Operation::from_op(&op, self.sequence);
        let scope = meta.scope();
        self.notices.retain(|n| n.scope != scope);
        if self.validation_scope == scope {
            self.message = None;
        }
        if meta.kind == OperationKind::Create {
            self.create_result_target = meta.target.clone();
        }
        self.pending_meta = Some(meta);
        let path = self.registry_path.clone();
        let home = self.home.clone();
        let ssh_config = self.ssh_config.clone();
        let scheduler = self.scheduler.clone();
        let limit = self.op_timeout;
        #[cfg(test)]
        let test_operation = self.test_operation;
        #[cfg(test)]
        let isolate_vault_io = self.isolate_vault_io;
        self.pending = Some(self.spawn_waking(ctx, async move {
            #[cfg(test)]
            if let Some(operation) = test_operation {
                return operation(op);
            }
            // Таймаут накрывает операцию ЦЕЛИКОМ, включая пробу: человеку не
            // важно, на каком шаге застряло, ему важно, что окно не висит.
            match tokio::time::timeout(limit, async {
                #[cfg(test)]
                if isolate_vault_io && matches!(op, Op::Open { .. } | Op::Create { .. }) {
                    // GUI tests retain the real timeout while replacing live D-Bus I/O.
                    return std::future::pending::<OpOutcome>().await;
                }
                run_op(&path, &home, &ssh_config, &scheduler, op).await
            })
            .await
            {
                Ok(outcome) => outcome,
                Err(_) => OpOutcome::Failed(format!(
                    "хранилище не откликнулось {}. Возможно, том занят другой программой. \
                     Состояние записи не изменено — обновите список",
                    timeout_text(limit)
                )),
            }
        }));
        true
    }

    /// Периодическая перечитка реестра, пока есть открытые тома.
    ///
    /// E-minimal: закрыватель пишет отложенное закрытие в реестр, а окно
    /// должно показать это без перезапуска. Период в 5 с — баланс между
    /// свежестью картинки и нагрузкой на диск/шину.
    fn spawn_reload_tick(&mut self, ctx: &egui::Context) {
        if self.reload_tick.is_some() || self.pending.is_some() {
            return;
        }
        let path = self.registry_path.clone();
        self.reload_tick = Some(self.spawn_waking(ctx, async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            match Registry::load_from(&path).await {
                Ok(reg) => OpOutcome::Loaded(reg.entries().to_vec()),
                Err(e) => OpOutcome::Failed(error_text(&e)),
            }
        }));
    }

    /// Проба шины — отдельная задача, а не часть загрузки списка: зависший
    /// D-Bus не имеет права задерживать показ уже прочитанных записей.
    fn spawn_bus_probe(&mut self, ctx: &egui::Context) {
        if self.bus_probe.is_some() {
            return;
        }
        self.bus_probe = Some(self.spawn_waking(ctx, async {
            match Udisks::connect().await {
                Ok(ud) => UdisksStatus::Available(ud.version().to_owned()),
                Err(e) => UdisksStatus::Missing(error_text(&e)),
            }
        }));
    }

    /// Проба SSH-связки раскрытой карточки: читает config и считает статус
    /// строки `Include` и коллизию имён; для открытого хранилища — ещё и
    /// резолюцию `ssh -G` по каждому хосту (К-7). Пробуждение окна — через
    /// [`App::spawn_waking`], как у любой фоновой задачи (инвариант 8).
    /// Резолюция зовётся с `config = None`: она обязана читать настоящий
    /// config пользователя — в этом смысл сверки.
    fn spawn_ssh_probe(
        &mut self,
        ctx: &egui::Context,
        label: Label,
        hosts: Vec<SshHost>,
        resolve: bool,
    ) {
        if self.ssh_probe.is_some() {
            return;
        }
        self.ssh_probe_key =
            self.entries
                .iter()
                .find(|e| e.label() == &label)
                .map(|e| SshProbeKey {
                    label: label.clone(),
                    kind: e.kind().clone(),
                    hosts: hosts.clone(),
                    resolve,
                });
        let config = self.ssh_config.clone();
        let home = self.home.clone();
        let timeout = self.op_timeout;
        let config_dir = self
            .registry_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();
        self.ssh_probe = Some(self.spawn_waking(ctx, async move {
            let snippet = ssh::snippet_path(&config_dir, &label);
            let line = ssh::include_line(&snippet);
            let (text, error) = match tokio::fs::read_to_string(&config).await {
                Ok(text) => (Some(text), None),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
                Err(e) => (None, Some(e.to_string())),
            };
            let mut resolutions = Vec::new();
            if resolve {
                let symlink = panzir_core::mountpoint::symlink_path(&home, &label);
                for h in &hosts {
                    let expected = symlink.join(&h.key_file);
                    resolutions.push(match ssh::ssh_g(&h.host, None, timeout).await {
                        Ok(r) => SshResolution {
                            ok: ssh::resolution_confirms(&r, &expected),
                            host: h.host.clone(),
                            detail: None,
                        },
                        Err(e) => SshResolution {
                            ok: false,
                            host: h.host.clone(),
                            detail: Some(e.to_string()),
                        },
                    });
                }
            }
            SshCardStatus {
                include: ssh::include_status(text.as_deref(), &line),
                collision: text
                    .as_deref()
                    .and_then(|t| ssh::detect_collision(t, &hosts)),
                error,
                resolutions,
                label,
            }
        }));
    }

    /// Снимает результаты завершившихся задач. Не блокирует.
    fn take_finished(&mut self) {
        if self.pending.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(handle) = self.pending.take()
        {
            let outcome = self.rt.block_on(handle);
            self.apply(outcome);
        }
        if self
            .reload_tick
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
            && let Some(handle) = self.reload_tick.take()
        {
            let outcome = self.rt.block_on(handle);
            self.apply_read(outcome);
        }
        if self.bus_probe.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(handle) = self.bus_probe.take()
            && let Ok(status) = self.rt.block_on(handle)
        {
            self.udisks = Some(status);
            self.rebuild_env();
        }
        if self.ssh_probe.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(handle) = self.ssh_probe.take()
            && let Ok(status) = self.rt.block_on(handle)
        {
            self.accept_ssh_status(status);
        }
        if self
            .holder_probe
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
            && let Some(handle) = self.holder_probe.take()
            && let Ok(status) = self.rt.block_on(handle)
            && self
                .holder_target()
                .is_some_and(|(l, p)| l == status.label && p == status.mount_point)
        {
            self.holder_status = Some(status);
        }
    }

    fn set_notice(&mut self, scope: NoticeScope, title: String, text: String) {
        self.notices.retain(|n| n.scope != scope);
        self.notices.push(Notice { scope, title, text });
    }

    fn replace_entries(&mut self, entries: Vec<VaultEntry>) {
        self.entries = entries;
        self.load = ListLoad::Loaded;
        self.forget_stale_passphrase();
        if self
            .ssh_status_key
            .as_ref()
            .is_some_and(|key| self.current_ssh_key().as_ref() != Some(key))
        {
            self.ssh_status = None;
            self.ssh_status_key = None;
        }
        if self.holder_status.as_ref().is_some_and(|s| {
            self.holder_target()
                .is_none_or(|(l, p)| l != s.label || p != s.mount_point)
        }) {
            self.holder_status = None;
            self.holder_next = 0.0;
        }
    }

    fn apply_read(&mut self, outcome: Result<OpOutcome, tokio::task::JoinError>) {
        match outcome {
            Ok(OpOutcome::Loaded(entries)) => {
                self.replace_entries(entries);
                self.read_error = None;
            }
            Ok(OpOutcome::LoadedWith(entries, text)) => {
                self.replace_entries(entries);
                self.read_error = Some(text);
            }
            Ok(OpOutcome::Failed(text)) => {
                self.read_error = Some(text);
                if self.load != ListLoad::Loaded {
                    self.load = ListLoad::Failed;
                }
            }
            Err(e) => {
                self.read_error = Some(format!("Чтение списка не выполнилось: {e}"));
                if self.load != ListLoad::Loaded {
                    self.load = ListLoad::Failed;
                }
            }
        }
    }

    fn apply(&mut self, outcome: Result<OpOutcome, tokio::task::JoinError>) {
        let meta = self.pending_meta.take();
        if meta.as_ref().is_some_and(|o| o.request != self.sequence) {
            return;
        }
        if meta
            .as_ref()
            .is_some_and(|o| o.kind == OperationKind::Reload)
        {
            self.apply_read(outcome);
            return;
        }
        let success = matches!(
            outcome,
            Ok(OpOutcome::Loaded(_) | OpOutcome::LoadedWith(_, _))
        );
        let scope = meta.as_ref().map_or(NoticeScope::Global, Operation::scope);
        let title = meta
            .as_ref()
            .map_or("Операция не выполнилась".into(), Operation::error_title);
        // Наш rename переносит раскрытие; внешнее изменение такой эвристики не имеет.
        if success
            && let Some(op) = &meta
            && op.kind == OperationKind::Rename
            && self.expanded == op.target
        {
            self.expanded = op.new_label.clone();
        }
        match outcome {
            Ok(OpOutcome::Loaded(entries)) => self.replace_entries(entries),
            Ok(OpOutcome::LoadedWith(entries, text)) => {
                self.replace_entries(entries);
                self.set_notice(scope, "Операция выполнена с предупреждением".into(), text);
            }
            Ok(OpOutcome::Failed(text)) => self.set_notice(scope, title, text),
            Err(e) => self.set_notice(scope, title, format!("Операция не выполнилась: {e}")),
        }
        if success && let Some(op) = &meta {
            if op.kind == OperationKind::Include {
                // The config changed: even a probe with identical record inputs
                // may have read it before the write. Drop completed handles too.
                if let Some(probe) = self.ssh_probe.take() {
                    probe.abort();
                }
                self.ssh_probe_key = None;
                self.ssh_status = None;
                self.ssh_status_key = None;
            }
            if op.kind == OperationKind::Create && self.screen == Screen::Create {
                self.screen = Screen::List;
                if let Some(label) = &op.target {
                    theme::request_focus(&self.ctx, theme::id(label.as_str(), "primary"));
                }
                self.forget_stale_passphrase();
            }
            if matches!(
                op.kind,
                OperationKind::Rename | OperationKind::AddSsh | OperationKind::Include
            ) {
                self.clear_card(false);
            }
        }
    }

    fn current_ssh_key(&self) -> Option<SshProbeKey> {
        let label = self.expanded.as_ref()?;
        let e = self.entries.iter().find(|e| e.label() == label)?;
        Some(SshProbeKey {
            label: label.clone(),
            kind: e.kind().clone(),
            hosts: e.ssh_hosts().to_vec(),
            resolve: matches!(e.state(), VaultState::Open { .. }),
        })
    }

    fn accept_ssh_status(&mut self, status: SshCardStatus) {
        let key = self.ssh_probe_key.take();
        if key.is_some() && key == self.current_ssh_key() {
            self.ssh_status = Some(status);
            self.ssh_status_key = key;
        }
    }

    fn holder_target(&self) -> Option<(Label, PathBuf)> {
        let label = self.expanded.as_ref()?;
        let e = self
            .entries
            .iter()
            .find(|e| e.label() == label && e.close_attempts() > 0)?;
        if let VaultState::Open { mount_point, .. } = e.state() {
            Some((label.clone(), mount_point.clone()))
        } else {
            None
        }
    }

    fn maybe_probe_holders(&mut self, ctx: &egui::Context) {
        let Some((label, mount_point)) = self.holder_target() else {
            return;
        };
        let now = ctx.input(|i| i.time);
        let changed = self
            .holder_requested
            .as_ref()
            .is_none_or(|(l, p)| *l != label || *p != mount_point);
        if self.holder_probe.is_some() || (!changed && now < self.holder_next) {
            return;
        }
        // Дедлайн задаётся при dispatch, а не на каждом кадре.
        if now < self.holder_next && !changed {
            return;
        }
        self.holder_next = now + 5.0;
        self.holder_requested = Some((label.clone(), mount_point.clone()));
        self.holder_probe = Some(self.spawn_waking(ctx, async move {
            let path = mount_point.clone();
            let names =
                tokio::task::spawn_blocking(move || panzir_core::holders::find_holders(&path))
                    .await
                    .unwrap_or_default();
            HolderStatus {
                label,
                mount_point,
                names,
            }
        }));
    }

    /// Собирает плашку окружения из локальных зависимостей и состояния шины.
    fn rebuild_env(&mut self) {
        let mut lines = Vec::with_capacity(self.local_deps.statuses.len() + 1);
        // Пока проба не вернулась, состояние шины НЕИЗВЕСТНО — а неизвестное
        // не то же самое, что сломанное. Строки нет вовсе, иначе исправная
        // машина первые кадры сообщала бы о нехватке того, что ещё проверяется.
        match &self.udisks {
            Some(UdisksStatus::Available(version)) => lines.push(EnvLine {
                name: "udisks2".to_owned(),
                ok: true,
                hint: format!("версия {version}"),
            }),
            Some(UdisksStatus::Missing(hint)) => lines.push(EnvLine {
                name: "udisks2".to_owned(),
                ok: false,
                hint: hint.clone(),
            }),
            None => {}
        }
        for status in &self.local_deps.statuses {
            lines.push(EnvLine {
                name: status.name.to_owned(),
                ok: status.ok,
                hint: status.hint.clone(),
            });
        }
        self.env = lines;
    }

    /// Кадры smoke-режима: считаем и закрываемся сами.
    ///
    /// Запрос перерисовки здесь — про холостую прокрутку кадров и живёт только
    /// в smoke-режиме: под `xvfb-run` событий ввода нет вовсе, и без него
    /// следующий кадр не наступит никогда. Пробуждение из [`App::spawn_op`] —
    /// другое дело, оно работает в любом режиме.
    fn tick_smoke(&mut self, ctx: &egui::Context) {
        let Some(limit) = self.smoke_frames else {
            return;
        };
        self.frames_drawn += 1;
        if self.frames_drawn >= limit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else {
            ctx.request_repaint();
        }
    }

    /// Сброс восстановимой истории после последнего store поля кадра.
    /// Обычные кадры, собственные Подробнее и unchanged reload сюда не входят.
    fn clear_history(&self, id: egui::Id) {
        if let Some(mut state) = egui::TextEdit::load_state(&self.ctx, id) {
            state.clear_undoer();
            state.store(&self.ctx, id);
        }
    }

    fn clear_create_passwords(&mut self) {
        if let Some(d) = self.create.as_mut() {
            d.passphrase.zeroize();
            d.confirm.zeroize();
        }
        self.clear_history(theme::id("create", "passphrase"));
        self.clear_history(theme::id("create", "confirm"));
    }

    fn clear_card(&mut self, restore_focus: bool) {
        if self
            .interaction
            .as_ref()
            .is_some_and(|(label, _)| self.validation_scope == NoticeScope::Card(label.clone()))
        {
            self.message = None;
        }
        if let Some(d) = self.unlock.as_mut() {
            d.text.zeroize();
        }
        if let Some(d) = self.delete.as_mut() {
            d.passphrase.zeroize();
        }
        if let Some(d) = &self.unlock {
            self.clear_history(theme::id(d.target.as_str(), "unlock"));
        }
        if let Some(d) = &self.delete {
            self.clear_history(theme::id(d.target.as_str(), "delete-password"));
        }
        if restore_focus && let Some((label, kind)) = &self.interaction {
            let role = self.origin_role.unwrap_or("primary");
            let original_exists = self
                .entries
                .iter()
                .any(|e| e.label() == label && e.kind() == kind);
            let origin_visible = role == "primary"
                || (self.expanded.as_ref() == Some(label)
                    && (role != "include"
                        || self
                            .ssh_status
                            .as_ref()
                            .is_some_and(|s| s.label == *label && s.include != IncludeStatus::Ok)));
            let target = if original_exists && origin_visible && self.pending.is_none() {
                theme::id(label.as_str(), role)
            } else if let Some(label) = self
                .interaction_following
                .iter()
                .find(|label| self.entries.iter().any(|e| e.label() == *label))
            {
                theme::id(
                    label.as_str(),
                    if self.pending.is_some() {
                        "details"
                    } else {
                        "primary"
                    },
                )
            } else {
                theme::id(
                    "list",
                    if self.pending.is_some() {
                        "status"
                    } else {
                        "create"
                    },
                )
            };
            theme::request_focus(&self.ctx, target);
        }
        self.unlock = None;
        self.delete = None;
        self.rename = None;
        self.ssh_draft = None;
        self.ssh_confirm = None;
        self.interaction = None;
        self.origin_role = None;
        self.interaction_following.clear();
    }

    fn begin_card(
        &mut self,
        label: &Label,
        origin: &'static str,
        field: &'static str,
        details: bool,
    ) -> bool {
        self.clear_card(false);
        let Some(index) = self.entries.iter().position(|e| e.label() == label) else {
            return false;
        };
        self.interaction = Some((label.clone(), self.entries[index].kind().clone()));
        self.interaction_following = self.entries[index + 1..]
            .iter()
            .map(|e| e.label().clone())
            .collect();
        self.origin_role = Some(origin);
        if details {
            self.expanded = Some(label.clone());
        } else if self.expanded.as_ref().is_some_and(|l| l != label) {
            self.expanded = None;
        }
        self.clear_history(theme::id(label.as_str(), field));
        theme::request_focus(&self.ctx, theme::id(label.as_str(), field));
        true
    }

    fn forget_stale_passphrase(&mut self) {
        let invalid = self.interaction.as_ref().is_some_and(|(label, kind)| {
            self.screen != Screen::List
                || !self.entries.iter().any(|e| {
                    e.label() == label
                        && e.kind() == kind
                        && (self.unlock.is_none() || !matches!(e.state(), VaultState::Open { .. }))
                })
        });
        if invalid {
            let target = self.interaction.as_ref().map(|(l, _)| l.clone());
            // Resolve focus against the layout that will actually be drawn.
            if self.expanded == target {
                self.expanded = None;
            }
            self.clear_card(true);
        }
        if self
            .expanded
            .as_ref()
            .is_some_and(|label| !self.entries.iter().any(|e| e.label() == label))
        {
            self.expanded = None;
        }
        if self.screen != Screen::Create && self.create.is_some() {
            self.clear_create_passwords();
            self.create = None;
        }
    }

    /// Путь контейнера записи. `None` — это носитель, а не файл.
    fn container_of(&self, label: &Label) -> Option<PathBuf> {
        self.entries
            .iter()
            .find(|e| e.label().as_str() == label.as_str())
            .and_then(|e| match e.kind() {
                VaultKind::File(path) => Some(path.clone()),
                VaultKind::Device { .. } => None,
            })
    }

    /// Срок автозакрытия записи. Записи нет — срок по умолчанию: до открытия
    /// дело всё равно не дойдёт (`container_of` откажет раньше).
    fn auto_close_of(&self, label: &Label) -> Option<Duration> {
        self.entries
            .iter()
            .find(|e| e.label().as_str() == label.as_str())
            .map_or(Some(DEFAULT_AUTO_CLOSE), VaultEntry::auto_close)
    }

    /// Отказ по носителю произносится словами: молчание здесь — тот же дефект,
    /// что и ложное сообщение (инвариант 10).
    fn refuse_device(&mut self, label: &Label) {
        self.set_notice(
            NoticeScope::Card(label.clone()),
            "Операция недоступна".into(),
            "Носители пока не поддерживаются: сейчас можно работать только с файлами-хранилищами"
                .into(),
        );
    }

    fn handle(&mut self, ctx: &egui::Context, action: ListAction) {
        let navigation = matches!(
            action,
            ListAction::Cancel | ListAction::ToggleDetails(_) | ListAction::Dismiss(_)
        );
        if !navigation && self.pending.is_some() {
            self.validation_scope = NoticeScope::Global;
            self.message = Some("Подождите: предыдущая операция ещё идёт".into());
            return;
        }
        self.forget_stale_passphrase();
        match action {
            ListAction::Cancel => self.clear_card(true),
            ListAction::Dismiss(scope) => {
                self.notices.retain(|n| n.scope != scope);
                self.message = None;
            }
            ListAction::Reload => {
                self.spawn_op(ctx, Op::Reload);
            }
            ListAction::ToggleDetails(label) => {
                if self.expanded.as_ref() == Some(&label) {
                    if self.interaction.as_ref().is_some_and(|(l, _)| l == &label) {
                        self.clear_card(false);
                    }
                    self.expanded = None;
                    theme::request_focus(ctx, theme::id(label.as_str(), "details"));
                } else {
                    if self.interaction.as_ref().is_some_and(|(l, _)| l != &label) {
                        self.clear_card(false);
                    }
                    self.expanded = Some(label);
                }
            }
            ListAction::BeginUnlock(label) => {
                if self.container_of(&label).is_none() {
                    self.clear_card(false);
                    self.refuse_device(&label);
                    return;
                }
                if self.begin_card(&label, "primary", "unlock", false) {
                    self.unlock = Some(UnlockDraft {
                        target: label,
                        text: String::new(),
                    });
                }
            }
            ListAction::BeginRename(label) => {
                if self.begin_card(&label, "rename", "rename-field", true) {
                    self.rename = Some(RenameDraft {
                        target: label.clone(),
                        text: label.to_string(),
                    });
                }
            }
            ListAction::BeginSshHost(label) => {
                if self.begin_card(&label, "ssh-host", "ssh-host-field", true) {
                    self.ssh_draft = Some(SshHostDraft {
                        target: label,
                        host: String::new(),
                        hostname: String::new(),
                        user: String::new(),
                        port: String::new(),
                        key_file: String::new(),
                    });
                }
            }
            ListAction::Open(label) => {
                // Секрет забирается `mem::take`: буфер виджета остаётся пустой
                // строкой, копии не создаётся, а черновик снимается сразу — и
                // при успехе, и при отказе. Оставлять фразу в поле «чтобы
                // поправить опечатку» значило бы не выполнить единственное
                // обещание, которое мы дали: защитить участок от клавиши до
                // `SecretString`.
                if self
                    .unlock
                    .as_ref()
                    .is_none_or(|d| d.target != label || d.text.is_empty())
                {
                    return;
                }
                let typed = self
                    .unlock
                    .as_mut()
                    .filter(|d| d.target.as_str() == label.as_str())
                    .map(|d| std::mem::take(&mut d.text));
                self.clear_card(false);
                let Some(mut typed) = typed else { return };
                // Секрет строится из `&str`: `SecretString` копирует его в
                // собственный буфер, который затирает при уничтожении, — а
                // исходную строку мы затираем сами, здесь. Отдать `String`
                // целиком было бы короче, но перевод `String → Box<str>`
                // вправе перевыделить память, и тогда незачищенная копия
                // осталась бы лежать в куче (находка ревью Гейта-2).
                let passphrase = SecretString::from(typed.as_str());
                typed.zeroize();

                let auto_close = self.auto_close_of(&label);
                match self.container_of(&label) {
                    Some(container) => {
                        self.spawn_op(
                            ctx,
                            Op::Open {
                                label,
                                container,
                                passphrase,
                                auto_close,
                            },
                        );
                    }
                    None => self.refuse_device(&label),
                }
            }
            ListAction::Close(label) => {
                self.clear_card(false);
                // Путь контейнера берём из записи: в `Op` он приходит уже
                // разобранным, чтобы фоновая задача не читала реестр второй раз.
                match self.container_of(&label) {
                    Some(container) => {
                        self.spawn_op(ctx, Op::Close { label, container });
                    }
                    None => self.refuse_device(&label),
                }
            }
            ListAction::AskDelete(label) => {
                // Носитель — отказ словами, а не сирота: `container_of` даёт
                // `None` для носителей (находка 1 ревью плана). Сирота —
                // только файл, которого нет на месте.
                match self.container_of(&label) {
                    Some(container) => {
                        // Осиротелость — проверкой пути в момент клика
                        // (гриль 6), не кэшем списка.
                        let orphan = !container.exists();
                        if !self.begin_card(
                            &label,
                            "delete",
                            if orphan {
                                "delete-submit"
                            } else {
                                "delete-password"
                            },
                            true,
                        ) {
                            return;
                        }
                        self.delete = Some(DeleteDraft {
                            target: label.clone(),
                            orphan,
                            passphrase: String::new(),
                        });
                        // Баннер живёт на карточке — раскрываем её, иначе
                        // подтверждение осталось бы невидимым.
                        self.expanded = Some(label);
                    }
                    None => {
                        self.clear_card(false);
                        self.refuse_device(&label);
                    }
                }
            }
            ListAction::ConfirmDelete => {
                // Секрет забирается `mem::take` и черновик снимается сразу —
                // как у разблокировки: и при успехе, и при отказе.
                let Some(draft) = self.delete.as_mut() else {
                    return;
                };
                if !draft.orphan && draft.passphrase.is_empty() {
                    return;
                }
                let orphan = draft.orphan;
                let label = draft.target.clone();
                let mut typed = std::mem::take(&mut draft.passphrase);
                self.clear_card(false);
                let (container, passphrase) = if orphan {
                    typed.zeroize();
                    (None, None)
                } else {
                    let Some(container) = self.container_of(&label) else {
                        // Запись исчезла из списка, пока баннер висел: удалять
                        // вслепую нельзя — фраза относилась к другой правде.
                        typed.zeroize();
                        self.message = Some(format!(
                            "записи «{label}» больше нет в списке — обновите окно"
                        ));
                        return;
                    };
                    // Секрет строится из `&str`: перевод `String` вправе
                    // оставить незачищенную копию в куче (находка Гейта-2),
                    // поэтому исходник затираем сами.
                    let passphrase = SecretString::from(typed.as_str());
                    typed.zeroize();
                    (Some(container), Some(passphrase))
                };
                self.spawn_op(
                    ctx,
                    Op::Delete {
                        label,
                        container,
                        passphrase,
                    },
                );
            }
            ListAction::CommitRename { old, new } => match Label::new(&new) {
                Ok(new) => {
                    // Черновик снимается только если операция реально началась:
                    // иначе набранное имя исчезло бы вместе с полем.
                    self.spawn_op(ctx, Op::Rename { old, new });
                }
                Err(e) => {
                    self.validation_scope = NoticeScope::Card(old);
                    self.message = Some(error_text(&e));
                }
            },
            ListAction::StartCreate => {
                self.clear_card(false);
                self.clear_create_passwords();
                self.screen = Screen::Create;
                self.create = Some(CreateDraft::default());
                self.create_result_target = None;
                self.message = None;
                theme::request_focus(ctx, theme::id("create", "label"));
            }
            ListAction::AddSshHost {
                target,
                host,
                hostname,
                user,
                port,
                key_file,
            } => {
                // Порт — опциональное поле: пусто → None, иначе число.
                let port = match port.trim() {
                    "" => None,
                    raw => match raw.parse::<u16>() {
                        Ok(p) => Some(p),
                        Err(_) => {
                            self.validation_scope = NoticeScope::Card(target.clone());
                            self.message = Some(
                                "порт не подходит: целое число от 0 до 65535 или оставьте поле пустым"
                                    .to_owned(),
                            );
                            return;
                        }
                    },
                };
                match SshHost::new(&host, &hostname, &user, port, &key_file) {
                    Ok(host) => {
                        // Черновик снимается только если операция началась —
                        // как у переименования: набранное не пропадает молча.
                        if self.spawn_op(
                            ctx,
                            Op::AddSshHost {
                                label: target,
                                host,
                            },
                        ) {
                            // Несекретный ввод остаётся доступен после отказа.
                        }
                    }
                    Err(e) => {
                        self.validation_scope = NoticeScope::Card(target);
                        self.message = Some(error_text(&Error::from(e)));
                    }
                }
            }
            ListAction::AskSshInclude { target, repair } => {
                // Точная строка считается здесь, а не в виджете: человеку
                // показывается ровно то, что уйдёт в его config.
                let config_dir = self
                    .registry_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .to_path_buf();
                let line = ssh::include_line(&ssh::snippet_path(&config_dir, &target));
                if !self.begin_card(&target, "include", "include-submit", true) {
                    return;
                }
                self.ssh_confirm = Some(SshConfirm {
                    target,
                    repair,
                    line,
                });
            }
            ListAction::ConfirmSshInclude => {
                let Some(confirm) = self.ssh_confirm.clone() else {
                    return;
                };
                // Черновик снимается, только если операция ушла в работу —
                // как у переименования и добавления хоста.
                if self.spawn_op(
                    ctx,
                    Op::SshInclude {
                        label: confirm.target,
                        repair: confirm.repair,
                    },
                ) {
                    // Подтверждение снимается успешным результатом.
                }
            }
        }
    }

    /// Экран создания: Cancel уводит на список (черновик затрёт `forget`),
    /// Submit валидирует, строит секрет и запускает `Op::Create`.
    fn handle_create(&mut self, ctx: &egui::Context, action: CreateAction) {
        match action {
            CreateAction::Dismiss(scope) => {
                self.notices.retain(|n| n.scope != scope);
                self.message = None;
                return;
            }
            CreateAction::Cancel => {
                if matches!(self.validation_scope, NoticeScope::Create(_)) {
                    self.message = None;
                }
                self.clear_create_passwords();
                self.screen = Screen::List;
                self.create = None;
                theme::request_focus(
                    ctx,
                    if self.pending.is_some() {
                        theme::id("list", "status")
                    } else {
                        theme::id("list", "create")
                    },
                );
                return;
            }
            CreateAction::Submit => {}
        }
        if self.pending.is_some() {
            return;
        }
        if self
            .create
            .as_ref()
            .is_none_or(|d| d.passphrase.is_empty() || d.passphrase != d.confirm)
        {
            return;
        }
        if let Some(d) = self.create.as_ref()
            && let Ok(label) = Label::new(&d.label)
        {
            self.validation_scope = NoticeScope::Create(label);
        }
        // 1. Читаем и валидируем — секрет НЕ трогаем, пока не убедились.
        let parsed = self
            .create
            .as_ref()
            .map(|d| (Label::new(&d.label), view_create::parse_size(&d.size)));
        let Some((label, size)) = parsed else { return };
        let label = match label {
            Ok(l) => l,
            Err(e) => {
                self.message = Some(error_text(&e));
                return;
            }
        };
        let Some(size_bytes) = size else {
            self.message =
                Some("размер не подходит: целое число МиБ, не меньше минимума".to_owned());
            return;
        };
        // 1-bis. Пре-чек занятой метки — срезает частый случай (метка уже у
        // записи, в т.ч. флешки) ДО создания, без спиннера. НЕ единственная
        // защита: настоящая — `Registry::add` под локом в `run_create`, с
        // откатом тома при гонке.
        if self
            .entries
            .iter()
            .any(|e| e.label().as_str() == label.as_str())
        {
            self.message = Some(error_text(&Error::DuplicateLabel(label.to_string())));
            return;
        }
        // 2. Валидно — забираем секрет: буфер виджета пустеет (`mem::take`),
        // повтор затираем, `SecretString` строим из `&str` и исходник затираем
        // сами (перевод `String` вправе оставить незачищенную копию в куче).
        let passphrase = {
            let Some(draft) = self.create.as_mut() else {
                return;
            };
            let mut typed = std::mem::take(&mut draft.passphrase);
            draft.confirm.zeroize();
            let secret = SecretString::from(typed.as_str());
            typed.zeroize();
            secret
        };
        self.clear_create_passwords();
        // 3. Запускаем; черновик (уже без секрета) снимет `forget` при `screen = List`.
        let container = container_path(&self.home, &label);
        self.spawn_op(
            ctx,
            Op::Create {
                label,
                container,
                size_bytes,
                passphrase,
            },
        );
    }

    /// Ждёт завершения операции по её собственному сигналу и применяет исход.
    ///
    /// Только для тестов: `sleep` и повторов здесь нет, ожидание идёт по
    /// `JoinHandle`. Дедлайн превращает зависание в названный провал.
    #[cfg(test)]
    #[expect(clippy::expect_used, reason = "тестовый помощник")]
    fn block_until_idle(&mut self) {
        // Таймер строится ВНУТРИ рантайма: `tokio::time::timeout`, созданный
        // снаружи, паникует «there is no reactor running» ещё до ожидания.
        if let Some(handle) = self.bus_probe.take() {
            let status = self
                .rt
                .block_on(async move { tokio::time::timeout(TEST_DEADLINE, handle).await })
                .expect("проба шины не завершилась за отведённое время");
            if let Ok(status) = status {
                self.udisks = Some(status);
            }
        }
        // Периодическая перечитка в тестах не нужна и ждала бы 5 с.
        if let Some(handle) = self.reload_tick.take() {
            handle.abort();
        }
        if let Some(handle) = self.ssh_probe.take()
            && let Ok(status) = self
                .rt
                .block_on(async move { tokio::time::timeout(TEST_DEADLINE, handle).await })
                .expect("проба SSH-связки не завершилась за отведённое время")
        {
            self.accept_ssh_status(status);
        }
        if let Some(handle) = self.pending.take() {
            let outcome = self
                .rt
                .block_on(async move { tokio::time::timeout(TEST_DEADLINE, handle).await })
                .expect("операция ядра не завершилась за отведённое время");
            self.apply(outcome);
        }
        self.rebuild_env();
    }
}

impl eframe::App for App {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        theme::BACKGROUND.to_normalized_gamma_f32()
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.take_finished();
        self.forget_stale_passphrase();
        if self.pending_meta.is_none()
            && self
                .ctx
                .data(|d| d.get_temp::<egui::Id>(egui::Id::new("panzir-focus-request")))
                == Some(theme::id("list", "status"))
        {
            let target = self
                .create_result_target
                .as_ref()
                .filter(|l| self.entries.iter().any(|e| e.label() == *l))
                .map_or(theme::id("list", "create"), |l| {
                    theme::id(l.as_str(), "details")
                });
            theme::request_focus(&self.ctx, target);
        }

        // E-minimal: если есть открытые тома, перечитываем реестр в фоне,
        // чтобы показать отложенное автозакрытие, записанное закрывателем.
        if self
            .entries
            .iter()
            .any(|e| matches!(e.state(), VaultState::Open { .. }))
        {
            self.spawn_reload_tick(ui.ctx());
        }

        let ctx = ui.ctx().clone();
        match self.screen {
            Screen::List => {
                let action = view_list::show(
                    ui,
                    ListInput {
                        entries: &self.entries,
                        env: &self.env,
                        message: self.message.as_deref(),
                        validation_scope: &self.validation_scope,
                        busy: self.pending.is_some(),
                        notices: &self.notices,
                        read_error: self.read_error.as_deref(),
                        load: self.load,
                        operation: self.pending_meta.as_ref(),
                        holder: self.holder_status.as_ref(),
                        rename: &mut self.rename,
                        expanded: &self.expanded,
                        unlock: &mut self.unlock,
                        ssh_draft: &mut self.ssh_draft,
                        ssh_status: &self.ssh_status,
                        ssh_confirm: &mut self.ssh_confirm,
                        delete: &mut self.delete,
                    },
                );
                if let Some(action) = action {
                    self.handle(&ctx, action);
                }
            }
            Screen::Create => {
                let busy = self.pending.is_some();
                let message = self.message.as_deref();
                let action = self.create.as_mut().and_then(|draft| {
                    view_create::show(ui, draft, busy, message, &self.entries, &self.notices)
                });
                if let Some(action) = action {
                    self.handle_create(&ctx, action);
                }
            }
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            match self.screen {
                Screen::Create => self.handle_create(&ctx, CreateAction::Cancel),
                Screen::List => self.clear_card(true),
            }
        }
        self.forget_stale_passphrase();
        self.maybe_probe_holders(&ctx);

        // Проба связки — для раскрытой карточки с хостами, когда статус
        // устарел (список сменился) или ещё не запрошен.
        if self.screen == Screen::List
            && self.ssh_probe.is_none()
            && let Some(label) = self.expanded.clone()
            && (self.ssh_status.is_none()
                || self.ssh_status_key.as_ref() != self.current_ssh_key().as_ref())
            && let Some(entry) = self.entries.iter().find(|e| e.label() == &label)
            && !entry.ssh_hosts().is_empty()
        {
            let hosts = entry.ssh_hosts().to_vec();
            // Резолюция `ssh -G` — только по открытому хранилищу: у закрытого
            // она ничего не добавляет к «ключи недоступны».
            let resolve = matches!(entry.state(), VaultState::Open { .. });
            self.spawn_ssh_probe(ui.ctx(), label, hosts, resolve);
        }

        self.tick_smoke(ui.ctx());
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.clear_card(false);
        self.clear_create_passwords();
    }
}

async fn run_op(
    path: &std::path::Path,
    home: &std::path::Path,
    ssh_config: &std::path::Path,
    scheduler: &SystemdUser,
    op: Op,
) -> OpOutcome {
    match op {
        Op::Reload => match Registry::load_from(path).await {
            Ok(reg) => OpOutcome::Loaded(reg.entries().to_vec()),
            Err(e) => OpOutcome::Failed(error_text(&e)),
        },
        Op::Delete {
            label,
            container,
            passphrase,
        } => {
            run_delete(
                path, home, ssh_config, scheduler, &label, container, passphrase,
            )
            .await
        }
        Op::Rename { old, new } => write_then_read(path, move |r| r.rename(&old, new)).await,
        Op::Close { label, container } => {
            run_close(path, home, scheduler, &label, &container).await
        }
        Op::Open {
            label,
            container,
            passphrase,
            auto_close,
        } => {
            run_open(
                path,
                home,
                scheduler,
                &label,
                &container,
                &passphrase,
                auto_close,
            )
            .await
        }
        Op::Create {
            label,
            container,
            size_bytes,
            passphrase,
        } => run_create(path, home, &label, &container, size_bytes, &passphrase).await,
        Op::AddSshHost { label, host } => run_add_ssh_host(path, home, &label, host).await,
        Op::SshInclude { label, repair } => run_ssh_include(path, ssh_config, &label, repair).await,
    }
}

/// Вставка/починка строки `Include` — по подтверждению (М-1): чужой config
/// правится только здесь, содержимое и права сохраняет ядро (М-2, М-3).
/// Реестр не меняется; перечитываем его, чтобы инвалидировать статус связки.
async fn run_ssh_include(
    path: &std::path::Path,
    ssh_config: &std::path::Path,
    label: &Label,
    repair: bool,
) -> OpOutcome {
    let config_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let snippet = ssh::snippet_path(config_dir, label);
    let result = if repair {
        ssh::repair_include(ssh_config, &snippet).await
    } else {
        ssh::apply_include(ssh_config, &snippet).await
    };
    match result {
        Ok(_) => match Registry::load_from(path).await {
            Ok(reg) => OpOutcome::Loaded(reg.entries().to_vec()),
            Err(e) => OpOutcome::Failed(error_text(&e)),
        },
        Err(e) => OpOutcome::Failed(error_text(&Error::from(e))),
    }
}

/// Добавление SSH-хоста: правда — в реестр под локом, затем сниппет
/// перезаписывается как производная (спека Ш-7). Отказ записи сниппета не
/// откатывает реестр: при открытии сниппет пересоздаётся из реестра.
async fn run_add_ssh_host(
    path: &std::path::Path,
    home: &std::path::Path,
    label: &Label,
    host: SshHost,
) -> OpOutcome {
    let written = Registry::with_write_lock_at(path, {
        let label = label.clone();
        move |r| {
            let entry = r
                .entries_mut()
                .iter_mut()
                .find(|e| e.label().as_str() == label.as_str())
                .ok_or_else(|| Error::VaultNotFound(label.as_str().to_owned()))?;
            entry.add_ssh_host(host);
            Ok(r.entries().to_vec())
        }
    })
    .await;
    let entries = match written {
        Ok(entries) => entries,
        Err(e) => return OpOutcome::Failed(error_text(&e)),
    };

    let Some(entry) = entries
        .iter()
        .find(|e| e.label().as_str() == label.as_str())
    else {
        return OpOutcome::Loaded(entries);
    };
    let config_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let snippet = panzir_core::ssh::snippet_path(config_dir, label);
    let symlink = panzir_core::mountpoint::symlink_path(home, label);
    let text = panzir_core::ssh::render_snippet(entry.ssh_hosts(), &symlink);
    match panzir_core::ssh::write_snippet_atomic(&snippet, &text).await {
        Ok(()) => OpOutcome::Loaded(entries),
        // Хост уже записан в реестр — это успех с отказавшей производной,
        // а не отказ операции: список обновляем, ворнинг говорим (инв. 10).
        Err(e) => OpOutcome::LoadedWith(
            entries,
            format!(
                "хост записан в список, но сниппет не обновился: {}",
                error_text(&Error::from(e))
            ),
        ),
    }
}

/// Открытие: одна задача, один секрет, одно пробуждение окна.
async fn run_open(
    path: &std::path::Path,
    home: &std::path::Path,
    scheduler: &SystemdUser,
    label: &Label,
    container: &std::path::Path,
    passphrase: &SecretString,
    auto_close: Option<Duration>,
) -> OpOutcome {
    let ud = match Udisks::connect().await {
        Ok(ud) => ud,
        Err(e) => return OpOutcome::Failed(error_text(&e)),
    };
    match lifecycle::open_file_vault(
        &ud, container, label, passphrase, home, scheduler, auto_close,
    )
    .await
    {
        // Точка монтирования — из ответа udisks2, не угаданная: путь симлинка
        // сюда не подставляется (спека п.2 скоупа).
        Ok(opened) => {
            let outcome = set_state_then_read(
                path,
                label,
                VaultState::Open {
                    mount_point: opened.mount_point,
                    until: opened.until,
                },
            )
            .await;
            // Ш-7: сниппет пересоздаётся из реестра при каждом открытии —
            // он производная, а не правда. Сверка связки и `ssh -G` по
            // хостам показываются пробой карточки (список сменился → статус
            // инвалидирован → переспрос).
            let OpOutcome::Loaded(entries) = &outcome else {
                return outcome;
            };
            let Some(entry) = entries
                .iter()
                .find(|e| e.label().as_str() == label.as_str())
                .filter(|e| !e.ssh_hosts().is_empty())
            else {
                return outcome;
            };
            let config_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
            let snippet = ssh::snippet_path(config_dir, label);
            let symlink = panzir_core::mountpoint::symlink_path(home, label);
            let text = ssh::render_snippet(entry.ssh_hosts(), &symlink);
            match ssh::write_snippet_atomic(&snippet, &text).await {
                Ok(()) => outcome,
                Err(e) => OpOutcome::LoadedWith(
                    entries.clone(),
                    format!(
                        "хранилище открыто, но SSH-сниппет не обновился: {}",
                        error_text(&Error::from(e))
                    ),
                ),
            }
        }
        Err(e) => OpOutcome::Failed(error_text(&e)),
    }
}

/// Создание: папка → контейнер (ядро создаёт открытым) → симлинк → запись.
///
/// Одна задача, один секрет, одно пробуждение окна (инвариант 8). `home`
/// приходит параметром (инвариант 9), env здесь не читается.
async fn run_create(
    path: &std::path::Path,
    home: &std::path::Path,
    label: &Label,
    container: &std::path::Path,
    size_bytes: u64,
    passphrase: &SecretString,
) -> OpOutcome {
    let ud = match Udisks::connect().await {
        Ok(ud) => ud,
        Err(e) => return OpOutcome::Failed(error_text(&e)),
    };
    // Папка 0700 → контейнер → симлинк → откат-при-отказе — целиком в ядре:
    // `ensure_loop_detached` — `pub(crate)`, из окна откат физически невыразим.
    let created = match create::create_file_vault(
        &ud, home, label, container, size_bytes, passphrase,
    )
    .await
    {
        Ok(created) => created,
        Err(e) => return OpOutcome::Failed(error_text(&e)),
    };
    // Запись в реестр под локом — НАСТОЯЩАЯ защита от гонки меток (пре-чек в
    // `handle_create` лишь срезает частый случай без спиннера). На отказе —
    // откат тома ядром, иначе остался бы живой том без записи.
    let result = Registry::with_write_lock_at(path, {
        let label = label.clone();
        let container = container.to_path_buf();
        let mount_point = created.mount_point.clone();
        move |r| {
            r.add(VaultEntry::new(
                label,
                VaultKind::File(container),
                VaultState::Open {
                    mount_point,
                    until: None,
                },
            ))?;
            Ok(r.entries().to_vec())
        }
    })
    .await;
    match result {
        Ok(entries) => OpOutcome::Loaded(entries),
        Err(e) => {
            create::rollback_created_file_vault(&ud, home, label, &created.loop_object, container)
                .await;
            OpOutcome::Failed(error_text(&e))
        }
    }
}

/// Закрытие: проба → решение → действие → правда в реестре.
///
/// Проба и закрытие — ОДНА задача (инвариант 8): одно пробуждение окна на
/// завершении, промежуточный результат наружу не выходит.
async fn run_close(
    path: &std::path::Path,
    home: &std::path::Path,
    scheduler: &SystemdUser,
    label: &Label,
    container: &std::path::Path,
) -> OpOutcome {
    let ud = match Udisks::connect().await {
        Ok(ud) => ud,
        Err(e) => return OpOutcome::Failed(error_text(&e)),
    };
    let probe = match lifecycle::probe_file_vault(&ud, container).await {
        Ok(p) => p,
        Err(e) => return OpOutcome::Failed(error_text(&e)),
    };
    match close_decision(probe) {
        CloseDecision::AlreadyDetached => {
            // Тихий и, вероятно, самый частый случай: том закрыли штатной
            // утилитой дисков или приложение падало. Отказа человеку здесь
            // нет — он просил закрыть, том закрыт, править нечего кроме записи.
            set_state_then_read(path, label, VaultState::Closed).await
        }
        CloseDecision::Foreign(uid) => OpOutcome::Failed(format!(
            "файл подключён другим пользователем (uid {uid}) — закрывать его отсюда нельзя, \
             второе подключение испортило бы данные"
        )),
        CloseDecision::Close(loop_object) => {
            match lifecycle::close_file_vault(&ud, &loop_object, label, home, false, scheduler)
                .await
            {
                Ok(()) => set_state_then_read(path, label, VaultState::Closed).await,
                Err(e) => OpOutcome::Failed(error_text(&e)),
            }
        }
    }
}

/// Текст ветки (а) отказа закрытия внутри удаления: том фактически ещё
/// открыт (занят чужими программами) — удаление прервано, запись и след целы.
fn delete_still_open_text() -> String {
    "закройте программы, работающие с хранилищем, затем закройте его и повторите удаление"
        .to_owned()
}

/// Текст ветки (б): повторная проба показала, что том фактически закрыт
/// (`AlreadyDetached`), — значит отказал шаг ПОСЛЕ закрытия. Честно называем
/// препятствие при повторе (добавка раунда 3): `~/panzir-<метка>` занят
/// чужим путём, симлинк снять нельзя.
fn delete_closed_but_failed_text(label: &Label) -> String {
    format!(
        "закрытие прошло, повторите удаление; если повтор не проходит — ~/panzir-{label} мешает"
    )
}

/// Файл подключён другим пользователем: не трогаем ни при первой пробе, ни
/// при повторной (инвариант 3 — второй loop на тот же файл портит данные).
fn delete_foreign_text(uid: u32) -> String {
    format!(
        "файл подключён другим пользователем (uid {uid}) — удаление отменено: \
         закрывать его отсюда нельзя, второе подключение испортило бы данные"
    )
}

/// Удаление записи (спека П-1/П-2). Порядок жёсткий: **проверка фразы
/// (ничего не меняет) → закрытие тома (если открыт) → уборка SSH-следа
/// (симлинк → сниппет → строка `Include`) → удаление записи из реестра**.
/// Каждый шаг видит успех предыдущего; при отказе запись и всё, что правится
/// позже отказавшего шага, не трогаются. Файл контейнера остаётся на диске.
async fn run_delete(
    path: &std::path::Path,
    home: &std::path::Path,
    ssh_config: &std::path::Path,
    scheduler: &SystemdUser,
    label: &Label,
    container: Option<PathBuf>,
    passphrase: Option<SecretString>,
) -> OpOutcome {
    // Гонка «файл исчез между баннером и кнопкой» (гриль 6): проверять фразу
    // и закрывать том не по чему — удаление идёт сиротской веткой; записи
    // и следу файл не нужен.
    let container = match container {
        Some(c) => match tokio::fs::try_exists(&c).await {
            Ok(true) => Some(c),
            Ok(false) => None,
            Err(e) => return OpOutcome::Failed(error_text(&Error::Io(e))),
        },
        None => None,
    };

    if let Some(container) = &container {
        // Файл на месте, а фразы нет — окно такую комбинацию не строит;
        // молча пропустить проверку владения нельзя (защита, а не удобство).
        let Some(passphrase) = passphrase else {
            return OpOutcome::Failed(format!(
                "файл хранилища «{label}» на месте, а парольная фраза не передана — \
                 ничего не удалено"
            ));
        };
        // Шаг 0: проверка фразы ничего не меняет — неверная фраза оставляет
        // мир нетронутым. `verify_passphrase` отвечает `Error::Command` и на
        // чужую фразу, и на сбой cryptsetup: сырой текст человеку не
        // показываем, любой провал проверки — «фраза не подошла» (спека,
        // МИНОР-3 раунда 2).
        if keyslot::verify_passphrase(container, &Passphrase::new(passphrase))
            .await
            .is_err()
        {
            return OpOutcome::Failed(
                "парольная фраза не подошла — запись, файлы и SSH-связка не тронуты".to_owned(),
            );
        }

        // «Открыт ли том» читаем из реестра — тем же состоянием рисовался
        // баннер, который человек подтвердил. Том, открытый мимо приложения
        // после последней перечитки, остаётся открытым: запись и след снять
        // можно, данные не пострадают (контейнер не трогаем никогда).
        let state = match Registry::load_from(path).await {
            Ok(reg) => reg
                .entries()
                .iter()
                .find(|e| e.label() == label)
                .map(|e| e.state().clone()),
            Err(e) => return OpOutcome::Failed(error_text(&e)),
        };
        let Some(state) = state else {
            return OpOutcome::Failed(error_text(&Error::VaultNotFound(label.as_str().to_owned())));
        };
        if matches!(state, VaultState::Open { .. }) {
            let ud = match Udisks::connect().await {
                Ok(ud) => ud,
                Err(e) => return OpOutcome::Failed(error_text(&e)),
            };
            // Проба → решение → действие — как `run_close`.
            let probe = match lifecycle::probe_file_vault(&ud, container).await {
                Ok(p) => p,
                Err(e) => return OpOutcome::Failed(error_text(&e)),
            };
            match close_decision(probe) {
                // Реестр сказал «открыто», факт — закрыт: закрывать нечего.
                CloseDecision::AlreadyDetached => {}
                CloseDecision::Foreign(uid) => {
                    return OpOutcome::Failed(delete_foreign_text(uid));
                }
                CloseDecision::Close(loop_object) => {
                    if let Err(e) = lifecycle::close_file_vault(
                        &ud,
                        &loop_object,
                        label,
                        home,
                        false,
                        scheduler,
                    )
                    .await
                    {
                        // Раунд 2 (БЛОКЕР): текст по СТАДИИ отказа, не по
                        // варианту ошибки — `UnexpectedUdisksState` при
                        // `detach_loop=false` означает два противоположных
                        // состояния. Повторная проба различает их.
                        let after = lifecycle::probe_file_vault(&ud, container)
                            .await
                            .ok()
                            .map(close_decision);
                        return OpOutcome::Failed(match after {
                            Some(CloseDecision::AlreadyDetached) => {
                                delete_closed_but_failed_text(label)
                            }
                            Some(CloseDecision::Close(_)) => delete_still_open_text(),
                            Some(CloseDecision::Foreign(uid)) => delete_foreign_text(uid),
                            // Повторная проба тоже отказала — честнее исходный
                            // отказ закрытия, чем выдуманное состояние.
                            None => error_text(&e),
                        });
                    }
                }
            }
        }
    }

    // Шаг «след»: симлинк → сниппет → строка (НИТ-4 раунда 2). Открытый том
    // снял симлинк внутри `close_file_vault`; здесь — lingering-симлинк при
    // уже закрытом томе (no-op при отсутствии).
    if let Err(e) = panzir_core::mountpoint::remove_symlink(home, label).await {
        return OpOutcome::Failed(error_text(&e));
    }
    let config_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let snippet = ssh::snippet_path(config_dir, label);
    if let Err(e) = ssh::remove_trace(ssh_config, &snippet).await {
        return OpOutcome::Failed(error_text(&Error::from(e)));
    }

    // Шаг «запись» — последним: `Registry::remove` трёт только запись,
    // контейнер остаётся на диске (решение Капитана, названо в баннере).
    let label = label.clone();
    write_then_read(path, move |r| r.remove(&label)).await
}

/// Как назвать человеку отведённое время. Секунды — для продукта,
/// «отведённое время» — для тестовых миллисекунд, где число бессмысленно.
fn timeout_text(limit: Duration) -> String {
    if limit.as_secs() >= 1 {
        format!("за {} с", limit.as_secs())
    } else {
        "за отведённое время".to_owned()
    }
}

/// Привести состояние записи к правде и вернуть свежий список.
async fn set_state_then_read(
    path: &std::path::Path,
    label: &Label,
    state: VaultState,
) -> OpOutcome {
    let label = label.clone();
    write_then_read(path, move |r| {
        let Some(entry) = r
            .entries_mut()
            .iter_mut()
            .find(|e| e.label().as_str() == label.as_str())
        else {
            // Запись исчезла между кликом и завершением — не наша ошибка и не
            // повод для отказа: том всё равно закрыт.
            return Ok(());
        };
        if entry.state() == &state {
            return Ok(());
        }
        entry.set_state(state)
    })
    .await
}

/// Правка и чтение результата — под одним локом, одним вызовом.
async fn write_then_read<F>(path: &std::path::Path, edit: F) -> OpOutcome
where
    F: FnOnce(&mut Registry) -> panzir_core::Result<()> + Send,
{
    let result = Registry::with_write_lock_at(path, |r| {
        edit(r)?;
        Ok(r.entries().to_vec())
    })
    .await;
    match result {
        Ok(entries) => OpOutcome::Loaded(entries),
        Err(e) => OpOutcome::Failed(error_text(&e)),
    }
}

#[cfg(test)]
// expect/unwrap в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
#[expect(
    clippy::expect_used,
    reason = "тесты: unwrap не используется, только expect с текстом"
)]
mod tests {
    include!("redesign_tests.rs");
    use std::path::Path;

    use egui_kittest::Harness;
    use egui_kittest::kittest::{NodeT as _, Queryable};
    use panzir_core::vault::VaultState;

    use super::*;

    // ---------- Разбор argv и строка исхода (круг починки 2026-08-28) ----------

    fn os(text: &str) -> std::ffi::OsString {
        std::ffi::OsString::from(text)
    }

    #[test]
    fn argv_without_arguments_is_window() {
        assert_eq!(close_label_from(&[os("panzir-gui")]), CloseRequest::Window);
    }

    #[test]
    fn close_with_valid_label_is_close() {
        assert_eq!(
            close_label_from(&[os("panzir-gui"), os("--close"), os("t27")]),
            CloseRequest::Close(Label::new("t27").expect("label"))
        );
    }

    #[test]
    fn close_without_label_is_usage_missing_label() {
        assert_eq!(
            close_label_from(&[os("panzir-gui"), os("--close")]),
            CloseRequest::Usage(UsageReason::MissingLabel)
        );
    }

    #[test]
    fn unknown_flag_is_usage_unknown_argument() {
        assert_eq!(
            close_label_from(&[os("panzir-gui"), os("--version")]),
            CloseRequest::Usage(UsageReason::UnknownArgument(os("--version")))
        );
        // Опечатка в имени режима — тот же класс: упасть громко, а не молча
        // открыть окно (ровно чинимый дефект).
        assert_eq!(
            close_label_from(&[os("panzir-gui"), os("--clse"), os("t27")]),
            CloseRequest::Usage(UsageReason::UnknownArgument(os("--clse")))
        );
    }

    #[test]
    fn invalid_label_is_usage_invalid_label() {
        assert_eq!(
            close_label_from(&[os("panzir-gui"), os("--close"), os("Bad_Label!!")]),
            CloseRequest::Usage(UsageReason::InvalidLabel("Bad_Label!!".to_owned()))
        );
    }

    #[test]
    fn extra_argument_after_label_is_usage() {
        assert_eq!(
            close_label_from(&[os("panzir-gui"), os("--close"), os("t27"), os("extra")]),
            CloseRequest::Usage(UsageReason::UnknownArgument(os("extra")))
        );
    }

    #[test]
    fn non_utf8_argument_is_usage() {
        use std::os::unix::ffi::OsStrExt as _;
        let bad = std::ffi::OsStr::from_bytes(&[0x2d, 0x80]); // "-" + broken byte
        assert!(matches!(
            close_label_from(&[os("panzir-gui"), bad.to_os_string()]),
            CloseRequest::Usage(UsageReason::UnknownArgument(_))
        ));
        assert!(matches!(
            close_label_from(&[os("panzir-gui"), os("--close"), bad.to_os_string()]),
            CloseRequest::Usage(UsageReason::InvalidLabel(_))
        ));
    }

    #[test]
    fn usage_reasons_read_differently() {
        let texts = [
            usage_reason_text(&UsageReason::UnknownArgument(os("--version"))),
            usage_reason_text(&UsageReason::MissingLabel),
            usage_reason_text(&UsageReason::InvalidLabel("x!!".to_owned())),
        ];
        for (i, a) in texts.iter().enumerate() {
            for (j, b) in texts.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "причины {i} и {j} обязаны различаться");
                }
            }
        }
    }

    #[test]
    fn close_outcomes_read_differently() {
        let label = Label::new("t27").expect("label");
        let lines = [
            outcome_line(&label, &lifecycle::CloseOutcome::Closed),
            outcome_line(&label, &lifecycle::CloseOutcome::AlreadyClosed),
            outcome_line(&label, &lifecycle::CloseOutcome::Deferred { attempt: 1 }),
        ];
        for (i, a) in lines.iter().enumerate() {
            for (j, b) in lines.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "исходы {i} и {j} обязаны читаться по-разному");
                }
            }
        }
        // «Не закрыл» не должен выглядеть как «закрыл» рядом с успешным юнитом.
        assert!(
            lines[2].contains("deferred"),
            "deferred says so: {}",
            lines[2]
        );
        assert!(!lines[2].contains(": closed"), "не «closed»: {}", lines[2]);
    }

    // ---------- Ю-2: разбор PANZIR_SMOKE_FRAMES ----------

    #[test]
    fn smoke_frames_absent_or_unparsable_means_normal_mode() {
        assert_eq!(smoke_frames_from(None), None, "переменной нет");
        assert_eq!(smoke_frames_from(Some("")), None, "пустая строка");
        assert_eq!(smoke_frames_from(Some("   ")), None, "одни пробелы");
        assert_eq!(smoke_frames_from(Some("abc")), None, "не число");
        assert_eq!(smoke_frames_from(Some("-1")), None, "отрицательное");
    }

    #[test]
    fn smoke_frames_zero_does_not_enable_smoke_mode() {
        // Ноль закрыл бы окно до первого кадра, и джоба стала бы зелёной,
        // не проверив ничего — ровно та болезнь, против которой тест написан.
        assert_eq!(smoke_frames_from(Some("0")), None);
    }

    #[test]
    fn smoke_frames_positive_number_enables_smoke_mode() {
        assert_eq!(smoke_frames_from(Some("3")), Some(3));
        assert_eq!(smoke_frames_from(Some(" 3 ")), Some(3));
    }

    // ---------- Ю-1: перевод отказов ядра ----------

    /// По одному значению на каждый вариант `Error`.
    ///
    /// Список ручной, и сам он новый вариант не ловит: `vec!` сборку не
    /// сломает. Настоящая защита — exhaustive `match` без ветки `_` внутри
    /// [`error_text`]: там новый вариант ядра обязателен к разбору, иначе крейт
    /// не компилируется. Этот список проверяет качество перевода, а не полноту.
    fn every_error_variant() -> Vec<Error> {
        vec![
            Error::Io(std::io::Error::other("проба")),
            Error::MissingDependency {
                name: "udisks2",
                hint: "поставьте udisks2".to_owned(),
            },
            Error::InvalidLabel("ЗАГЛАВНЫЕ".to_owned()),
            Error::InvalidContainerPath("/нет/родителя".to_owned()),
            Error::InvalidState {
                from: "closed",
                to: "closed",
            },
            Error::Command {
                cmd: "cryptsetup".to_owned(),
                status: "1".to_owned(),
            },
            Error::UnexpectedUdisksState("объект пропал".to_owned()),
            Error::Registry("битый toml".to_owned()),
            Error::NotAuthorized {
                reason: AuthRefusal::Denied,
            },
            Error::NotAuthorized {
                reason: AuthRefusal::NeedsConfirmation,
            },
            Error::NotAuthorized {
                reason: AuthRefusal::Dismissed,
            },
            Error::NoHome,
            Error::AlreadyRunning,
            Error::VaultNotFound("t-alpha".to_owned()),
            Error::DuplicateLabel("t-beta".to_owned()),
            Error::ContainerMissing {
                path: "/tmp/x.vault".to_owned(),
            },
            Error::VaultAlreadyAttached {
                path: "/tmp/x.vault".to_owned(),
                uid: 1000,
            },
            Error::VolumeLocked {
                object: "/org/freedesktop/UDisks2/block_devices/loop0".to_owned(),
            },
            Error::MultipleLoopsAttached {
                path: "/tmp/x.vault".to_owned(),
                count: 2,
            },
            Error::Ssh(SshError::InvalidField {
                field: "host",
                value: "Bad Host".to_owned(),
            }),
            Error::Ssh(SshError::Io(std::io::Error::other("проба"))),
            Error::Ssh(SshError::Query {
                host: "devbox".to_owned(),
                status: "exit status: 255".to_owned(),
            }),
            Error::Ssh(SshError::QueryTimeout {
                host: "devbox".to_owned(),
            }),
        ]
    }

    #[test]
    fn every_error_gets_human_text_that_is_not_the_raw_display() {
        for err in every_error_variant() {
            let text = error_text(&err);
            assert!(!text.trim().is_empty(), "пустой перевод для {err:?}");
            assert_ne!(
                text,
                err.to_string(),
                "человеку показывается сырой Display для {err:?}"
            );
        }
    }

    #[test]
    fn already_running_is_explained_in_plain_words() {
        let text = error_text(&Error::AlreadyRunning);
        assert!(
            text.contains("занят другой операцией"),
            "текст не объясняет причину: {text}"
        );
        assert_ne!(text, Error::AlreadyRunning.to_string());
    }

    /// Круг H: текст называет только то, что вариант ошибки действительно несёт.
    /// `Io` рождается и в трубе к cryptsetup (`passphrase.rs`), не только «на
    /// диске»; `Registry` — и при записи (`registry.rs`), не только при чтении.
    #[test]
    fn io_and_registry_texts_do_not_claim_a_cause_they_cannot_know() {
        let io = error_text(&Error::Io(std::io::Error::other("проба")));
        assert!(
            !io.contains("диск"),
            "Io рождается и в трубе к cryptsetup, «диск» — не причина: {io}"
        );
        let reg = error_text(&Error::Registry("проба".to_owned()));
        assert!(
            reg.contains("сохранить"),
            "Registry рождается и при записи, «прочитать» — не вся правда: {reg}"
        );
    }

    /// Круг H: отказ polkit — не сбой службы. Три оттенка — три разных текста;
    /// ни один не говорит «не отвечает» и не называет агента: имя ошибки не
    /// различает «агента нет» и «вызов сам запретил диалог».
    #[test]
    fn polkit_refusal_texts_name_only_what_the_variant_carries() {
        let texts: Vec<String> = [
            AuthRefusal::Denied,
            AuthRefusal::NeedsConfirmation,
            AuthRefusal::Dismissed,
        ]
        .into_iter()
        .map(|reason| error_text(&Error::NotAuthorized { reason }))
        .collect();
        for text in &texts {
            assert!(
                !text.contains("не отвечает"),
                "отказ в правах выдан за сбой службы: {text}"
            );
            assert!(
                !text.contains("агент"),
                "текст называет причину, которой имя ошибки не несёт: {text}"
            );
        }
        assert_ne!(
            texts[0], texts[1],
            "«нельзя» и «нужно подтверждение» слились"
        );
        assert_ne!(
            texts[1], texts[2],
            "«нужно подтверждение» и «отменено» слились"
        );
        assert_ne!(texts[0], texts[2], "«нельзя» и «отменено» слились");
    }

    // ---------- Т-13а: окно поверх kittest ----------

    /// Фикстура: реестр с двумя записями и **файл-пустышка** по пути `t-alpha`.
    /// Без файла проверка «удаление не тронуло данные» была бы красной всегда,
    /// независимо от поведения кода.
    fn fixture(dir: &Path) -> std::path::PathBuf {
        let registry = dir.join("vaults.toml");
        let container = dir.join("t-alpha.vault");
        std::fs::write(&container, b"").expect("создать файл-пустышку");

        let rt = Runtime::new().expect("рантайм для фикстуры");
        rt.block_on(Registry::with_write_lock_at(&registry, |r| {
            r.add(VaultEntry::new(
                Label::new("t-alpha").expect("метка"),
                VaultKind::File(container.clone()),
                VaultState::Closed,
            ))?;
            r.add(VaultEntry::new(
                Label::new("t-beta").expect("метка"),
                VaultKind::Device {
                    uuid: "1111-2222".to_owned(),
                },
                VaultState::Disconnected,
            ))?;
            Ok(())
        }))
        .expect("записать фикстуру");
        registry
    }

    /// Раскрыть карточку первой записи и открыть поле ввода фразы.
    fn start_typing_passphrase(harness: &mut Harness<'static, App>) {
        harness.get_by_label("Подробнее t-alpha").click();
        harness.run();
        harness.get_by_label("Открыть хранилище t-alpha").click();
        harness.run();
    }

    /// Единственное обещание, которое мы дали про секрет, — участок от клавиши
    /// до `SecretString`. Буфер виджета обязан опустеть при отправке, и это
    /// проверяется, а не декларируется.
    #[test]
    fn passphrase_buffer_is_emptied_on_submit() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        start_typing_passphrase(&mut harness);

        harness
            .state_mut()
            .unlock
            .as_mut()
            .expect("черновик ввода")
            .text = "фраза-которая-не-должна-остаться".to_owned();
        harness.get_by_label("Открыть с паролем t-alpha").click();
        harness.run();

        assert!(
            harness.state().unlock.is_none(),
            "фраза осталась в состоянии виджета после отправки"
        );
    }

    /// Пока операция идёт, действия карточки недоступны: иначе двойной клик
    /// отправит две правки, а человек не поймёт, какая из них победила.
    ///
    /// Занятость наводится задачей, которая **не завершается никогда**, — это
    /// детерминированно, в отличие от настоящей операции, чей срок зависит от
    /// загрузки машины.
    #[test]
    fn card_actions_are_disabled_while_an_operation_runs() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        harness.get_by_label("Подробнее t-alpha").click();
        harness.run();
        assert!(
            !harness
                .get_by_label("Открыть хранилище t-alpha")
                .accesskit_node()
                .is_disabled(),
            "до опыта кнопка уже неактивна — проверка ничего не докажет"
        );

        let ctx = harness.ctx.clone();
        let never = harness
            .state()
            .spawn_waking(&ctx, std::future::pending::<OpOutcome>());
        harness.state_mut().pending = Some(never);
        harness.run();

        assert!(
            harness
                .get_by_label("Открыть хранилище t-alpha")
                .accesskit_node()
                .is_disabled(),
            "во время операции действие карточки осталось доступным"
        );
    }

    /// Начатый и брошенный ввод не остаётся в памяти: свернули карточку —
    /// черновик снят.
    ///
    /// # Что этот тест доказывает, а что нет
    /// Доказывает, что черновик **снят** при уходе с карточки. Что его буфер
    /// при этом **затёрт**, тест доказать не может: содержимое освобождённой
    /// памяти из безопасного Rust не прочитать, а `unsafe_code = "forbid"`
    /// не пустит попытку. Затирание держится вызовом `zeroize` в
    /// [`App::forget_stale_passphrase`] и читается глазами на ревью.
    #[test]
    fn an_abandoned_passphrase_does_not_survive_leaving_the_card() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        start_typing_passphrase(&mut harness);

        harness
            .state_mut()
            .unlock
            .as_mut()
            .expect("черновик ввода")
            .text = "начал-и-передумал".to_owned();
        harness.run();
        assert!(
            harness.state().unlock.is_some(),
            "черновика нет до опыта — проверять нечего"
        );

        harness.get_by_label("Свернуть t-alpha").click();
        harness.run();

        assert!(
            harness.state().unlock.is_none(),
            "брошенный ввод пережил уход с карточки"
        );
    }

    /// Открыть экран создания (кнопка на списке).
    fn start_create(harness: &mut Harness<'static, App>) {
        harness.get_by_label("Создать хранилище").click();
        harness.run();
    }

    /// Заполнить черновик создания валидными значениями.
    fn fill_valid_create(harness: &mut Harness<'static, App>) {
        let d = harness
            .state_mut()
            .create
            .as_mut()
            .expect("черновик создания");
        d.label = "work".to_owned();
        d.size = "64".to_owned();
        d.passphrase = "secret".to_owned();
        d.confirm = "secret".to_owned();
    }

    #[test]
    fn create_screen_shows_the_form() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        start_create(&mut harness);
        for field in [
            "Название",
            "Размер, МиБ",
            "Пароль хранилища",
            "Повторите пароль",
        ] {
            assert!(
                harness.query_by_label(field).is_some(),
                "на форме создания нет поля {field}"
            );
        }
        assert!(
            harness.query_by_label("Создать хранилище").is_some(),
            "нет кнопки «Создать»"
        );
        assert!(
            harness.query_by_label("Отмена").is_some(),
            "нет кнопки «Отмена»"
        );
    }

    #[test]
    fn mismatched_passwords_disable_create() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        start_create(&mut harness);
        fill_valid_create(&mut harness);
        harness
            .state_mut()
            .create
            .as_mut()
            .expect("черновик")
            .confirm = "typo".to_owned();
        harness.run();
        assert!(
            harness
                .get_by_label("Создать хранилище")
                .accesskit_node()
                .is_disabled(),
            "«Создать» активна при несовпадающих паролях"
        );
        // Контроль: пароли совпали — кнопка активна.
        harness
            .state_mut()
            .create
            .as_mut()
            .expect("черновик")
            .confirm = "secret".to_owned();
        harness.run();
        assert!(
            !harness
                .get_by_label("Создать хранилище")
                .accesskit_node()
                .is_disabled(),
            "«Создать» неактивна при совпадающих валидных полях"
        );
    }

    #[test]
    fn create_is_disabled_while_an_operation_runs() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        start_create(&mut harness);
        fill_valid_create(&mut harness);
        harness.run();
        assert!(
            !harness
                .get_by_label("Создать хранилище")
                .accesskit_node()
                .is_disabled(),
            "до опыта кнопка уже неактивна — проверка ничего не докажет"
        );
        // Занятость наводится незавершающейся задачей (как card_actions-тест).
        let ctx = harness.ctx.clone();
        let never = harness
            .state()
            .spawn_waking(&ctx, std::future::pending::<OpOutcome>());
        harness.state_mut().pending = Some(never);
        harness.run();
        assert!(
            harness
                .get_by_label("Создать хранилище")
                .accesskit_node()
                .is_disabled(),
            "«Создать» осталась активной во время операции"
        );
    }

    #[test]
    fn cancelling_create_forgets_the_passphrase() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        start_create(&mut harness);
        harness
            .state_mut()
            .create
            .as_mut()
            .expect("черновик")
            .passphrase = "не-должно-остаться".to_owned();
        harness.run();
        assert!(
            harness.state().create.is_some(),
            "черновика нет до опыта — проверять нечего"
        );
        harness.get_by_label("Отмена").click();
        harness.run();
        assert!(
            harness.state().create.is_none(),
            "черновик создания пережил «Отмену» (секрет не затёрт)"
        );
    }

    #[test]
    fn create_screen_shows_a_kernel_message() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        start_create(&mut harness);
        harness.state_mut().message = Some("служба дисков вернула ошибку".to_owned());
        harness.run();
        assert!(
            harness
                .query_by_label_contains("служба дисков вернула ошибку")
                .is_some(),
            "отказ ядра не виден на экране создания (инвариант 10)"
        );
    }

    #[test]
    fn list_create_button_is_disabled_while_an_operation_runs() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        assert!(
            !harness
                .get_by_label("Создать хранилище")
                .accesskit_node()
                .is_disabled(),
            "до опыта кнопка уже неактивна — проверка ничего не докажет"
        );
        let ctx = harness.ctx.clone();
        let never = harness
            .state()
            .spawn_waking(&ctx, std::future::pending::<OpOutcome>());
        harness.state_mut().pending = Some(never);
        harness.run();
        assert!(
            harness
                .get_by_label("Создать хранилище")
                .accesskit_node()
                .is_disabled(),
            "«Создать хранилище» активна во время операции (гонка сообщения, инвариант 10)"
        );
    }

    #[test]
    fn submitting_a_valid_form_dispatches_create_and_wipes_the_passphrase() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        // op_timeout = 0: задача создания оборвётся по таймауту на первом poll
        // (`connect`), не тронув живой udisks2 — иначе тест реально создал бы том.
        harness.state_mut().op_timeout = Duration::ZERO;
        start_create(&mut harness);
        {
            let d = harness.state_mut().create.as_mut().expect("черновик");
            d.label = "fresh".to_owned(); // свободна: в fixture только t-alpha/t-beta
            d.size = "64".to_owned();
            d.passphrase = "test-passphrase".to_owned();
            d.confirm = "test-passphrase".to_owned();
        }
        let ctx = harness.ctx.clone();
        harness
            .state_mut()
            .handle_create(&ctx, CreateAction::Submit);

        assert!(
            harness.state().pending.is_some(),
            "Op::Create не отправлена"
        );
        assert_eq!(
            harness.state().screen,
            Screen::Create,
            "создание должно оставаться на форме до результата"
        );
        assert!(
            harness
                .state()
                .create
                .as_ref()
                .is_some_and(|d| d.passphrase.is_empty()),
            "пароль остался в черновике после Submit (секрет не забран)"
        );
        // Оборвать фоновую задачу: op_timeout=0 её и так завершает, udisks2 не ждём.
        if let Some(h) = harness.state_mut().pending.take() {
            h.abort();
        }
    }

    #[test]
    fn submitting_a_taken_label_is_rejected_before_creating() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        harness.state_mut().block_until_idle(); // реестр загружен: t-alpha, t-beta
        harness.run();
        harness.state_mut().op_timeout = Duration::ZERO;
        start_create(&mut harness);
        {
            let d = harness.state_mut().create.as_mut().expect("черновик");
            d.label = "t-beta".to_owned(); // занята записью-флешкой — триггер БЛОКЕРа 1
            d.size = "64".to_owned();
            d.passphrase = "x".to_owned();
            d.confirm = "x".to_owned();
        }
        let ctx = harness.ctx.clone();
        harness
            .state_mut()
            .handle_create(&ctx, CreateAction::Submit);
        assert!(
            harness.state().pending.is_none(),
            "создание запущено на занятой метке — пре-чек не сработал"
        );
        assert!(
            harness
                .state()
                .message
                .as_deref()
                .is_some_and(|m| m.contains("уже занято")),
            "нет сообщения о занятой метке"
        );
    }

    /// Обещание «формат — стандартный LUKS2» обязано быть видно на карточке
    /// ЛЮБОГО хранилища — и файлового, и на носителе. Ветки `File`/`Device`
    /// в `show_card` взаимоисключающие: строка, спрятанная в ветку `File`, не
    /// дошла бы до USB, а инвариант обещает это без разбора файл/флешка.
    ///
    /// Контроль канала на карточке носителя: пока её `match`-ветка («Носитель,
    /// UUID тома…») на экране, канал точно несёт карточку Device — иначе
    /// проверка «строка есть» была бы вакуумной (см. /testing §1).
    #[test]
    fn both_file_and_device_cards_show_the_standard_luks2_promise() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));

        // t-alpha (File) — первая запись: раскрываем её карточку.
        harness.get_by_label("Подробнее t-alpha").click();
        harness.run();
        assert!(
            harness.query_by_label_contains("Файл хранилища").is_some(),
            "раскрыта не файловая карточка — контроль канала пуст"
        );
        assert!(
            harness
                .query_by_label_contains("стандартный LUKS2")
                .is_some(),
            "файловая карточка не показала обещание про стандартный LUKS2"
        );

        // t-beta (Device): после раскрытия t-alpha единственный «Подробнее» — её.
        harness.get_by_label("Подробнее t-beta").click();
        harness.run();
        assert!(
            harness.query_by_label_contains("UUID тома").is_some(),
            "раскрыта не карточка носителя — контроль канала пуст"
        );
        assert!(
            harness
                .query_by_label_contains("стандартный LUKS2")
                .is_some(),
            "карточка носителя (USB) спрятала обещание про стандартный LUKS2"
        );
    }

    /// Отказ ядра не имеет права менять список: мы не знаем, что стало с томом,
    /// а показать выдуманное состояние хуже, чем оставить прежнее.
    #[test]
    fn a_failed_operation_leaves_the_list_untouched_and_says_why() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        let before: Vec<String> = harness
            .state()
            .entries
            .iter()
            .map(|e| format!("{}:{}", e.label().as_str(), state_text(e.state())))
            .collect();

        harness
            .state_mut()
            .apply(Ok(OpOutcome::Failed("фраза не подошла".to_owned())));
        harness.run();

        let after: Vec<String> = harness
            .state()
            .entries
            .iter()
            .map(|e| format!("{}:{}", e.label().as_str(), state_text(e.state())))
            .collect();
        assert_eq!(before, after, "отказ изменил список, хотя не имел права");
        harness.get_by_label_contains("фраза не подошла");
    }

    /// Таймаут: длительность приходит параметром (инвариант 9), иначе этот тест
    /// стоил бы минуты ожидания на каждом прогоне. Состояние записи после
    /// таймаута не меняется — мы не знаем, чем кончилась операция.
    #[test]
    fn a_timed_out_operation_says_so_and_leaves_the_record_alone() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        start_typing_passphrase(&mut harness);
        // Срок ужимается ЗДЕСЬ, а не при создании окна: таймаут накрывает и
        // первичную загрузку списка, и с нулём при старте записей просто не
        // появилось бы — тест падал бы на подготовке, а не на предмете
        // проверки. Ноль, а не «маленькое число»: миллисекунда соревнуется с
        // реальной операцией, и исход зависел бы от загрузки машины.
        harness.state_mut().op_timeout = Duration::ZERO;

        harness
            .state_mut()
            .unlock
            .as_mut()
            .expect("черновик ввода")
            .text = "любая".to_owned();
        harness.get_by_label("Открыть с паролем t-alpha").click();
        harness.run();
        harness.state_mut().block_until_idle();
        harness.run();

        harness.get_by_label_contains("не откликнулось");
        let alpha = harness
            .state()
            .entries
            .iter()
            .find(|e| e.label().as_str() == "t-alpha")
            .expect("запись на месте");
        assert_eq!(
            alpha.state(),
            &VaultState::Closed,
            "таймаут изменил состояние записи, хотя исход операции неизвестен"
        );
    }

    /// `Detached` — тихий и, вероятно, самый частый случай: том закрыли
    /// штатной утилитой дисков или приложение падало. Закрывать нечего, и
    /// звать `close_file_vault` было бы обращением к объекту, которого уже нет.
    ///
    /// Отведённое время называется человеку словами, а не миллисекундами.
    #[test]
    fn timeout_is_named_in_seconds_only_when_seconds_make_sense() {
        assert_eq!(timeout_text(Duration::from_secs(60)), "за 60 с");
        assert_eq!(
            timeout_text(Duration::from_millis(50)),
            "за отведённое время"
        );
    }

    /// Фикстура с ОТКРЫТЫМ хранилищем: отдельная от `fixture`, чтобы не
    /// трогать записи, на которые опираются тесты 3b.
    fn fixture_open(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let registry = dir.join("vaults.toml");
        let container = dir.join("t-open.vault");
        std::fs::write(&container, b"").expect("создать файл-пустышку");
        let mount = dir.join("mnt-t-open");
        std::fs::create_dir_all(&mount).expect("создать точку монтирования");

        let rt = Runtime::new().expect("рантайм для фикстуры");
        rt.block_on(Registry::with_write_lock_at(&registry, |r| {
            r.add(VaultEntry::new(
                Label::new("t-open").expect("метка"),
                VaultKind::File(container.clone()),
                VaultState::Open {
                    mount_point: mount.clone(),
                    until: None,
                },
            ))?;
            Ok(())
        }))
        .expect("записать фикстуру");
        (registry, mount)
    }

    /// Карточка обязана показывать ФАКТИЧЕСКУЮ точку монтирования, сообщённую
    /// udisks2 и сохранённую в записи, — а не угаданный путь симлинка.
    #[test]
    fn card_shows_the_real_mount_point_when_open() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let (registry, mount) = fixture_open(dir.path());
        let mut harness = harness_at(registry);

        harness.get_by_label_contains("Подробнее").click();
        harness.run();

        harness.get_by_label_contains(&mount.display().to_string());
    }

    fn harness_at(registry: std::path::PathBuf) -> Harness<'static, App> {
        harness_at_size(registry, [760.0, 1600.0])
    }

    fn harness_at_size(registry: std::path::PathBuf, size: [f32; 2]) -> Harness<'static, App> {
        let home = registry
            .parent()
            .expect("у фикстуры есть каталог")
            .to_path_buf();
        let ssh_config = home.join(".ssh").join("config");
        let mut harness = egui_kittest::HarnessBuilder::default()
            // Реактивное окно: завершение каждой фоновой задачи — отдельный
            // немедленный repaint (инвариант 8). Кадр после подтверждения
            // связки видит пачку: конец операции + конец переспроса статуса;
            // четырёх шагов по умолчанию на это не хватает. Это конечные
            // всплески, не вечный repaint: run() всё равно останавливается,
            // когда задачи кончились.
            .with_size(size)
            .with_max_steps(64)
            .build_eframe(move |cc| {
                App::new(
                    cc,
                    registry.clone(),
                    home.clone(),
                    ssh_config.clone(),
                    PathBuf::from("/bin/true"),
                    None,
                    Duration::from_secs(5),
                )
            });
        harness.state_mut().isolate_vault_io = true;
        harness.state_mut().block_until_idle();
        harness.run();
        harness
    }

    // ---------- Ш-7: добавление SSH-хоста с карточки ----------

    /// Раскрыть карточку первой записи и начать черновик добавления хоста.
    fn start_ssh_draft(harness: &mut Harness<'static, App>) {
        harness.get_by_label("Подробнее t-alpha").click();
        harness.run();
        harness.get_by_label("Добавить хост t-alpha").click();
        harness.run();
    }

    fn fill_ssh_draft(harness: &mut Harness<'static, App>, host: &str, port: &str) {
        let mut draft = harness
            .state_mut()
            .ssh_draft
            .take()
            .expect("черновик хоста");
        draft.host = host.to_owned();
        draft.hostname = "192.0.2.10".to_owned();
        draft.user = "devbox".to_owned();
        draft.port = port.to_owned();
        draft.key_file = "id_ed25519".to_owned();
        harness.state_mut().ssh_draft = Some(draft);
    }

    #[test]
    fn adding_ssh_host_writes_registry_and_snippet() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        start_ssh_draft(&mut harness);
        fill_ssh_draft(&mut harness, "devbox", "9281");
        harness
            .state_mut()
            .ssh_draft
            .as_mut()
            .expect("draft")
            .key_file = "ssh/id_ed25519".to_owned();

        harness.get_by_label("Сохранить хост").click();
        harness.run();
        harness.state_mut().block_until_idle();
        harness.run();

        // Правда — в реестре.
        let text = std::fs::read_to_string(dir.path().join("vaults.toml")).expect("registry");
        assert!(
            text.contains("[[vaults.ssh_hosts]]"),
            "host must be stored:\n{text}"
        );
        assert!(text.contains("port = 9281"), "port must be stored:\n{text}");
        // Сниппет — производная, записана рядом с реестром, 0600.
        let snippet = dir.path().join("ssh-t-alpha.conf");
        let content = std::fs::read_to_string(&snippet).expect("snippet written");
        assert!(content.contains("Host devbox\n"), "snippet:\n{content}");
        assert!(
            content.contains("IdentitiesOnly yes\n"),
            "snippet:\n{content}"
        );
        assert!(
            content.contains(&format!(
                "IdentityFile {}/panzir-t-alpha/ssh/id_ed25519\n",
                dir.path().display()
            )),
            "snippet:\n{content}"
        );
        // Карточка показывает добавленного хоста.
        harness.get_by_label_contains("devbox");
    }

    #[test]
    fn invalid_ssh_host_field_is_refused_with_message_and_draft_kept() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        start_ssh_draft(&mut harness);
        fill_ssh_draft(&mut harness, "Bad Host", "9281");

        harness.get_by_label("Сохранить хост").click();
        harness.run();

        harness.get_by_label_contains("не подходит");
        assert!(
            harness.state().ssh_draft.is_some(),
            "черновик обязан пережить отказ валидации — иначе набранное пропало молча"
        );
        // Реестр не тронут.
        let text = std::fs::read_to_string(dir.path().join("vaults.toml")).expect("registry");
        assert!(
            !text.contains("ssh_hosts"),
            "registry must stay clean:\n{text}"
        );
    }

    #[test]
    fn unparsable_ssh_port_is_refused_with_message() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        start_ssh_draft(&mut harness);
        fill_ssh_draft(&mut harness, "devbox", "не число");

        harness.get_by_label("Сохранить хост").click();
        harness.run();

        harness.get_by_label_contains("порт");
        assert!(harness.state().ssh_draft.is_some());
    }

    #[test]
    fn ssh_host_without_port_is_stored_without_port() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        start_ssh_draft(&mut harness);
        fill_ssh_draft(&mut harness, "devbox", "");

        harness.get_by_label("Сохранить хост").click();
        harness.run();
        harness.state_mut().block_until_idle();
        harness.run();

        let content =
            std::fs::read_to_string(dir.path().join("ssh-t-alpha.conf")).expect("snippet");
        assert!(
            !content.contains("Port"),
            "no Port line expected:\n{content}"
        );
    }

    // ---------- Ш-7, шаг 3: вставка Include по подтверждению ----------

    /// Фикстура: одна запись t-alpha (файл, закрыто) с SSH-хостом devbox.
    /// Возвращает пути реестра и config, который пойдёт в окно.
    fn fixture_ssh(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let registry = dir.join("vaults.toml");
        let container = dir.join("t-alpha.vault");
        std::fs::write(&container, b"").expect("создать файл-пустышку");

        let rt = Runtime::new().expect("рантайм для фикстуры");
        rt.block_on(Registry::with_write_lock_at(&registry, |r| {
            let mut e = VaultEntry::new(
                Label::new("t-alpha").expect("метка"),
                VaultKind::File(container.clone()),
                VaultState::Closed,
            );
            e.add_ssh_host(
                SshHost::new("devbox", "192.0.2.10", "devbox", None, "id_ed25519")
                    .expect("valid host"),
            );
            r.add(e)
        }))
        .expect("записать фикстуру");
        (registry, dir.join(".ssh").join("config"))
    }

    fn expand_first_card(harness: &mut Harness<'static, App>) {
        harness.get_by_label("Подробнее t-alpha").click();
        harness.run();
    }

    /// Кадр → дождаться фоновых задач → кадр.
    fn settle(harness: &mut Harness<'static, App>) {
        harness.run();
        harness.state_mut().block_until_idle();
        harness.run();
        harness.state_mut().block_until_idle();
        harness.run();
    }

    #[test]
    fn include_insertion_shows_exact_line_and_writes_only_after_confirm() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let (registry, config) = fixture_ssh(dir.path());
        std::fs::create_dir(config.parent().expect(".ssh")).expect("mkdir .ssh");
        std::fs::write(&config, "# мой конфиг\n").expect("чужой config");
        let mut harness = harness_at(registry);
        let line = format!("Include {}/ssh-t-alpha.conf", dir.path().display());

        expand_first_card(&mut harness);
        settle(&mut harness);

        harness.get_by_label("Включить SSH-связку t-alpha").click();
        harness.run();
        // Точная строка показана ДО записи — и записи без подтверждения нет.
        harness.get_by_label_contains(&line);
        assert_eq!(
            std::fs::read_to_string(&config).expect("config"),
            "# мой конфиг\n",
            "без подтверждения чужой config не трогаем"
        );

        harness.get_by_label("Подтвердить").click();
        settle(&mut harness);
        settle(&mut harness);

        assert_eq!(
            std::fs::read_to_string(&config).expect("config"),
            format!("{line}\n# мой конфиг\n")
        );
        harness.get_by_label_contains("связка включена");
    }

    #[test]
    fn shadowed_include_warns_and_repair_moves_line_first() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let (registry, config) = fixture_ssh(dir.path());
        std::fs::create_dir(config.parent().expect(".ssh")).expect("mkdir .ssh");
        let line = format!("Include {}/ssh-t-alpha.conf", dir.path().display());
        let foreign = "Host *\n    ServerAliveInterval 30\n";
        std::fs::write(&config, format!("{foreign}{line}\n")).expect("shadowed config");
        let mut harness = harness_at(registry);

        expand_first_card(&mut harness);
        settle(&mut harness);

        harness.get_by_label_contains("съехала");
        harness
            .get_by_label("Поднять строку первой t-alpha")
            .click();
        harness.run();
        harness.get_by_label_contains(&line);

        harness.get_by_label("Подтвердить").click();
        settle(&mut harness);

        assert_eq!(
            std::fs::read_to_string(&config).expect("config"),
            format!("{line}\n{foreign}"),
            "строка поднята первой, чужое содержимое байт-в-байт"
        );
    }

    #[test]
    fn foreign_host_with_same_name_shows_collision_warning() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let (registry, config) = fixture_ssh(dir.path());
        std::fs::create_dir(config.parent().expect(".ssh")).expect("mkdir .ssh");
        std::fs::write(&config, "Host devbox\n    HostName 203.0.113.9\n").expect("config");
        let mut harness = harness_at(registry);

        expand_first_card(&mut harness);
        settle(&mut harness);

        harness.get_by_label_contains("уже занято");
    }

    #[test]
    fn closed_vault_card_says_keys_unavailable() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let (registry, _config) = fixture_ssh(dir.path());
        let mut harness = harness_at(registry);

        expand_first_card(&mut harness);
        harness.run();

        harness.get_by_label_contains("ключи недоступны");
    }

    // ---------- Ш-7, шаг 4: резолюция ssh -G на карточке ----------

    /// Фикстура: запись t-alpha ОТКРЫТА (симуляция — без udisks), с хостом
    /// devbox. Проба с резолюцией в харнессе не бежит (звала бы настоящий
    /// ssh против настоящего config): статус подставляется в состояние
    /// напрямую, а механику `ssh -G` покрывают юниты разбора и Т-5.
    fn fixture_ssh_open(dir: &Path) -> std::path::PathBuf {
        let registry = dir.join("vaults.toml");
        let container = dir.join("t-alpha.vault");
        std::fs::write(&container, b"").expect("создать файл-пустышку");

        let rt = Runtime::new().expect("рантайм для фикстуры");
        rt.block_on(Registry::with_write_lock_at(&registry, |r| {
            let mut e = VaultEntry::new(
                Label::new("t-alpha").expect("метка"),
                VaultKind::File(container.clone()),
                VaultState::Closed,
            );
            e.add_ssh_host(
                SshHost::new("devbox", "192.0.2.10", "devbox", None, "id_ed25519")
                    .expect("valid host"),
            );
            e.set_state(VaultState::Open {
                mount_point: dir.join("mnt"),
                until: None,
            })
            .expect("closed -> open");
            r.add(e)
        }))
        .expect("записать фикстуру");
        registry
    }

    fn inject_ssh_status(harness: &mut Harness<'static, App>, resolutions: Vec<SshResolution>) {
        let key = harness.state().entries.first().map(|e| SshProbeKey {
            label: e.label().clone(),
            kind: e.kind().clone(),
            hosts: e.ssh_hosts().to_vec(),
            resolve: matches!(e.state(), VaultState::Open { .. }),
        });
        harness.state_mut().ssh_status_key = key;
        harness.state_mut().ssh_status = Some(SshCardStatus {
            label: Label::new("t-alpha").expect("метка"),
            include: IncludeStatus::Ok,
            collision: None,
            error: None,
            resolutions,
        });
    }

    #[test]
    fn open_vault_card_shows_confirmed_resolution() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture_ssh_open(dir.path()));
        inject_ssh_status(
            &mut harness,
            vec![SshResolution {
                host: "devbox".to_owned(),
                ok: true,
                detail: None,
            }],
        );

        expand_first_card(&mut harness);
        harness.run();

        harness.get_by_label_contains("devbox: ssh -G подтверждает связку");
        harness.get_by_label_contains("связка включена");
    }

    #[test]
    fn open_vault_card_warns_when_resolution_not_confirmed() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture_ssh_open(dir.path()));
        inject_ssh_status(
            &mut harness,
            vec![SshResolution {
                host: "devbox".to_owned(),
                ok: false,
                detail: None,
            }],
        );

        expand_first_card(&mut harness);
        harness.run();

        harness.get_by_label_contains("devbox: ssh -G не подтверждает связку");
    }

    #[test]
    fn open_vault_card_shows_ssh_g_failure_text() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture_ssh_open(dir.path()));
        inject_ssh_status(
            &mut harness,
            vec![SshResolution {
                host: "devbox".to_owned(),
                ok: false,
                detail: Some("ssh -G devbox timed out".to_owned()),
            }],
        );

        expand_first_card(&mut harness);
        harness.run();

        harness.get_by_label_contains("devbox: ssh -G devbox timed out");
    }

    #[test]
    fn list_shows_entries_from_the_registry() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let harness = harness_at(fixture(dir.path()));

        harness.get_by_label("t-alpha");
        harness.get_by_label("t-beta");
    }

    /// П-1: клик «Удалить из списка» сам по себе ничего не удаляет — открывает
    /// баннер «что будет удалено» с полем фразы (файл на месте). Запись в
    /// реестре и контейнер на диске нетронуты.
    ///
    /// Красная фаза (обязательна по спеке): на коде до П-1 клик удалял
    /// мгновенно — ни баннера, ни записи.
    #[test]
    fn delete_button_opens_a_banner_and_removes_nothing_by_itself() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let container = dir.path().join("t-alpha.vault");
        let mut harness = harness_at(fixture(dir.path()));
        assert!(container.exists(), "фикстура не создала файл — тест слеп");

        if harness
            .query_by_label("Удалить из списка t-alpha")
            .is_none()
        {
            harness.get_by_label("Подробнее t-alpha").click();
            harness.run();
        }
        harness.get_by_label("Удалить из списка t-alpha").click();
        harness.run();

        // Баннер с ратифицированным текстом и полем фразы.
        harness.get_by_label_contains("Будет удалено");
        harness.get_by_label_contains("парольную фразу хранилища");
        harness.get_by_label("Парольная фраза:");
        harness.get_by_label("Удалить");
        harness.get_by_label("Отмена");
        // Ничего не удалено: запись в реестре на месте, контейнер на диске.
        let text = std::fs::read_to_string(dir.path().join("vaults.toml")).expect("registry");
        assert!(text.contains("t-alpha"), "запись удалена кликом:\n{text}");
        assert!(
            container.exists(),
            "контейнер тронут кликом — это данные человека"
        );
    }

    // ---------- П-1/П-2: двухшаговое удаление ----------

    /// SSH-след записи t-alpha: сниппет рядом с реестром, строка `Include` в
    /// config с чужим содержимым ниже, симлинк `panzir-t-alpha` в «доме».
    const TRACE_FOREIGN: &str = "Host *\n    ServerAliveInterval 30\n";

    fn plant_ssh_trace(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let ssh_dir = dir.join(".ssh");
        std::fs::create_dir(&ssh_dir).expect("mkdir .ssh");
        let config = ssh_dir.join("config");
        let snippet = dir.join("ssh-t-alpha.conf");
        std::fs::write(&snippet, "Host devbox\n").expect("сниппет");
        std::fs::write(
            &config,
            format!("Include {}\n{TRACE_FOREIGN}", snippet.display()),
        )
        .expect("config");
        let symlink = dir.join("panzir-t-alpha");
        // Цель не создаётся: dangling-симлинк — штатное состояние закрытого
        // тома, `remove_symlink` смотрит на basename, а не на цель.
        std::os::unix::fs::symlink(dir.join("mnt-t-alpha"), &symlink).expect("симлинк");
        (config, snippet, symlink)
    }

    fn assert_trace_intact(dir: &Path) {
        let config = dir.join(".ssh").join("config");
        let text = std::fs::read_to_string(&config).expect("config");
        assert!(
            text.contains("Include"),
            "строка Include снята при отказе:\n{text}"
        );
        assert!(
            dir.join("ssh-t-alpha.conf").exists(),
            "сниппет снят при отказе"
        );
        assert!(
            std::fs::symlink_metadata(dir.join("panzir-t-alpha")).is_ok(),
            "симлинк снят при отказе"
        );
    }

    fn assert_trace_clean(dir: &Path) {
        let config = dir.join(".ssh").join("config");
        assert_eq!(
            std::fs::read_to_string(&config).expect("config"),
            TRACE_FOREIGN,
            "чужое содержимое обязано остаться байт-в-байт"
        );
        assert!(!dir.join("ssh-t-alpha.conf").exists(), "сниппет остался");
        assert!(
            std::fs::symlink_metadata(dir.join("panzir-t-alpha")).is_err(),
            "симлинк остался"
        );
    }

    /// Открыть баннер удаления первой записи (t-alpha).
    fn open_delete_banner(harness: &mut Harness<'static, App>) {
        if harness
            .query_by_label("Удалить из списка t-alpha")
            .is_none()
        {
            harness.get_by_label("Подробнее t-alpha").click();
            harness.run();
        }
        harness.get_by_label("Удалить из списка t-alpha").click();
        harness.run();
    }

    fn type_delete_passphrase(harness: &mut Harness<'static, App>, phrase: &str) {
        harness
            .state_mut()
            .delete
            .as_mut()
            .expect("черновик удаления")
            .passphrase = phrase.to_owned();
        harness.run();
    }

    /// Сирота (файла нет на месте): баннер сироты без поля фразы, «Удалить»
    /// снимает запись и SSH-след целиком; удалению файл не нужен (гриль 6).
    #[test]
    fn orphan_delete_needs_no_passphrase_and_cleans_the_trace() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let registry = fixture(dir.path());
        std::fs::remove_file(dir.path().join("t-alpha.vault")).expect("убрать контейнер");
        plant_ssh_trace(dir.path());
        let mut harness = harness_at(registry);

        open_delete_banner(&mut harness);
        harness.get_by_label_contains("Файла хранилища нет на месте");
        assert!(
            harness.query_by_label("Парольная фраза:").is_none(),
            "у сироты не должно быть поля фразы — проверять не по чему"
        );

        harness.get_by_label("Удалить").click();
        settle(&mut harness);

        assert!(
            harness.query_by_label_contains("t-alpha ·").is_none(),
            "запись сироты осталась в списке"
        );
        harness.get_by_label("t-beta");
        let text = std::fs::read_to_string(dir.path().join("vaults.toml")).expect("registry");
        assert!(
            !text.contains("t-alpha"),
            "запись осталась в реестре:\n{text}"
        );
        assert_trace_clean(dir.path());
    }

    /// Носитель — НЕ сирота (находка 1 ревью плана): отказ `refuse_device`,
    /// баннер не открывается, запись на месте. Иначе отключённая флешка
    /// проходила бы удалением записи без фразы.
    #[test]
    fn device_delete_is_refused_without_a_banner() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));

        if harness.query_by_label("Удалить из списка t-beta").is_none() {
            harness.get_by_label("Подробнее t-beta").click();
            harness.run();
        }
        harness.get_by_label("Удалить из списка t-beta").click();
        harness.run();

        harness.get_by_label_contains("Носители пока не поддерживаются");
        assert!(
            harness.query_by_label_contains("Будет удалено").is_none(),
            "баннер открылся на носителе"
        );
        assert!(
            harness.state().delete.is_none(),
            "черновик удаления завёлся на носителе"
        );
        let text = std::fs::read_to_string(dir.path().join("vaults.toml")).expect("registry");
        assert!(text.contains("t-beta"), "запись носителя удалена:\n{text}");
    }

    /// Неверная фраза: мир нетронут — запись, контейнер и след целы, текст
    /// «фраза не подошла» (проверка — шаг 0, ничего не меняет).
    #[test]
    fn wrong_passphrase_aborts_delete_and_leaves_everything_untouched() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let container = dir.path().join("t-alpha.vault");
        let mut harness = harness_at(fixture(dir.path()));
        plant_ssh_trace(dir.path());

        open_delete_banner(&mut harness);
        type_delete_passphrase(&mut harness, "не-та-фраза");
        harness.get_by_label("Удалить").click();
        settle(&mut harness);

        harness.get_by_label_contains("фраза не подошла");
        let text = std::fs::read_to_string(dir.path().join("vaults.toml")).expect("registry");
        assert!(
            text.contains("t-alpha"),
            "запись удалена при неверной фразе:\n{text}"
        );
        assert!(container.exists(), "контейнер тронут");
        assert_trace_intact(dir.path());
    }

    /// Отказ шага «след» (симлинк занят чужим путём — каталог, не наш
    /// симлинк) прерывает удаление ДО записи: запись и остальной след целы.
    /// Это и есть доказательство порядка «след → запись» без моков.
    #[test]
    fn trace_failure_aborts_before_removing_the_entry() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let registry = fixture(dir.path());
        std::fs::remove_file(dir.path().join("t-alpha.vault")).expect("убрать контейнер");
        plant_ssh_trace(dir.path());
        // Чужой путь на месте симлинка: обычный каталог — снимать его нельзя.
        std::fs::remove_file(dir.path().join("panzir-t-alpha")).expect("убрать симлинк фикстуры");
        std::fs::create_dir(dir.path().join("panzir-t-alpha")).expect("чужой каталог");
        let mut harness = harness_at(registry);

        open_delete_banner(&mut harness);
        harness.get_by_label("Удалить").click();
        settle(&mut harness);

        harness.get_by_label_contains("неожиданно");
        let text = std::fs::read_to_string(dir.path().join("vaults.toml")).expect("registry");
        assert!(
            text.contains("t-alpha"),
            "запись удалена при отказе следа:\n{text}"
        );
        // След не тронут: строка и сниппет на месте (шаг упал на симлинке).
        let config =
            std::fs::read_to_string(dir.path().join(".ssh").join("config")).expect("config");
        assert!(
            config.contains("Include"),
            "строка снята при отказе:\n{config}"
        );
        assert!(dir.path().join("ssh-t-alpha.conf").exists());
    }

    /// Набранная в баннере фраза не переживает отмену и уход с карточки
    /// (К-4, по образцу теста разблокировки app.rs:1858-1864). Доказывается
    /// СНЯТИЕ черновика; затирание буфера держится `zeroize` и читается
    /// глазами — содержимое освобождённой памяти безопасный Rust не читает.
    #[test]
    fn delete_passphrase_does_not_survive_cancel_or_collapse() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));

        // Отмена.
        open_delete_banner(&mut harness);
        type_delete_passphrase(&mut harness, "начал-и-передумал");
        harness.get_by_label("Отмена").click();
        harness.run();
        assert!(
            harness.state().delete.is_none(),
            "черновик пережил «Отмену» (секрет не затёрт)"
        );

        // Уход с карточки (свернули).
        open_delete_banner(&mut harness);
        type_delete_passphrase(&mut harness, "начал-и-передумал");
        assert!(
            harness.state().delete.is_some(),
            "черновика нет до опыта — проверять нечего"
        );
        harness.get_by_label("Свернуть t-alpha").click();
        harness.run();
        assert!(
            harness.state().delete.is_none(),
            "брошенная фраза пережила уход с карточки"
        );
    }

    /// Два исхода отказа закрытия — два различимых текста (спека, раунд 2):
    /// ветка (а) зовёт закрыть программы, ветка (б) — повторить удаление и
    /// называет препятствие при повторе (добавка раунда 3).
    #[test]
    fn delete_close_refusal_texts_read_differently() {
        let label = Label::new("t-alpha").expect("метка");
        let still_open = delete_still_open_text();
        let closed_but_failed = delete_closed_but_failed_text(&label);
        let foreign = delete_foreign_text(1001);
        assert_ne!(still_open, closed_but_failed);
        assert_ne!(still_open, foreign);
        assert_ne!(closed_but_failed, foreign);
        assert!(
            still_open.contains("закройте программы"),
            "ветка (а): {still_open}"
        );
        assert!(
            closed_but_failed.contains("повторите удаление"),
            "ветка (б): {closed_but_failed}"
        );
        assert!(
            closed_but_failed.contains("~/panzir-t-alpha"),
            "ветка (б) обязана назвать препятствие: {closed_but_failed}"
        );
        assert!(foreign.contains("uid 1001"), "чужой uid: {foreign}");
    }

    /// Регрессия (Гейт-2, раунд 4, МИНОР): повторный клик «Удалить из
    /// списка» при висевшем баннере обязан снять старый черновик С
    /// затиранием, а не дропнуть набранную фразу прямым присваиванием.
    /// Доказывается замена черновика (свежий — с пустым полем); затирание
    /// старого буфера держится `zeroize` в `AskDelete` и читается глазами —
    /// содержимое освобождённой памяти безопасный Rust не читает.
    #[test]
    fn reopening_the_delete_banner_replaces_the_draft() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));

        open_delete_banner(&mut harness);
        type_delete_passphrase(&mut harness, "набрано-но-не-отправлено");
        // Второй клик по той же кнопке при висевшем баннере.
        open_delete_banner(&mut harness);

        let draft = harness.state().delete.as_ref().expect("черновик удаления");
        assert!(
            draft.passphrase.is_empty(),
            "старая набранная фраза перешла в новый черновик"
        );
    }

    /// Skip-страж по образцу М-4 (ssh_it.rs): без `cryptsetup` в PATH
    /// полный путь пропускается — сьют не `#[ignore]`.
    fn cryptsetup_available() -> bool {
        std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|dir| dir.join("cryptsetup").is_file())
        })
    }

    /// Настоящий LUKS2-контейнер (не пустышка): `luksFormat` на обычном
    /// файле не требует ни root, ни udisks2 — только заголовок, а проверка
    /// фразы (`--test-passphrase`) читает ровно его.
    fn luks_format(container: &Path, passphrase: &str) {
        use std::io::Write as _;

        let file = std::fs::File::create(container).expect("создать контейнер");
        // LUKS2-заголовок ~16 МиБ; файл чуть больше, sparse.
        file.set_len(33 * 1024 * 1024).expect("размер контейнера");
        let mut child = std::process::Command::new("cryptsetup")
            .args([
                "luksFormat",
                "--type",
                "luks2",
                "--pbkdf",
                "pbkdf2",
                "--pbkdf-force-iterations",
                "1000",
                "--batch-mode",
                "--key-file",
                "-",
            ])
            .arg(container)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("запустить cryptsetup");
        // Фраза уходит через stdin, как в `Passphrase::write_to_stdin`:
        // без перевода строки, конец — EOF.
        let mut stdin = child.stdin.take().expect("stdin cryptsetup");
        stdin
            .write_all(passphrase.as_bytes())
            .expect("передать фразу");
        drop(stdin);
        let output = child.wait_with_output().expect("дождаться cryptsetup");
        assert!(
            output.status.success(),
            "luksFormat завершился с {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Полный путь (критерий приёмки 2): баннер → верная фраза → «Удалить»
    /// снимает запись и SSH-след — и не трогает контейнер. Фраза проверяется
    /// настоящим cryptsetup против настоящего LUKS2-контейнера; том в
    /// реестре закрыт, поэтому шаг закрытия не зовёт udisks2 и тесту не
    /// нужна живая шина.
    #[test]
    fn full_delete_path_with_the_right_passphrase_keeps_the_container() {
        if !cryptsetup_available() {
            eprintln!("skip: нет cryptsetup в PATH — полный путь удаления пропущен (М-4)");
            return;
        }
        let dir = tempfile::tempdir().expect("временный каталог");
        let container = dir.path().join("t-alpha.vault");
        luks_format(&container, "правильная фраза");
        let registry = dir.path().join("vaults.toml");
        let rt = Runtime::new().expect("рантайм для фикстуры");
        rt.block_on(Registry::with_write_lock_at(&registry, |r| {
            r.add(VaultEntry::new(
                Label::new("t-alpha").expect("метка"),
                VaultKind::File(container.clone()),
                VaultState::Closed,
            ))
        }))
        .expect("записать фикстуру");
        plant_ssh_trace(dir.path());
        let mut harness = harness_at(registry);

        open_delete_banner(&mut harness);
        harness.get_by_label_contains("Будет удалено");
        type_delete_passphrase(&mut harness, "правильная фраза");
        harness.get_by_label("Удалить").click();
        settle(&mut harness);

        assert!(
            harness.query_by_label("t-alpha").is_none(),
            "запись осталась в списке после полного пути"
        );
        let text = std::fs::read_to_string(dir.path().join("vaults.toml")).expect("registry");
        assert!(
            !text.contains("t-alpha"),
            "запись осталась в реестре:\n{text}"
        );
        assert!(
            container.exists(),
            "удаление записи стёрло файл контейнера — это данные человека"
        );
        assert_trace_clean(dir.path());
    }

    #[test]
    fn renaming_to_an_existing_label_is_rejected_with_a_readable_message() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));

        if harness.query_by_label("Переименовать t-alpha").is_none() {
            harness.get_by_label("Подробнее t-alpha").click();
            harness.run();
        }
        harness.get_by_label("Переименовать t-alpha").click();
        harness.run();

        harness.state_mut().rename.as_mut().expect("черновик").text = "t-beta".to_owned();
        harness.get_by_label("Сохранить").click();
        harness.run();
        harness.state_mut().block_until_idle();
        harness.run();

        harness.get_by_label_contains("уже занято");
        harness.get_by_label("t-alpha");
    }

    #[test]
    fn renaming_to_a_free_label_changes_the_entry() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));

        if harness.query_by_label("Переименовать t-alpha").is_none() {
            harness.get_by_label("Подробнее t-alpha").click();
            harness.run();
        }
        harness.get_by_label("Переименовать t-alpha").click();
        harness.run();

        harness.state_mut().rename.as_mut().expect("черновик").text = "t-gamma".to_owned();
        harness.get_by_label("Сохранить").click();
        harness.run();
        harness.state_mut().block_until_idle();
        harness.run();

        harness.get_by_label("t-gamma");
        harness.get_by_label("t-beta");
        assert!(
            harness.query_by_label("t-alpha").is_none(),
            "старая метка осталась в списке"
        );
        assert!(
            harness.state().rename.is_none(),
            "поле ввода не закрылось после успешного переименования"
        );
    }

    #[test]
    fn banner_names_a_broken_dependency_including_udisks2() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));

        // Состояние шины задаётся тестом: живой ответ здесь ничего не решает.
        harness.state_mut().udisks = Some(UdisksStatus::Missing(
            "поставьте и запустите udisks2".to_owned(),
        ));
        harness
            .state_mut()
            .local_deps
            .statuses
            .push(deps::DepStatus {
                name: "cryptsetup",
                ok: false,
                hint: "установите пакет cryptsetup".to_owned(),
            });
        harness.state_mut().rebuild_env();
        harness.run();

        harness.get_by_label_contains("udisks2");
        harness.get_by_label_contains("cryptsetup");
    }

    #[test]
    fn every_background_task_wakes_the_window() {
        // Четыре раза подряд в этом круге ломалось одно и то же: механизм не
        // отличал работающее состояние от зависшего, потому что никто не
        // спрашивал «кто дёрнет следующий кадр». Здесь это спрашивает тест.
        //
        // Проверяется сама дверь `spawn_waking`: что она будит окно.
        // Её ЕДИНСТВЕННОСТЬ этим тестом не доказывается — она держится тем, что
        // `pending` и `bus_probe` присваиваются только здесь, и проверяется
        // глазами на ревью, а не автоматически.
        let dir = tempfile::tempdir().expect("временный каталог");
        let harness = harness_at(fixture(dir.path()));
        let ctx = harness.ctx.clone();

        assert!(
            !ctx.has_requested_repaint(),
            "окно не в покое до опыта — проверка ничего не докажет"
        );

        let handle = harness.state().spawn_waking(&ctx, async { 42_u8 });
        let value = harness
            .state()
            .rt
            .block_on(handle)
            .expect("задача завершилась");

        assert_eq!(value, 42, "дверь потеряла результат задачи");
        assert!(
            ctx.has_requested_repaint(),
            "завершившаяся задача не разбудила окно: без этого после клика \
             окно стоит с неактивными кнопками до случайного движения мыши"
        );
    }

    #[test]
    fn lock_held_by_another_process_is_explained_to_the_person() {
        use std::io::BufRead as _;

        let dir = tempfile::tempdir().expect("временный каталог");
        let registry = fixture(dir.path());
        // П-1: удаление запускается кнопкой баннера, а не «Удалить из
        // списка». Сиротская ветка (файла нет) не спрашивает фразу — тесту
        // не нужен живой cryptsetup.
        std::fs::remove_file(dir.path().join("t-alpha.vault")).expect("убрать контейнер");
        let mut harness = harness_at(registry.clone());

        // Настоящий внешний держатель лока, а не подделка. Про готовность
        // узнаём по его строке, а не паузой: пауза была бы маскировкой гонки.
        let mut holder = std::process::Command::new("flock")
            .arg("-x")
            .arg(&registry)
            .arg("-c")
            .arg("echo held; sleep 30")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("запустить внешнего держателя лока");
        let mut line = String::new();
        std::io::BufReader::new(holder.stdout.as_mut().expect("stdout держателя"))
            .read_line(&mut line)
            .expect("дождаться, пока лок взят");
        assert_eq!(line.trim(), "held");

        if harness
            .query_by_label("Удалить из списка t-alpha")
            .is_none()
        {
            harness.get_by_label("Подробнее t-alpha").click();
            harness.run();
        }
        harness.get_by_label("Удалить из списка t-alpha").click();
        harness.run();
        // Баннер сироты: поля фразы нет, удаление — кнопкой «Удалить».
        harness.get_by_label_contains("Файла хранилища нет на месте");
        harness.get_by_label("Удалить").click();
        harness.run();
        harness.state_mut().block_until_idle();
        harness.run();

        harness.get_by_label_contains("занят другой операцией");
        // Запись осталась в списке: строка записи, а не упоминание в баннере.
        harness.get_by_label("t-alpha");

        holder.kill().expect("снять держателя лока");
        holder.wait().expect("дождаться держателя");
    }

    #[test]
    fn refused_operation_keeps_the_draft_and_says_why() {
        // Минор-1 раунда 6: клик «Сохранить» при занятой очереди уничтожал
        // черновик, а `spawn_op` молча возвращался — поле закрылось, имя
        // прежнее, сообщения нет.
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));
        let ctx = harness.ctx.clone();

        // Занимаем очередь задачей, которая сама не закончится.
        let busy = harness.state().spawn_waking(&ctx, async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            OpOutcome::Failed(String::new())
        });
        let old = Label::new("t-alpha").expect("метка");
        harness.state_mut().pending = Some(busy);
        harness.state_mut().rename = Some(RenameDraft {
            target: old.clone(),
            text: "t-gamma".to_owned(),
        });

        harness.state_mut().handle(
            &ctx,
            ListAction::CommitRename {
                old,
                new: "t-gamma".to_owned(),
            },
        );

        let state = harness.state();
        assert!(
            state.rename.is_some(),
            "черновик уничтожен, хотя операция не началась — набранное имя потеряно молча"
        );
        assert!(
            state
                .message
                .as_deref()
                .is_some_and(|m| m.contains("Подождите")),
            "отказ не объяснён человеку: {:?}",
            state.message
        );

        if let Some(handle) = harness.state_mut().pending.take() {
            handle.abort();
        }
    }

    #[test]
    fn unknown_bus_state_is_not_reported_as_missing() {
        // Минор-2 раунда 6: пока проба не вернулась, плашка сообщала о нехватке
        // того, что ещё проверяется.
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));

        harness.state_mut().udisks = None;
        harness.state_mut().local_deps.statuses = vec![deps::DepStatus {
            name: "cryptsetup",
            ok: true,
            hint: String::new(),
        }];
        harness.state_mut().rebuild_env();
        harness.run();

        assert!(
            harness.query_by_label_contains("udisks2").is_none(),
            "неизвестное состояние шины показано как нехватка"
        );
        assert!(
            harness
                .query_by_label("Чего не хватает в системе")
                .is_none(),
            "плашка тревожит на исправной машине"
        );
    }

    #[test]
    fn busy_message_names_holders_or_falls_back_gracefully() {
        let unknown: Vec<String> = vec![];
        let text = busy_message(&unknown);
        assert!(
            text.contains("использующие их программы"),
            "fallback must be general: {text}"
        );
        assert!(text.contains("„Закрыть“"));

        let one = vec!["vim".to_owned()];
        let text = busy_message(&one);
        assert!(
            text.contains("„vim“"),
            "single holder must be quoted: {text}"
        );
        assert!(text.contains("Закройте его файлы"));

        let many = vec!["vim".to_owned(), "bash".to_owned()];
        let text = busy_message(&many);
        assert!(
            text.contains("vim, bash"),
            "multiple holders must be listed: {text}"
        );
        assert!(text.contains("Закройте его файлы"));
    }

    #[test]
    fn empty_registry_shows_the_first_run_screen() {
        let dir = tempfile::tempdir().expect("временный каталог");
        // Файла реестра нет вовсе — ровно состояние первого запуска.
        let harness = harness_at(dir.path().join("vaults.toml"));

        harness.get_by_label("Хранилищ пока нет");
        assert!(
            harness.query_by_label("Удалить из списка").is_none(),
            "кнопки записей на пустом экране"
        );
    }
    #[test]
    fn redesign_primary_action_is_visible_without_details() {
        let dir = tempfile::tempdir().expect("fixture");
        let harness = harness_at(fixture(dir.path()));
        assert!(
            harness
                .query_by_label("Открыть хранилище t-alpha")
                .is_some(),
            "основное действие скрыто за Подробнее"
        );
    }

    #[test]
    fn redesign_reload_preserves_foreground_failure() {
        let dir = tempfile::tempdir().expect("fixture");
        let mut harness = harness_at(fixture(dir.path()));
        let entries = harness.state().entries.clone();
        harness
            .state_mut()
            .apply(Ok(OpOutcome::Failed("synthetic operation failure".into())));
        harness.state_mut().apply(Ok(OpOutcome::Loaded(entries)));
        assert_eq!(
            harness.state().notices.last().map(|n| n.text.as_str()),
            Some("synthetic operation failure"),
            "reload потерял отказ операции"
        );
    }
}
