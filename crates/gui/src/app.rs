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
use panzir_core::lifecycle::{self, VaultProbe};
use panzir_core::registry::{Registry, VaultEntry};
use panzir_core::udisks::{ObjPath, Udisks};
use panzir_core::vault::{Label, VaultKind, VaultState, container_path};
use panzir_core::{AuthRefusal, Error};
use secrecy::SecretString;
use secrecy::zeroize::Zeroize as _;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::view_create::{self, CreateAction, CreateDraft};
use crate::view_list::{self, ListAction, ListInput, RenameDraft, UnlockDraft};

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

/// Что окно просит у ядра. Все операции идут через одну дверь — [`App::spawn_op`].
#[derive(Debug)]
enum Op {
    /// Перечитать реестр.
    Reload,
    /// Убрать запись из реестра. Контейнер на диске не трогается.
    Remove(Label),
    /// Открыть хранилище набранной фразой.
    Open {
        /// Метка записи.
        label: Label,
        /// Путь к файлу-контейнеру.
        container: PathBuf,
        /// Секрет. Дальше окна в открытом виде не живёт: `SecretString`
        /// затирает себя при уничтожении.
        passphrase: SecretString,
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
}

/// Чем кончилась операция. Список приходит вместе с исходом: правка реестра и
/// чтение результата происходят под одним локом, вторым вызовом не разъезжаются.
#[derive(Debug)]
enum OpOutcome {
    /// Свежий список записей.
    Loaded(Vec<VaultEntry>),
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

/// Переводит отказ ядра на человеческий язык.
///
/// Match намеренно без ветки `_`: новый вариант в ядре обязан сломать сборку
/// здесь, а не молча приехать к человеку сырым `Display` из `thiserror`.
#[must_use]
pub fn error_text(err: &Error) -> String {
    match err {
        Error::AlreadyRunning => "panzir уже запущен — закройте второе окно и повторите".to_owned(),
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
    }
}

/// Короткое имя состояния записи для списка.
#[must_use]
pub fn state_text(state: &VaultState) -> &'static str {
    match state {
        VaultState::Closed => "закрыто",
        VaultState::Open { .. } => "открыто",
        VaultState::Disconnected => "отключено",
    }
}

/// Короткое имя типа хранилища для списка.
#[must_use]
pub fn kind_text(kind: &VaultKind) -> &'static str {
    match kind {
        VaultKind::File(_) => "файл",
        VaultKind::Device { .. } => "флешка",
    }
}

/// Какой экран показан. Отделён от черновика создания намеренно: черновик
/// живёт в `Option`, а `screen` говорит, показан ли он, — тогда «ушли с формы,
/// а черновик завис» становится ловимым состоянием (условие устаревания для
/// `forget_stale_passphrase`, как `expanded` для разблокировки).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Screen {
    /// Список хранилищ.
    List,
    /// Форма создания нового хранилища.
    Create,
}

/// Состояние главного окна.
pub struct App {
    rt: Runtime,
    registry_path: PathBuf,
    home: PathBuf,
    op_timeout: Duration,
    smoke_frames: Option<u32>,
    frames_drawn: u32,
    entries: Vec<VaultEntry>,
    env: Vec<EnvLine>,
    udisks: Option<UdisksStatus>,
    local_deps: DepsReport,
    pending: Option<JoinHandle<OpOutcome>>,
    bus_probe: Option<JoinHandle<UdisksStatus>>,
    message: Option<String>,
    rename: Option<RenameDraft>,
    expanded: Option<Label>,
    unlock: Option<UnlockDraft>,
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
        smoke_frames: Option<u32>,
        op_timeout: Duration,
    ) -> Self {
        let rt = Runtime::new().expect("не удалось создать рантайм tokio");
        let local_deps = deps::check_local_deps();
        let mut app = Self {
            rt,
            registry_path,
            home,
            op_timeout,
            smoke_frames,
            frames_drawn: 0,
            entries: Vec::new(),
            env: Vec::new(),
            udisks: None,
            local_deps,
            pending: None,
            bus_probe: None,
            message: None,
            rename: None,
            expanded: None,
            unlock: None,
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
        let path = self.registry_path.clone();
        let home = self.home.clone();
        let limit = self.op_timeout;
        self.pending = Some(self.spawn_waking(ctx, async move {
            // Таймаут накрывает операцию ЦЕЛИКОМ, включая пробу: человеку не
            // важно, на каком шаге застряло, ему важно, что окно не висит.
            match tokio::time::timeout(limit, run_op(&path, &home, op)).await {
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

    /// Снимает результаты завершившихся задач. Не блокирует.
    fn take_finished(&mut self) {
        if self.pending.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(handle) = self.pending.take()
        {
            let outcome = self.rt.block_on(handle);
            self.apply(outcome);
        }
        if self.bus_probe.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(handle) = self.bus_probe.take()
            && let Ok(status) = self.rt.block_on(handle)
        {
            self.udisks = Some(status);
            self.rebuild_env();
        }
    }

    fn apply(&mut self, outcome: Result<OpOutcome, tokio::task::JoinError>) {
        match outcome {
            Ok(OpOutcome::Loaded(entries)) => {
                self.entries = entries;
                self.message = None;
            }
            Ok(OpOutcome::Failed(text)) => self.message = Some(text),
            Err(e) => {
                self.message = Some(format!("операция не выполнилась: {e}"));
            }
        }
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

    /// Набранная фраза не переживает уход с карточки.
    ///
    /// Одно место на все пути: свернули карточку, раскрыли другую, список
    /// перечитался — черновик перестал соответствовать раскрытой записи и
    /// затирается. Без этого начатый и брошенный ввод просто выпадал бы из
    /// памяти нетронутым (находка ревью Гейта-2).
    fn forget_stale_passphrase(&mut self) {
        // Разблокировка: черновик не соответствует раскрытой карточке.
        let matches_card = match (&self.unlock, &self.expanded) {
            (Some(draft), Some(label)) => draft.target.as_str() == label.as_str(),
            _ => false,
        };
        if !matches_card && let Some(mut draft) = self.unlock.take() {
            draft.text.zeroize();
        }
        // Создание: ушли с формы (`screen != Create`), а черновик завис —
        // затираем оба поля пароля. Одно место на оба черновика, чтобы новую
        // точку выхода не пришлось помнить (инвариант 5).
        if self.screen != Screen::Create
            && let Some(mut draft) = self.create.take()
        {
            draft.passphrase.zeroize();
            draft.confirm.zeroize();
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

    /// Отказ по носителю произносится словами: молчание здесь — тот же дефект,
    /// что и ложное сообщение (инвариант 10).
    fn refuse_device(&mut self) {
        self.message = Some(
            "носители пока не поддержаны — в этом круге приложение умеет только \
             файлы-хранилища"
                .to_owned(),
        );
    }

    fn handle(&mut self, ctx: &egui::Context, action: ListAction) {
        match action {
            ListAction::Open(label) => {
                // Секрет забирается `mem::take`: буфер виджета остаётся пустой
                // строкой, копии не создаётся, а черновик снимается сразу — и
                // при успехе, и при отказе. Оставлять фразу в поле «чтобы
                // поправить опечатку» значило бы не выполнить единственное
                // обещание, которое мы дали: защитить участок от клавиши до
                // `SecretString`.
                let typed = self
                    .unlock
                    .as_mut()
                    .filter(|d| d.target.as_str() == label.as_str())
                    .map(|d| std::mem::take(&mut d.text));
                self.unlock = None;
                let Some(mut typed) = typed else { return };
                // Секрет строится из `&str`: `SecretString` копирует его в
                // собственный буфер, который затирает при уничтожении, — а
                // исходную строку мы затираем сами, здесь. Отдать `String`
                // целиком было бы короче, но перевод `String → Box<str>`
                // вправе перевыделить память, и тогда незачищенная копия
                // осталась бы лежать в куче (находка ревью Гейта-2).
                let passphrase = SecretString::from(typed.as_str());
                typed.zeroize();

                match self.container_of(&label) {
                    Some(container) => {
                        self.spawn_op(
                            ctx,
                            Op::Open {
                                label,
                                container,
                                passphrase,
                            },
                        );
                    }
                    None => self.refuse_device(),
                }
            }
            ListAction::Close(label) => {
                // Путь контейнера берём из записи: в `Op` он приходит уже
                // разобранным, чтобы фоновая задача не читала реестр второй раз.
                match self.container_of(&label) {
                    Some(container) => {
                        self.spawn_op(ctx, Op::Close { label, container });
                    }
                    None => self.refuse_device(),
                }
            }
            ListAction::Remove(label) => {
                self.spawn_op(ctx, Op::Remove(label));
            }
            ListAction::CommitRename { old, new } => match Label::new(&new) {
                Ok(new) => {
                    // Черновик снимается только если операция реально началась:
                    // иначе набранное имя исчезло бы вместе с полем.
                    if self.spawn_op(ctx, Op::Rename { old, new }) {
                        self.rename = None;
                    }
                }
                Err(e) => self.message = Some(error_text(&e)),
            },
            ListAction::StartCreate => {
                self.screen = Screen::Create;
                self.create = Some(CreateDraft::default());
            }
        }
    }

    /// Экран создания: Cancel уводит на список (черновик затрёт `forget`),
    /// Submit валидирует, строит секрет и запускает `Op::Create`.
    fn handle_create(&mut self, ctx: &egui::Context, action: CreateAction) {
        let CreateAction::Submit = action else {
            // Cancel: уходим на список; черновик (с секретом) затрёт
            // `forget_stale_passphrase`, увидев `screen != Create`.
            self.screen = Screen::List;
            return;
        };
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
        // 3. Запускаем; черновик (уже без секрета) снимет `forget` при `screen = List`.
        let container = container_path(&self.home, &label);
        if self.spawn_op(
            ctx,
            Op::Create {
                label,
                container,
                size_bytes,
                passphrase,
            },
        ) {
            self.screen = Screen::List;
        }
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
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.take_finished();

        let ctx = ui.ctx().clone();
        match self.screen {
            Screen::List => {
                let action = view_list::show(
                    ui,
                    ListInput {
                        entries: &self.entries,
                        env: &self.env,
                        message: self.message.as_deref(),
                        busy: self.pending.is_some(),
                        rename: &mut self.rename,
                        expanded: &mut self.expanded,
                        unlock: &mut self.unlock,
                    },
                );
                if let Some(action) = action {
                    self.handle(&ctx, action);
                }
            }
            Screen::Create => {
                let busy = self.pending.is_some();
                let message = self.message.as_deref();
                let action = self
                    .create
                    .as_mut()
                    .and_then(|draft| view_create::show(ui, draft, busy, message));
                if let Some(action) = action {
                    self.handle_create(&ctx, action);
                }
            }
        }
        self.forget_stale_passphrase();

        self.tick_smoke(ui.ctx());
    }
}

async fn run_op(path: &std::path::Path, home: &std::path::Path, op: Op) -> OpOutcome {
    match op {
        Op::Reload => match Registry::load_from(path).await {
            Ok(reg) => OpOutcome::Loaded(reg.entries().to_vec()),
            Err(e) => OpOutcome::Failed(error_text(&e)),
        },
        Op::Remove(label) => write_then_read(path, move |r| r.remove(&label)).await,
        Op::Rename { old, new } => write_then_read(path, move |r| r.rename(&old, new)).await,
        Op::Close { label, container } => run_close(path, home, &label, &container).await,
        Op::Open {
            label,
            container,
            passphrase,
        } => run_open(path, home, &label, &container, &passphrase).await,
        Op::Create {
            label,
            container,
            size_bytes,
            passphrase,
        } => run_create(path, home, &label, &container, size_bytes, &passphrase).await,
    }
}

/// Открытие: одна задача, один секрет, одно пробуждение окна.
async fn run_open(
    path: &std::path::Path,
    home: &std::path::Path,
    label: &Label,
    container: &std::path::Path,
    passphrase: &SecretString,
) -> OpOutcome {
    let ud = match Udisks::connect().await {
        Ok(ud) => ud,
        Err(e) => return OpOutcome::Failed(error_text(&e)),
    };
    match lifecycle::open_file_vault(&ud, container, label, passphrase, home).await {
        // Точка монтирования — из ответа udisks2, не угаданная: путь симлинка
        // сюда не подставляется (спека п.2 скоупа).
        Ok(opened) => {
            set_state_then_read(
                path,
                label,
                VaultState::Open {
                    mount_point: opened.mount_point,
                    until: None,
                },
            )
            .await
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
            match lifecycle::close_file_vault(&ud, &loop_object, label, home, false).await {
                Ok(()) => set_state_then_read(path, label, VaultState::Closed).await,
                Err(e) => OpOutcome::Failed(error_text(&e)),
            }
        }
    }
}

/// Что делать с томом по результату пробы.
///
/// Вынесено в чистую функцию намеренно: тест окна не может позвать живой
/// udisks2, а разбор пяти вариантов — именно то, что обязано быть проверено.
#[derive(Debug, PartialEq, Eq)]
enum CloseDecision {
    /// Файл не подключён: закрывать нечего, привести запись к правде.
    AlreadyDetached,
    /// Есть объект loop-устройства — закрываем.
    Close(ObjPath),
    /// Подключён чужим uid: не трогаем (инвариант 3).
    Foreign(u32),
}

/// `match` без ветки `_`: новый вариант пробы обязан сломать сборку здесь.
fn close_decision(probe: VaultProbe) -> CloseDecision {
    match probe {
        VaultProbe::Detached => CloseDecision::AlreadyDetached,
        VaultProbe::AttachedLocked { loop_object }
        | VaultProbe::AttachedUnlocked { loop_object, .. }
        | VaultProbe::AttachedOpen { loop_object, .. } => CloseDecision::Close(loop_object),
        VaultProbe::Foreign { uid, .. } => CloseDecision::Foreign(uid),
    }
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
    use std::path::Path;

    use egui_kittest::Harness;
    use egui_kittest::kittest::{NodeT as _, Queryable};
    use panzir_core::vault::VaultState;

    use super::*;

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
            text.contains("уже запущен"),
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
        harness
            .get_all_by_label("Подробнее")
            .next()
            .expect("кнопка раскрытия первой записи")
            .click();
        harness.run();
        harness.get_by_label("Открыть").click();
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
        harness.get_by_label("Открыть").click();
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
        harness
            .get_all_by_label("Подробнее")
            .next()
            .expect("кнопка раскрытия первой записи")
            .click();
        harness.run();
        assert!(
            !harness
                .get_by_label("Открыть")
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
                .get_by_label("Открыть")
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

        harness.get_by_label("Свернуть").click();
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
        for field in ["Метка:", "Размер, МиБ:", "Пароль:", "Повтор:"] {
            assert!(
                harness.query_by_label(field).is_some(),
                "на форме создания нет поля {field}"
            );
        }
        assert!(
            harness.query_by_label("Создать").is_some(),
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
                .get_by_label("Создать")
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
                .get_by_label("Создать")
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
                .get_by_label("Создать")
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
                .get_by_label("Создать")
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
            Screen::List,
            "экран не вернулся на список после Submit"
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
        harness
            .get_all_by_label("Подробнее")
            .next()
            .expect("кнопка раскрытия файловой записи")
            .click();
        harness.run();
        assert!(
            harness.query_by_label_contains("Файл:").is_some(),
            "раскрыта не файловая карточка — контроль канала пуст"
        );
        assert!(
            harness
                .query_by_label_contains("стандартный LUKS2")
                .is_some(),
            "файловая карточка не показала обещание про стандартный LUKS2"
        );

        // t-beta (Device): после раскрытия t-alpha единственный «Подробнее» — её.
        harness
            .get_all_by_label("Подробнее")
            .next()
            .expect("кнопка раскрытия записи на носителе")
            .click();
        harness.run();
        assert!(
            harness
                .query_by_label_contains("Носитель, UUID тома")
                .is_some(),
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
        harness.get_by_label("Открыть").click();
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
    /// # Почему проверен только один вариант из пяти
    /// Остальные четыре несут `ObjPath`, а у него **нет публичного
    /// конструктора** (`udisks.rs:76-89`: `from_owned` приватен,
    /// `block_device` — `pub(crate)`). Собрать их вне `panzir-core`
    /// невозможно. Что закрывает дыру вместо теста: `match` без ветки `_`
    /// (новый вариант ломает сборку) и живые IT ядра, где ветка `Foreign`
    /// проверяется на настоящем томе (`t19`). Записано в отчёт Гейта-2 как
    /// ограничение, а не как достаточное покрытие.
    #[test]
    fn detached_volume_is_not_closed_again() {
        assert_eq!(
            close_decision(VaultProbe::Detached),
            CloseDecision::AlreadyDetached,
            "отсоединённый том нечем закрывать: объекта loop-устройства не существует"
        );
    }

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
        let home = registry
            .parent()
            .expect("у фикстуры есть каталог")
            .to_path_buf();
        let mut harness = Harness::new_eframe(move |cc| {
            App::new(
                cc,
                registry.clone(),
                home.clone(),
                None,
                Duration::from_secs(5),
            )
        });
        harness.state_mut().block_until_idle();
        harness.run();
        harness
    }

    #[test]
    fn list_shows_entries_from_the_registry() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let harness = harness_at(fixture(dir.path()));

        harness.get_by_label_contains("t-alpha");
        harness.get_by_label_contains("t-beta");
    }

    #[test]
    fn removing_an_entry_keeps_the_container_file_on_disk() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let container = dir.path().join("t-alpha.vault");
        let mut harness = harness_at(fixture(dir.path()));
        assert!(container.exists(), "фикстура не создала файл — тест слеп");

        harness
            .get_all_by_label("Удалить из списка")
            .next()
            .expect("кнопка удаления первой записи")
            .click();
        harness.run();
        harness.state_mut().block_until_idle();
        harness.run();

        assert!(
            harness.query_by_label_contains("t-alpha").is_none(),
            "запись осталась в списке"
        );
        harness.get_by_label_contains("t-beta");
        assert!(
            container.exists(),
            "удаление записи стёрло файл контейнера — это данные человека"
        );
    }

    #[test]
    fn renaming_to_an_existing_label_is_rejected_with_a_readable_message() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));

        harness
            .get_all_by_label("Переименовать")
            .next()
            .expect("кнопка переименования первой записи")
            .click();
        harness.run();

        harness.state_mut().rename.as_mut().expect("черновик").text = "t-beta".to_owned();
        harness.get_by_label("Сохранить").click();
        harness.run();
        harness.state_mut().block_until_idle();
        harness.run();

        harness.get_by_label_contains("уже занято");
        harness.get_by_label_contains("t-alpha");
    }

    #[test]
    fn renaming_to_a_free_label_changes_the_entry() {
        let dir = tempfile::tempdir().expect("временный каталог");
        let mut harness = harness_at(fixture(dir.path()));

        harness
            .get_all_by_label("Переименовать")
            .next()
            .expect("кнопка переименования первой записи")
            .click();
        harness.run();

        harness.state_mut().rename.as_mut().expect("черновик").text = "t-gamma".to_owned();
        harness.get_by_label("Сохранить").click();
        harness.run();
        harness.state_mut().block_until_idle();
        harness.run();

        harness.get_by_label_contains("t-gamma");
        harness.get_by_label_contains("t-beta");
        assert!(
            harness.query_by_label_contains("t-alpha").is_none(),
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

        harness
            .get_all_by_label("Удалить из списка")
            .next()
            .expect("кнопка удаления")
            .click();
        harness.run();
        harness.state_mut().block_until_idle();
        harness.run();

        harness.get_by_label_contains("уже запущен");
        harness.get_by_label_contains("t-alpha");

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
                .is_some_and(|m| m.contains("подождите")),
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
}
