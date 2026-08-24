//! Состояние окна, мост к ядру и перевод отказов на человеческий язык.
//!
//! Владелец связи «окно ↔ ядро»: всё асинхронное живёт здесь, экраны его не
//! знают. Ядро асинхронное, а [`eframe::App::ui`] синхронна и вызывается
//! десятки раз в секунду, поэтому операции уходят в рантайм tokio, а результат
//! снимается неблокирующе.

use std::future::Future;
use std::path::PathBuf;

use eframe::egui;
use panzir_core::Error;
use panzir_core::deps::{self, DepsReport};
use panzir_core::registry::{Registry, VaultEntry};
use panzir_core::udisks::Udisks;
use panzir_core::vault::{Label, VaultKind, VaultState};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::view_list::{self, ListAction, ListInput, RenameDraft};

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
    /// Сменить метку записи.
    Rename {
        /// Текущая метка.
        old: Label,
        /// Новая метка.
        new: Label,
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
            format!("список хранилищ не прочитать: {what}")
        }
        Error::Io(e) => format!("не удалось обратиться к диску: {e}"),
        Error::Udisks(e) => {
            format!("служба дисков udisks2 не отвечает: {e}")
        }
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

/// Состояние главного окна.
pub struct App {
    rt: Runtime,
    registry_path: PathBuf,
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
        smoke_frames: Option<u32>,
    ) -> Self {
        let rt = Runtime::new().expect("не удалось создать рантайм tokio");
        let local_deps = deps::check_local_deps();
        let mut app = Self {
            rt,
            registry_path,
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
        self.pending = Some(self.spawn_waking(ctx, async move { run_op(&path, op).await }));
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

    fn handle(&mut self, ctx: &egui::Context, action: ListAction) {
        match action {
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

        let action = view_list::show(
            ui,
            ListInput {
                entries: &self.entries,
                env: &self.env,
                message: self.message.as_deref(),
                busy: self.pending.is_some(),
                rename: &mut self.rename,
            },
        );
        if let Some(action) = action {
            let ctx = ui.ctx().clone();
            self.handle(&ctx, action);
        }

        self.tick_smoke(ui.ctx());
    }
}

async fn run_op(path: &std::path::Path, op: Op) -> OpOutcome {
    match op {
        Op::Reload => match Registry::load_from(path).await {
            Ok(reg) => OpOutcome::Loaded(reg.entries().to_vec()),
            Err(e) => OpOutcome::Failed(error_text(&e)),
        },
        Op::Remove(label) => write_then_read(path, move |r| r.remove(&label)).await,
        Op::Rename { old, new } => write_then_read(path, move |r| r.rename(&old, new)).await,
    }
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
    use egui_kittest::kittest::Queryable;
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

    fn harness_at(registry: std::path::PathBuf) -> Harness<'static, App> {
        let mut harness = Harness::new_eframe(move |cc| App::new(cc, registry.clone(), None));
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
