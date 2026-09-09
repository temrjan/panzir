//! panzir — окно управления зашифрованными хранилищами.
//!
//! Единственное место, где приложение встречается с операционной системой:
//! здесь читается окружение, определяется путь реестра и поднимается окно.
//!
//! Командная строка — внутренний контракт «таймер ↔ бинарь», а не
//! пользовательский CLI: таймер автозакрытия запускает этот же бинарь с
//! `--close <метка>`. Без аргументов — окно; ровно `--close <валидная метка>` —
//! headless-закрытие (0 — успех, включая «занято, отложено», 1 — отказ);
//! любой иной argv — usage с различимой причиной в stderr и код 2. Парсер
//! аргументов не нужен нарочно: форм вызова две.

#![deny(missing_docs)]

mod app;
mod view_create;
mod view_list;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use panzir_core::lifecycle;
use panzir_core::registry::Registry;
use panzir_core::schedule::SystemdUser;
use panzir_core::udisks::Udisks;
use panzir_core::vault::Label;
use tokio::runtime::Runtime;

/// Сколько ждём операцию с хранилищем, прежде чем сказать человеку, что оно
/// не откликается. Замер худшего случая закрытия — около 52 с (черновик
/// 2026-08-23), запас взят до круглого числа. Значение живёт ЗДЕСЬ, а не
/// внутри окна: инвариант 9 — иначе тесту нечем подставить своё, и проверка
/// таймаута стоила бы минуты ожидания на каждый прогон.
const OP_TIMEOUT: Duration = Duration::from_secs(60);

fn main() -> ExitCode {
    init_tracing();

    // Разбор argv — до любого чтения окружения и шин: exit 2 не зависит от
    // системы и наступает до Udisks::connect (на это опирается tests/cli.rs).
    // Парсеру — полный argv с argv[0]: имя ставит ОС (контракт §3.1 спеки).
    let argv: Vec<OsString> = std::env::args_os().collect();
    match app::close_label_from(&argv) {
        app::CloseRequest::Usage(reason) => {
            eprintln!("{}", app::usage_reason_text(&reason));
            eprintln!("{}", app::usage_line());
            ExitCode::from(2)
        }
        app::CloseRequest::Window => match environment() {
            Ok((registry_path, home)) => run_window(registry_path, home),
            Err(code) => code,
        },
        app::CloseRequest::Close(label) => match environment() {
            Ok((registry_path, home)) => run_close(&label, &registry_path, &home),
            Err(code) => code,
        },
    }
}

/// Общие для обоих режимов чтения системы — по одному разу каждое
/// (CLAUDE.md:37), и оба после разбора argv: exit 2 от окружения не зависит.
fn environment() -> Result<(PathBuf, PathBuf), ExitCode> {
    let registry_path = match Registry::default_path() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("{}", app::error_text(&e));
            return Err(ExitCode::FAILURE);
        }
    };

    // HOME читается здесь, в единственном месте встречи с системой: путь
    // симлинка хранилища строится от него, а окну он приходит параметром.
    let home = match std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        Some(h) => PathBuf::from(h),
        None => {
            eprintln!("{}", app::error_text(&panzir_core::Error::NoHome));
            return Err(ExitCode::FAILURE);
        }
    };
    Ok((registry_path, home))
}

/// Обычный запуск: окно управления хранилищами.
fn run_window(registry_path: PathBuf, home: PathBuf) -> ExitCode {
    // Единственное чтение `current_exe` в приложении — здесь, и оно фатально:
    // окно заводит таймеры с этим путём как командой закрывателя, подставлять
    // вместо него нечего. В `--close`-режиме путь не нужен вовсе: `disarm`
    // закрывателя не читает (М-7 ревью).
    let closer = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("не удалось определить путь к panzir: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Путь `~/.ssh/config` определяется здесь, в единственной встрече с
    // системой, и приходит в окно параметром (инвариант 9): тест подставляет
    // свой, настоящий config разработчика прогонами не трогается.
    let ssh_config = home.join(".ssh").join("config");
    // Единственное чтение этой переменной: разбор — в чистой функции, иначе
    // её нечем проверить (подменить переменную в тесте не даёт
    // `unsafe_code = "forbid"`).
    let raw_frames = std::env::var("PANZIR_SMOKE_FRAMES").ok();
    let smoke_frames = app::smoke_frames_from(raw_frames.as_deref());

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("panzir")
            .with_inner_size([720.0, 480.0]),
        ..Default::default()
    };

    match eframe::run_native(
        "panzir",
        options,
        Box::new(move |cc| {
            Ok(Box::new(app::App::new(
                cc,
                registry_path,
                home,
                ssh_config,
                closer,
                smoke_frames,
                OP_TIMEOUT,
            )))
        }),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("окно не удалось создать: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Headless-закрытие хранилища по вызову таймера (`--close <метка>`).
/// Эталон — `examples/close_worker.rs`; отличие одно: реестр и домашний
/// каталог берутся из системы, а не из аргументов.
///
/// «Занято» (`Deferred`) — не отказ: дедлайн снят, таймер не перезаведён,
/// ждём человека (E-minimal), поэтому юнит не `failed`, а строка исхода
/// читается иначе, чем «closed».
fn run_close(label: &Label, registry_path: &std::path::Path, home: &std::path::Path) -> ExitCode {
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("не удалось создать рантайм tokio: {e}");
            return ExitCode::FAILURE;
        }
    };
    let report = rt.block_on(async {
        let ud = Udisks::connect().await?;
        // Префикс закрывателя пуст: в этом режиме он не используется —
        // `disarm` его не читает, а `arm` на этом пути не вызывается. Поэтому
        // и `current_exe` здесь не читается: отказ определить собственный путь
        // не должен отменять закрытие хранилища (М-7 ревью).
        let clock = SystemdUser::new(Vec::new(), OP_TIMEOUT);
        lifecycle::close_registered(&ud, registry_path, home, &clock, label).await
    });
    match report {
        Ok(report) => {
            println!("{}", app::outcome_line(label, &report.outcome));
            ExitCode::SUCCESS
        }
        Err(e) => {
            // Журнальный путь — английский по решению (инвариант 10): `error_text`
            // даёт русский UI-текст для окна, журнал разбирают по `journalctl`.
            eprintln!("{label}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Подписчик журнала: без него пятнадцать точек `tracing` в ядре пишут в никуда.
/// Уровень — из `RUST_LOG`, по умолчанию `warn`.
///
/// Секретов в журнал не попадает (инвариант 5). **Формулировка изменена в
/// круге 3c:** раньше здесь стояло «парольных фраз в этом окне нет вовсе» —
/// с появлением разблокировки это перестало быть правдой. Сегодня верно
/// другое: фраза живёт в `SecretString`, чей `Debug` печатает заглушку, а не
/// содержимое, и ни в одну точку `tracing` не передаётся. Буфер поля ввода
/// опустошается при отправке (`App::handle`, проверено тестом
/// `passphrase_buffer_is_emptied_on_submit`).
///
/// Чего мы НЕ обещаем: что фразы не останется в памяти процесса. Проверить
/// это честно нечем, поэтому и не утверждается.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    // В stderr, а не в stdout: фатальные ошибки в `main` уходят через
    // `eprintln!`, и диагностика не должна разъезжаться с ними по потокам.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
