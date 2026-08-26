//! panzir — окно управления зашифрованными хранилищами.
//!
//! Единственное место, где приложение встречается с операционной системой:
//! здесь читается окружение, определяется путь реестра и поднимается окно.

#![deny(missing_docs)]

mod app;
mod view_create;
mod view_list;

use std::process::ExitCode;

use panzir_core::registry::Registry;
use std::path::PathBuf;
use std::time::Duration;

/// Сколько ждём операцию с хранилищем, прежде чем сказать человеку, что оно
/// не откликается. Замер худшего случая закрытия — около 52 с (черновик
/// 2026-08-23), запас взят до круглого числа. Значение живёт ЗДЕСЬ, а не
/// внутри окна: инвариант 9 — иначе тесту нечем подставить своё, и проверка
/// таймаута стоила бы минуты ожидания на каждый прогон.
const OP_TIMEOUT: Duration = Duration::from_secs(60);

fn main() -> ExitCode {
    init_tracing();

    let registry_path = match Registry::default_path() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("{}", app::error_text(&e));
            return ExitCode::FAILURE;
        }
    };

    // HOME читается здесь, в единственном месте встречи с системой: путь
    // симлинка хранилища строится от него, а окну он приходит параметром.
    let home = match std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        Some(h) => PathBuf::from(h),
        None => {
            eprintln!("{}", app::error_text(&panzir_core::Error::NoHome));
            return ExitCode::FAILURE;
        }
    };

    // Единственное чтение окружения в приложении: разбор — в чистой функции,
    // иначе его нечем проверить (подменить переменную в тесте не даёт
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
