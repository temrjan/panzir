//! panzir — окно управления зашифрованными хранилищами.
//!
//! Единственное место, где приложение встречается с операционной системой:
//! здесь читается окружение, определяется путь реестра и поднимается окно.

#![deny(missing_docs)]

mod app;
mod view_list;

use std::process::ExitCode;

use panzir_core::registry::Registry;

fn main() -> ExitCode {
    init_tracing();

    let registry_path = match Registry::default_path() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("{}", app::error_text(&e));
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
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, registry_path, smoke_frames)))),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("окно не удалось создать: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Подписчик журнала: без него пятнадцать точек `tracing` в ядре пишут в никуда.
/// Уровень — из `RUST_LOG`, по умолчанию `warn`. Секретов в журнал не попадает
/// (инвариант 5): парольных фраз в этом окне нет вовсе.
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
