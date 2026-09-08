//! Регрессия CRITICAL аудита 2026-08-28: бинарь обязан разбирать argv.
//! Внутренний контракт «таймер ↔ бинарь» (не пользовательский CLI, спека
//! 2026-08-28-panzir-autoclose-fix-plan.md §3.1): любой argv, кроме пустого и
//! ровно `--close <валидная метка>`, — usage с различимой причиной в stderr
//! и exit 2.
//!
//! exit 2 наступает до чтения HOME и до `Udisks::connect`: ни дисплея, ни
//! D-Bus тесту не нужно. На сломанном коде бинарь открывает окно и висит —
//! обвязка убивает его по дедлайну. Кейсы ниже — аргументы ПОСЛЕ argv[0]:
//! процесс запускает ОС, имя бинаря в argv[0] она ставит сама (юнит-тесты
//! парсера в app.rs кормят полный argv — два уровня, одна договорённость).

// expect/unwrap/panic в тестах — осознанно (конвенция проекта, как
// close_worker.rs:7).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Гонит бинарь с аргументами и ждёт завершения не дольше TIMEOUT;
/// по дедлайну убивает процесс и падает сам.
fn run_with_args(args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_panzir-gui"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn panzir-gui");
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            return child.wait_with_output().expect("collect output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("panzir-gui {args:?}: no exit within {TIMEOUT:?} — killed");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn stderr_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn close_without_label_is_usage_error() {
    let out = run_with_args(&["--close"]);
    assert_eq!(out.status.code(), Some(2), "exit code");
    let err = stderr_text(&out);
    assert!(err.contains("usage:"), "usage line in stderr: {err}");
    assert!(
        err.contains("--close requires a label"),
        "reason in stderr: {err}"
    );
}

#[test]
fn close_with_invalid_label_is_usage_error() {
    let out = run_with_args(&["--close", "Bad_Label!!"]);
    assert_eq!(out.status.code(), Some(2), "exit code");
    let err = stderr_text(&out);
    assert!(err.contains("usage:"), "usage line in stderr: {err}");
    assert!(err.contains("invalid label"), "reason in stderr: {err}");
    assert!(
        !err.contains("requires a label"),
        "reasons must read differently: {err}"
    );
}

#[test]
fn unknown_argument_is_usage_error() {
    let out = run_with_args(&["--version"]);
    assert_eq!(out.status.code(), Some(2), "exit code");
    let err = stderr_text(&out);
    assert!(err.contains("usage:"), "usage line in stderr: {err}");
    assert!(err.contains("unknown argument"), "reason in stderr: {err}");
}
