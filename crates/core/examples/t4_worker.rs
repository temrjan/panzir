//! Воркер для Т-4: один процесс добавляет запись в реестр.
#![allow(missing_docs)]
// expect/unwrap в тестовом воркере — осознанно.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use panzir_core::registry::{Registry, VaultEntry};
use panzir_core::vault::{Label, VaultKind, VaultState};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: t4_worker <registry_path> <label>");
        std::process::exit(2);
    }
    let path = PathBuf::from(&args[1]);
    let label = Label::new(&args[2]).expect("valid label");
    let file = PathBuf::from(format!("/tmp/{}.vault", label.as_str()));

    // LOCK_NB означает, что при одновременном старте один процесс может
    // получить AlreadyRunning. Переделаем в цикл с бэкоффом: так мы
    // доказываем, что race не приводит к дублированию, а оба процесса
    // в итоге записываются.
    let mut last_err = None;
    for attempt in 0..30 {
        match Registry::with_write_lock_at(&path, |r| {
            r.add(VaultEntry::new(
                label.clone(),
                VaultKind::File(file.clone()),
                VaultState::Closed,
            ))
        })
        .await
        {
            Ok(()) => return,
            Err(panzir_core::Error::AlreadyRunning) => {
                last_err = Some("AlreadyRunning");
                tokio::time::sleep(std::time::Duration::from_millis(50 + attempt * 10)).await;
            }
            Err(e) => {
                eprintln!("add entry failed: {e}");
                std::process::exit(1);
            }
        }
    }
    eprintln!("add entry failed after retries: {last_err:?}");
    std::process::exit(1);
}
