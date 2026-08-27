//! Закрыватель для живых IT автозакрытия (T-25, T-26): то, что таймер
//! запускает вместо окна. Продуктовый закрыватель — `panzir --close <метка>`,
//! он берёт реестр и домашний каталог из системы; этот — только из аргументов,
//! чтобы тест не тронул настоящий `~/.config/panzir/vaults.toml`.
#![allow(missing_docs)]
// expect/unwrap в тестовом воркере — осознанно.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use panzir_core::lifecycle::close_registered;
use panzir_core::schedule::SystemdUser;
use panzir_core::udisks::Udisks;
use panzir_core::vault::Label;

#[tokio::main]
async fn main() {
    // <registry> <home> --close <label>
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 || args[3] != "--close" {
        eprintln!("usage: close_worker <registry> <home> --close <label>");
        std::process::exit(2);
    }
    let registry = PathBuf::from(&args[1]);
    let home = PathBuf::from(&args[2]);
    let label = Label::new(&args[4]).expect("valid label");

    // Тот же префикс, каким нас запустили: `registry` и `home`.
    let closer: Vec<OsString> = std::env::args_os().take(3).collect();
    let clock = SystemdUser::new(closer, Duration::from_secs(60));

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    match close_registered(&ud, &registry, &home, &clock, &label).await {
        Ok(report) => println!("{}: {:?}", label, report.outcome),
        Err(e) => {
            eprintln!("{label}: {e}");
            std::process::exit(1);
        }
    }
}
