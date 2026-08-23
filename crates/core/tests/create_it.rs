//! Интеграционные тесты Т-1/Т-2/Т-3 (спека v1.1, тест-план) — на НАСТОЯЩИХ
//! контейнерах через живой udisks2. Спайк доказал: root не нужен, тесты
//! гоняют тот же путь, что и прод.
//!
//! Гейт: `#[ignore]` — без явного `--ignored` libtest честно показывает
//! `ignored`, а не `ok` за проверку, которая не бежала (Гейт-2, Н-9).
//! Локально на целевой Fedora:
//! `cargo test -p panzir-core --test create_it -- --ignored`
//! Т-3 (btrfs): `PANZIR_IT_DIR=<каталог на btrfs> cargo test ... t3_ -- --ignored`
//!
//! Правило §4.2 плана: опции проверяются ПО РЕЗУЛЬТАТУ (luksDump, findmnt,
//! lsattr), а не по отсутствию исключения — udisks2 молча глотает опции.

// expect в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use futures_util::FutureExt;
use panzir_core::create::{CreatedVault, create_file_container, teardown_file_container};
use panzir_core::udisks::Udisks;
use panzir_core::vault::Label;
use secrecy::SecretString;

/// Живой udisks2 не обязан переживать два конкурентных Format (22.08: два
/// параллельных теста уронили демон в SEGV). Тесты ходят в демон строго
/// по очереди — это не маскировка flaky, а уважение к внешней границе.
static UDISKS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn sh(cmd: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new(cmd).args(args).output()
}

/// Есть ли loop, привязанный к этому файлу — по sysfs (ядрёная правда).
/// Суффикс " (deleted)" обрезаем: файл могли уже удалить, а привязка жива.
fn loop_attached_to(container: &Path) -> bool {
    std::fs::read_dir("/sys/block")
        .into_iter()
        .flatten()
        .filter_map(std::result::Result::ok)
        .filter_map(|e| std::fs::read_to_string(e.path().join("loop/backing_file")).ok())
        .any(|backing| {
            backing.trim().trim_end_matches(" (deleted)") == container.display().to_string()
        })
}

/// Создать контейнер, выполнить проверки в `catch_unwind`, затем всегда
/// вызвать teardown и восстановить исходную панику. Мьютекс UDISKS_LOCK
/// держится на всём теле хелпера (создание + проверки + teardown).
async fn with_container<F, Fut>(ud: &Udisks, label: &str, test_fn: F)
where
    F: FnOnce(CreatedVault, PathBuf) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let dir = tempfile::tempdir().expect("tempdir");
    let container = dir.path().join(format!("{label}.vault"));

    let created = create_file_container(
        ud,
        &container,
        64 * 1024 * 1024,
        &Label::new(label).expect("label"),
        &SecretString::from(format!("test-passphrase-{label}")),
    )
    .await
    .expect("container created");

    let verdict = std::panic::AssertUnwindSafe(async {
        test_fn(created.clone(), container.clone()).await;
    })
    .catch_unwind()
    .await;

    let teardown = teardown_file_container(ud, &created.loop_object, &container).await;

    match (verdict, teardown) {
        (Ok(()), Ok(())) => {}
        (Ok(()), Err(e)) => panic!("teardown failed: {e}"),
        (Err(payload), Ok(())) => std::panic::resume_unwind(payload),
        (Err(payload), Err(e)) => {
            eprintln!("teardown also failed: {e}");
            std::panic::resume_unwind(payload);
        }
    }
}

/// Т-1: созданный контейнер — настоящий LUKS2 с ожидаемыми параметрами
/// заголовка, И метка ФС та, что просили (обе опции проверяются по
/// результату, а не по «D-Bus не вернул ошибку»).
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t1_created_container_is_genuine_luks2() {
    let _serial = UDISKS_LOCK.lock().await;
    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    with_container(&ud, "panzir-t1", |created, container| async move {
        // Положительный контроль канала: пока том жив, sysfs ОБЯЗАН знать
        // backing-файл — иначе страж в cleanup вакуумный.
        assert!(
            loop_attached_to(&container),
            "sysfs does not know the backing file while attached"
        );

        // isLuks признаёт файл
        let is_luks = sh("cryptsetup", &["isLuks", &container.display().to_string()])
            .expect("cryptsetup runs")
            .status
            .success();
        assert!(
            is_luks,
            "cryptsetup isLuks does not recognize the container"
        );

        let dump = sh(
            "cryptsetup",
            &["luksDump", &container.display().to_string()],
        )
        .expect("luksDump runs");
        let dump = String::from_utf8_lossy(&dump.stdout).into_owned();
        // luksDump разливает колонки пробелами и табуляциями — нормализуем.
        let flat = dump.split_whitespace().collect::<Vec<_>>().join(" ");
        for needle in ["Version: 2", "aes-xts-plain64", "512 bits", "argon2id"] {
            assert!(
                flat.contains(needle),
                "luksDump header missing {needle:?}:\n{dump}"
            );
        }

        // Метка ФС — по результату (Гейт-2, Н-6).
        let label_out = sh(
            "findmnt",
            &["-no", "LABEL", &created.mount_point.display().to_string()],
        )
        .expect("findmnt runs");
        let label = String::from_utf8_lossy(&label_out.stdout).trim().to_owned();
        assert!(
            !label.is_empty(),
            "findmnt LABEL is empty — channel carries nothing"
        );
        assert_eq!(label, "panzir-t1", "FS label mismatch");

        // Права контейнера — 0600 с первой секунды (Гейт-2, Н-2).
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&container)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "container mode is {mode:o}, expected 600");
    })
    .await;
}

/// Т-2: том смонтирован с noexec — по findmnt, не по отсутствию ошибки.
/// Анти-пустота: «rw» тоже обязан присутствовать, иначе проверка опций
/// могла бы читать пустую строку.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t2_mounted_with_noexec_proven_by_findmnt() {
    let _serial = UDISKS_LOCK.lock().await;
    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    with_container(&ud, "panzir-t2", |created, _container| async move {
        let out = sh(
            "findmnt",
            &["-no", "OPTIONS", &created.mount_point.display().to_string()],
        )
        .expect("findmnt runs");
        let options = String::from_utf8_lossy(&out.stdout).into_owned();

        assert!(
            options.contains("rw"),
            "sanity: findmnt must report real options, got {options:?}"
        );
        assert!(
            options.contains("noexec"),
            "mount must have noexec (план §4.9), got {options:?}"
        );
    })
    .await;
}

/// Т-3: на btrfs контейнер создаётся с No_COW — по `lsattr`, не по коду
/// возврата chattr (Гейт-2, Н-7). Каталог выбирается через PANZIR_IT_DIR
/// (должен указывать на btrfs, на целевой Fedora это ~/).
#[tokio::test]
#[ignore = "requires live udisks2/polkit and PANZIR_IT_DIR on btrfs; run with --ignored"]
async fn t3_container_on_btrfs_is_nocow() {
    let _serial = UDISKS_LOCK.lock().await;
    let Some(dir) = std::env::var_os("PANZIR_IT_DIR").map(PathBuf::from) else {
        eprintln!("SKIP: set PANZIR_IT_DIR to a directory on btrfs");
        return;
    };
    let container = dir.join(format!("panzir-t3-{}.vault", std::process::id()));

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(
        &ud,
        &container,
        64 * 1024 * 1024,
        &Label::new("panzir-t3").expect("label"),
        &SecretString::from("test-passphrase-t3"),
    )
    .await
    .expect("container created");

    let out = sh("lsattr", &[&container.display().to_string()]).expect("lsattr runs");
    let attrs = String::from_utf8_lossy(&out.stdout).into_owned();

    cleanup(&ud, &created, &container).await;

    let attrs = attrs.trim().to_owned();
    assert!(!attrs.is_empty(), "lsattr output empty — channel check");
    assert!(
        attrs.contains('C'),
        "container on btrfs must be No_COW (план §4.8), lsattr: {attrs:?}"
    );
}

/// Уборка за тестом — единый teardown-оркестр: close_encrypted с retry,
/// fallback loop_delete, ожидание sysfs и удаление файла только после
/// подтверждения отвязки loop.
async fn cleanup(ud: &Udisks, created: &CreatedVault, container: &Path) {
    if let Err(e) = teardown_file_container(ud, &created.loop_object, container).await {
        eprintln!("cleanup: teardown_file_container failed: {e}");
    }
}
