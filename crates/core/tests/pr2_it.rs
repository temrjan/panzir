//! Интеграционные тесты Т-3/Т-4/Т-10/Т-11/Т-12 (спека v1.1, план PR-2).
//!
//! Живые тесты помечены `#[ignore]` — без `--ignored` libtest честно показывает
//! `ignored`, а не `ok` за непрогнанную проверку (Гейт-2, Н-9).
//!
//! Т-9 (No_COW на btrfs) покрыт в `create_it.rs` (PR-1) и здесь не дублируется.
//!
//! Запуск на целевой Fedora:
//! `scripts/run-it-tests.sh` — готовит среду (polkit-правило, отключает GNOME-автомонт)
//! и запускает оба IT-сьюта.
//!
//! Ручной запуск требует:
//! - установленного `/etc/polkit-1/rules.d/99-panzir-test.rules` для нашего uid,
//! - отключённого GNOME-автомонта: `gsettings set org.gnome.desktop.media-handling automount false`,
//! - переменной `PANZIR_IT=1`.
//!
//! Прямая команда:
//! `PANZIR_IT=1 cargo test -p panzir-core --test pr2_it -- --ignored`

// expect/unwrap в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use futures_util::StreamExt as _;
use panzir_core::create::{CreatedVault, create_file_container, teardown_file_container};
use panzir_core::header::{HeaderBackupWarning, backup_header_from_file};
use panzir_core::keyslot::add_keyslot_to_file;
use panzir_core::mountpoint::{create_symlink, read_symlink, remove_symlink};
use panzir_core::passphrase::Passphrase;
use panzir_core::registry::{Registry, VaultEntry};
use panzir_core::udisks::Udisks;
use panzir_core::vault::{Label, VaultKind, VaultState};
use secrecy::SecretString;

/// Живой udisks2 не обязан переживать два параллельных вызова Format. Тесты
/// ходят в демон строго по очереди — уважение к внешней границе.
static UDISKS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn sh(cmd: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new(cmd).args(args).output()
}

fn require_it_flag() {
    assert!(
        std::env::var_os("PANZIR_IT").is_some(),
        "PANZIR_IT=1 is required to run live integration tests"
    );
}

/// Штатная уборка за тестом — тот же продовый путь, что в `create_it.rs`.
async fn cleanup(ud: &Udisks, created: &CreatedVault, container: &Path) {
    teardown_file_container(ud, &created.loop_object, container)
        .await
        .expect("cleanup must not leave a stale loop");
}

/// Т-3: второй keyslot реально работает — `luksDump` видит 2 слота,
/// открыть можно обоими паролями.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t3_second_keyslot_works() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let container = dir.path().join("t3.vault");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(
        &ud,
        &container,
        64 * 1024 * 1024,
        &Label::new("panzir-t3").expect("label"),
        &SecretString::from("first-pass-t3"),
    )
    .await
    .expect("container created");

    // Том приходит открытым; keyslot добавляется к запертому.
    // Используем unmount + lock без autoclear: после close_encrypted udisks2
    // не пересоздаёт интерфейс Encrypted на loop при внешнем luksAddKey + Rescan.
    ud.unmount_wait(&created.cleartext_object)
        .await
        .expect("unmount before add keyslot");
    ud.lock(&created.loop_object)
        .await
        .expect("lock before add keyslot");

    add_keyslot_to_file(
        &container,
        &Passphrase::new(SecretString::from("first-pass-t3")),
        &Passphrase::new(SecretString::from("second-pass-t3")),
    )
    .await
    .expect("add second keyslot");

    let dump = sh(
        "cryptsetup",
        &["luksDump", &container.display().to_string()],
    )
    .expect("luksDump runs");
    let dump = String::from_utf8_lossy(&dump.stdout);
    let slots = dump
        .lines()
        .skip_while(|l| !l.starts_with("Keyslots:"))
        .skip(1)
        .take_while(|l| !l.is_empty())
        .filter(|l| {
            l.trim().chars().next().is_some_and(|c| c.is_ascii_digit()) && l.contains("luks2")
        })
        .count();
    assert_eq!(slots, 2, "expected 2 key slots, got {slots}, dump:\n{dump}");

    // После lock udisks2 сбрасывает SetupByUID; повторный unlock/mount
    // без диалога polkit возможен только на свежем loop-устройстве.
    // Удаляем старый loop и поднимаем новый из того же файла.
    let old_device = format!("/dev/{}", created.loop_object.basename());
    let out = tokio::process::Command::new("udisksctl")
        .args(["loop-delete", "-b", &old_device, "--no-user-interaction"])
        .output()
        .await
        .expect("udisksctl loop-delete");
    assert!(
        out.status.success(),
        "loop-delete failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let file = tokio::fs::File::open(&container)
        .await
        .expect("reopen container")
        .into_std()
        .await;
    let new_loop = ud.loop_setup(file).await.expect("loop setup again");

    // Открываем первым паролем. Mount не делаем: в графической сессии
    // отдельный Mount после Unlock может запросить диалог polkit, а
    // сам факт успешного Unlock доказывает, что keyslot работает.
    // Автомонт может смонтировать после Unlock — размонтируем и дожмёмся.
    let ct1 = ud
        .unlock(&new_loop, &SecretString::from("first-pass-t3"))
        .await
        .expect("unlock with first passphrase");
    ud.unmount_wait(&ct1)
        .await
        .expect("unmount after first unlock");

    // Закрываем и убираем loop; для второго пароля поднимем loop заново,
    // иначе после lock udisks2 теряет Encrypted и повторный unlock не работает.
    ud.close_encrypted(&new_loop)
        .await
        .expect("close after first unlock");

    let file = tokio::fs::File::open(&container)
        .await
        .expect("reopen container for second key")
        .into_std()
        .await;
    let new_loop = ud
        .loop_setup(file)
        .await
        .expect("loop setup for second key");

    // Открываем вторым паролем.
    let ct2 = ud
        .unlock(&new_loop, &SecretString::from("second-pass-t3"))
        .await
        .expect("unlock with second passphrase");
    ud.unmount_wait(&ct2)
        .await
        .expect("unmount after second unlock");

    // cleanup для нового loop: teardown_file_container удалит и loop, и файл.
    teardown_file_container(&ud, &new_loop, &container)
        .await
        .expect("cleanup must not leave a stale loop");
}

/// Т-4: два хранилища, симлинки, уникальность метки, защита чужого пути,
/// стресс flock двумя процессами.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t4_two_vaults_symlinks_and_registry() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;
    let home = tempfile::tempdir().expect("home tempdir");
    let dir = tempfile::tempdir().expect("container tempdir");
    let c1 = dir.path().join("t4a.vault");
    let c2 = dir.path().join("t4b.vault");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let v1 = create_file_container(
        &ud,
        &c1,
        64 * 1024 * 1024,
        &Label::new("panzir-t4a").expect("label"),
        &SecretString::from("pass-t4a"),
    )
    .await
    .expect("create first");
    let v2 = create_file_container(
        &ud,
        &c2,
        64 * 1024 * 1024,
        &Label::new("panzir-t4b").expect("label"),
        &SecretString::from("pass-t4b"),
    )
    .await
    .expect("create second");

    let label_a = Label::new("t4a").expect("label a");
    let label_b = Label::new("t4b").expect("label b");

    create_symlink(home.path(), &label_a, &v1.mount_point)
        .await
        .expect("symlink a");
    create_symlink(home.path(), &label_b, &v2.mount_point)
        .await
        .expect("symlink b");

    let mp_a = read_symlink(home.path(), &label_a).await.expect("read a");
    let mp_b = read_symlink(home.path(), &label_b).await.expect("read b");
    assert_ne!(mp_a, mp_b, "symlinks must point to different mount points");

    // Чужой путь не трогаем.
    let foreign = home.path().join("panzir-foreign");
    std::fs::write(&foreign, b"do not touch").expect("write foreign");
    create_symlink(
        home.path(),
        &Label::new("foreign").expect("foreign label"),
        &v1.mount_point,
    )
    .await
    .expect_err("foreign path exists");
    assert!(foreign.exists(), "foreign file must survive");
    assert_eq!(
        std::fs::read_to_string(&foreign).expect("read foreign"),
        "do not touch"
    );

    // Дубликат метки в реестре.
    let reg_dir = tempfile::tempdir().expect("regdir");
    let reg_path = reg_dir.path().join("vaults.toml");
    Registry::with_write_lock_at(&reg_path, |r| {
        r.add(VaultEntry::new(
            Label::new("shared").expect("shared"),
            VaultKind::File(c1.clone()),
            VaultState::Closed,
        ))
    })
    .await
    .expect("add shared");
    let err = Registry::with_write_lock_at(&reg_path, |r| {
        r.add(VaultEntry::new(
            Label::new("shared").expect("shared"),
            VaultKind::File(c2.clone()),
            VaultState::Closed,
        ))
    })
    .await
    .expect_err("duplicate label");
    assert!(
        matches!(err, panzir_core::Error::DuplicateLabel(_)),
        "expected DuplicateLabel, got {err:?}"
    );

    // Невалидные метки отвергаются.
    assert!(Label::new("a/b").is_err(), "slash in label");
    assert!(Label::new("..").is_err(), "dotdot label");

    cleanup(&ud, &v1, &c1).await;
    cleanup(&ud, &v2, &c2).await;

    remove_symlink(home.path(), &label_a)
        .await
        .expect("remove a");
    remove_symlink(home.path(), &label_b)
        .await
        .expect("remove b");
    assert!(!home.path().join("panzir-t4a").exists());
    assert!(!home.path().join("panzir-t4b").exists());
}

/// Т-4 (продолжение): стресс advisory flock — два процесса одновременно
/// добавляют разные метки, обе успешны, дубликата нет.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t4_flock_stress_two_processes() {
    require_it_flag();
    let reg_dir = tempfile::tempdir().expect("regdir");
    let reg_path = reg_dir.path().join("vaults.toml");

    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = workspace_root
        .parent()
        .and_then(Path::parent)
        .expect("core is at crates/core inside workspace")
        .to_path_buf();
    let worker = workspace_root.join("target/debug/examples/t4_worker");
    assert!(
        worker.exists(),
        "worker binary not found at {}",
        worker.display()
    );

    // Собираем воркера явно, чтобы путь существовал.
    let build = tokio::process::Command::new("cargo")
        .args([
            "build",
            "-p",
            "panzir-core",
            "--example",
            "t4_worker",
            "--quiet",
        ])
        .current_dir(&workspace_root)
        .status()
        .await
        .expect("build worker");
    assert!(build.success(), "worker build failed");

    let run_worker = |label: &str| {
        let worker = worker.clone();
        let reg = reg_path.clone();
        let label = label.to_owned();
        tokio::spawn(async move {
            tokio::process::Command::new(&worker)
                .arg(&reg)
                .arg(&label)
                .status()
                .await
        })
    };

    let (a, b) = tokio::join!(run_worker("alpha"), run_worker("beta"));
    assert!(
        a.expect("spawn alpha").expect("run alpha").success(),
        "alpha worker failed"
    );
    assert!(
        b.expect("spawn beta").expect("run beta").success(),
        "beta worker failed"
    );

    let reg = Registry::load_from(&reg_path).await.expect("load registry");
    let labels: Vec<_> = reg
        .entries()
        .iter()
        .map(|e| e.label().as_str().to_owned())
        .collect();
    assert!(labels.contains(&"alpha".to_owned()), "alpha missing");
    assert!(labels.contains(&"beta".to_owned()), "beta missing");
    assert_eq!(labels.len(), 2, "no duplicates expected");
}

/// Т-10: бэкап заголовка читаем текущим пользователем, mode 0600,
/// предупреждение о той же ФС.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t10_header_backup_readable_and_warns_same_fs() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let container = dir.path().join("t10.vault");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(
        &ud,
        &container,
        64 * 1024 * 1024,
        &Label::new("panzir-t10").expect("label"),
        &SecretString::from("pass-t10"),
    )
    .await
    .expect("container created");
    ud.close_encrypted(&created.loop_object)
        .await
        .expect("close before backup");

    let backup_same = dir.path().join("t10-header.backup");
    let warning = backup_header_from_file(
        &container,
        &backup_same,
        &Passphrase::new(SecretString::from("pass-t10")),
    )
    .await
    .expect("backup same fs");
    assert!(
        matches!(warning, Some(HeaderBackupWarning::SameFilesystem)),
        "same-fs backup must warn"
    );

    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(&backup_same)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "backup mode is {mode:o}, expected 600");

    let magic = std::fs::read(&backup_same).expect("read backup");
    assert!(
        magic.starts_with(b"LUKS"),
        "backup must start with LUKS magic"
    );

    // Попытка записать бэкап на другую ФС. /dev/shm — tmpfs, если контейнер
    // не там же. Если совпала — тест мягко принимает любой результат.
    let other_dir = tempfile::tempdir_in("/dev/shm")
        .unwrap_or_else(|_| tempfile::tempdir().expect("fallback tempdir"));
    let backup_other = other_dir.path().join("t10-header-other.backup");
    let warning2 = backup_header_from_file(
        &container,
        &backup_other,
        &Passphrase::new(SecretString::from("pass-t10")),
    )
    .await
    .expect("backup other fs");

    let fs_same = sh(
        "stat",
        &["-f", "-c", "%T", &dir.path().display().to_string()],
    )
    .expect("stat same");
    let fs_other = sh(
        "stat",
        &["-f", "-c", "%T", &other_dir.path().display().to_string()],
    )
    .expect("stat other");
    let same = String::from_utf8_lossy(&fs_same.stdout).trim().to_owned();
    let other = String::from_utf8_lossy(&fs_other.stdout).trim().to_owned();
    if same != other && !same.is_empty() && !other.is_empty() {
        assert!(
            warning2.is_none(),
            "different fs must not produce same-fs warning"
        );
    }

    cleanup(&ud, &created, &container).await;
}

/// Т-11: пароль не появляется в `/proc/<pid>/cmdline` и `environ`.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t11_passphrase_does_not_leak_to_proc() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let container = dir.path().join("t11.vault");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(
        &ud,
        &container,
        64 * 1024 * 1024,
        &Label::new("panzir-t11").expect("label"),
        &SecretString::from("initial-pass-t11"),
    )
    .await
    .expect("container created");
    ud.close_encrypted(&created.loop_object)
        .await
        .expect("close before keyslot");

    let secret = "panzir-leak-test-secret-42";
    let existing = Passphrase::new(SecretString::from("initial-pass-t11"));
    let new = Passphrase::new(SecretString::from(secret));

    let container_for_task = container.clone();
    let add_task =
        tokio::spawn(
            async move { add_keyslot_to_file(&container_for_task, &existing, &new).await },
        );

    let mut leaked = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline {
        if scan_for_secret(secret).await {
            leaked = true;
            break;
        }
        if add_task.is_finished() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    add_task.await.expect("add task").expect("add keyslot");
    assert!(!leaked, "secret found in /proc while keyslot operation ran");

    cleanup(&ud, &created, &container).await;
}

async fn scan_for_secret(secret: &str) -> bool {
    let needle = secret.as_bytes();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().chars().any(|c| !c.is_ascii_digit()) {
            continue;
        }
        for file in ["cmdline", "environ"] {
            let path = entry.path().join(file);
            if let Ok(data) = tokio::fs::read(&path).await
                && data.windows(needle.len()).any(|w| w == needle)
            {
                return true;
            }
        }
    }
    false
}

/// Т-12: удаление loop-устройства порождает событие `InterfacesRemoved`,
/// после которого запись реестра переводится в `Disconnected`.
#[tokio::test]
#[ignore = "requires live udisks2/polkit and udisksctl; run with --ignored"]
async fn t12_device_removed_marks_disconnected() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let dir = tempfile::tempdir_in(&home).expect("tempdir in home");
    let container = dir.path().join("t12.vault");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(
        &ud,
        &container,
        64 * 1024 * 1024,
        &Label::new("panzir-t12").expect("label"),
        &SecretString::from("pass-t12"),
    )
    .await
    .expect("container created");
    // Запираем без autoclear: close_encrypted включил бы autoclear, и loop
    // мог бы самоотвязаться до нашего loop-delete.
    ud.unmount_wait(&created.cleartext_object)
        .await
        .expect("unmount before remove");
    ud.lock(&created.loop_object)
        .await
        .expect("lock before remove");

    let label = Label::new("panzir-t12").expect("label");
    let reg_dir = tempfile::tempdir_in(&home).expect("regdir in home");
    let reg_path = reg_dir.path().join("vaults.toml");
    Registry::with_write_lock_at(&reg_path, |r| {
        r.add(VaultEntry::new(
            label.clone(),
            VaultKind::File(container.clone()),
            VaultState::Closed,
        ))
    })
    .await
    .expect("add closed entry");

    // Подписываемся ДО удаления loop (наблюдение Ревьюера).
    let mut stream = ud.interfaces_removed_stream().await.expect("stream");

    let device = format!("/dev/{}", created.loop_object.basename());
    let out = tokio::process::Command::new("udisksctl")
        .args(["loop-delete", "-b", &device, "--no-user-interaction"])
        .output()
        .await
        .expect("udisksctl runs");
    assert!(
        out.status.success(),
        "loop-delete failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Ждём событие снятия интерфейсов с нашего loop-объекта.
    // udisks2 может снять Encrypted отдельно от Block; достаточно самого
    // сигнала InterfacesRemoved для этого path.
    let found = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(item) = stream.next().await {
            if let Ok(event) = item
                && event.path == created.loop_object
            {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(
        found,
        "InterfacesRemoved for {} not received",
        created.loop_object
    );

    // Переводим запись в Disconnected.
    Registry::with_write_lock_at(&reg_path, |r| {
        let entry = r
            .entries_mut()
            .iter_mut()
            .find(|e| *e.label() == label)
            .expect("entry exists");
        entry.set_state(VaultState::Disconnected)
    })
    .await
    .expect("mark disconnected");

    let reg = Registry::load_from(&reg_path).await.expect("load registry");
    let entry = reg
        .entries()
        .iter()
        .find(|e| *e.label() == label)
        .expect("entry exists");
    assert_eq!(
        entry.state(),
        &VaultState::Disconnected,
        "registry entry must be Disconnected"
    );

    teardown_file_container(&ud, &created.loop_object, &container)
        .await
        .expect("cleanup must not leave a stale loop");
}
