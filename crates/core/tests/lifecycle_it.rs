//! Интеграционные тесты T-14…T-19 (спека PR-3a): жизненный цикл хранилища.
//!
//! Живые тесты помечены `#[ignore]` с причиной — без `--ignored` libtest
//! честно показывает `ignored`, а не `ok` за непрогнанную проверку.
//!
//! Запуск на целевой Fedora: `scripts/run-it-tests.sh` (готовит polkit-правило
//! и отключает автомонт, свипает за собой).
//!
//! Прямая команда:
//! `PANZIR_IT=1 cargo test -p panzir-core --test lifecycle_it -- --ignored`

// expect/unwrap в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use panzir_core::Error;
use panzir_core::create::{create_file_container, teardown_file_container};
use panzir_core::lifecycle::{VaultProbe, close_file_vault, open_file_vault, probe_file_vault};
use panzir_core::udisks::Udisks;
use panzir_core::vault::Label;
use secrecy::SecretString;

/// Живой udisks2 не обязан переживать два конкурентных вызова (22.08: два
/// параллельных теста уронили демон в SEGV — см. `create_it.rs`). Тесты ходят
/// в демон строго по очереди.
static UDISKS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn require_it_flag() {
    assert!(
        std::env::var_os("PANZIR_IT").is_some(),
        "PANZIR_IT=1 is required to run live integration tests"
    );
}

/// Сколько loop-устройств привязано к файлу — считаем ПО SYSFS, а не нашей же
/// `find_loops_for_backing_file`: проверять реализацию её собственным вызовом
/// значит написать тавтологию, которая зеленеет при сломанном коде.
fn count_loops_by_sysfs(container: &Path) -> usize {
    let target = std::fs::canonicalize(container).ok();
    let Ok(entries) = std::fs::read_dir("/sys/block") else {
        return 0;
    };
    entries
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            let name = e.file_name();
            let Some(name) = name.to_str() else {
                return false;
            };
            let Ok(raw) = std::fs::read_to_string(format!("/sys/block/{name}/loop/backing_file"))
            else {
                return false;
            };
            let trimmed = raw.trim_end_matches(['\n', '\r']);
            let cleaned = trimmed.strip_suffix(" (deleted)").unwrap_or(trimmed);
            match (&target, std::fs::canonicalize(cleaned).ok()) {
                (Some(t), Some(c)) => *t == c,
                _ => Path::new(cleaned) == container,
            }
        })
        .count()
}

/// Положительный контроль счётчика: прежде чем утверждать «loop-ов ноль»,
/// тест обязан показать, что счётчик вообще умеет считать (М-14 ревью раунда 1).
/// Иначе «0» ничем не отличается от сломанного канала измерения.
fn assert_counter_can_see(container: &Path, expected_nonzero: usize) {
    assert_eq!(
        count_loops_by_sysfs(container),
        expected_nonzero,
        "positive control: counter must see the loops that are known to exist"
    );
}

fn findmnt_options(mount_point: &Path) -> String {
    let out = Command::new("findmnt")
        .args(["-no", "OPTIONS", &mount_point.display().to_string()])
        .output()
        .expect("findmnt runs");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Уборка за тестом, которая срабатывает и при упавшем `assert`.
///
/// `create_it.rs` решает это `catch_unwind`; здесь тот же результат достигается
/// RAII, потому что тела тестов слишком разные для одной обёртки. Без этого
/// упавший тест оставляет том живым, а следующий тест в том же сьюте видит
/// чужой loop и падает уже по ложной причине (М-5 ревью раунда 1).
///
/// Всё синхронно и через `udisksctl` — `Drop` не может быть async.
struct TestCleanup {
    container: PathBuf,
}

impl Drop for TestCleanup {
    fn drop(&mut self) {
        for name in loop_names_by_sysfs(&self.container) {
            let dev = format!("/dev/{name}");
            // Порядок обязателен: снять loop из-под живой dm-crypt нельзя —
            // Delete ответит Ok, а устройства останутся (Б-1 раунда 1).
            let _ = Command::new("udisksctl")
                .args(["unmount", "-b", &dev, "--no-user-interaction"])
                .output();
            let _ = Command::new("udisksctl")
                .args(["lock", "-b", &dev, "--no-user-interaction"])
                .output();
            let _ = Command::new("udisksctl")
                .args(["loop-delete", "-b", &dev, "--no-user-interaction"])
                .output();
        }
        let _ = std::fs::remove_file(&self.container);
    }
}

/// Имена loop-устройств, привязанных к файлу (по sysfs).
fn loop_names_by_sysfs(container: &Path) -> Vec<String> {
    let target = std::fs::canonicalize(container).ok();
    let Ok(entries) = std::fs::read_dir("/sys/block") else {
        return Vec::new();
    };
    entries
        .filter_map(std::result::Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_owned();
            let raw =
                std::fs::read_to_string(format!("/sys/block/{name}/loop/backing_file")).ok()?;
            let trimmed = raw.trim_end_matches(['\n', '\r']);
            let cleaned = trimmed.strip_suffix(" (deleted)").unwrap_or(trimmed);
            let same = match (&target, std::fs::canonicalize(cleaned).ok()) {
                (Some(t), Some(c)) => *t == c,
                _ => Path::new(cleaned) == container,
            };
            same.then_some(name)
        })
        .collect()
}

/// Каталог, который тесты выдают за домашний: симлинки не должны попадать
/// в настоящий `~` разработчика.
fn fake_home(dir: &Path) -> PathBuf {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).expect("fake home");
    home
}

/// T-14: полный цикл — открыть, закрыть, открыть снова. Главный инвариант:
/// закрытие НЕ удаляет файл контейнера.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t14_open_close_open_keeps_container_file() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = fake_home(dir.path());
    let container = dir.path().join("panzir-t14.vault");
    let _cleanup = TestCleanup {
        container: container.clone(),
    };
    let label = Label::new("t14").expect("label");
    let pass = SecretString::from("t14-passphrase");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(&ud, &container, 64 * 1024 * 1024, &label, &pass)
        .await
        .expect("container created");
    // Положительный контроль ДО утверждения «ноль» (М-14).
    assert_counter_can_see(&container, 1);

    // Закрываем продуктовым путём — файл обязан остаться.
    close_file_vault(&ud, &created.loop_object, &label, &home, true)
        .await
        .expect("close must succeed");
    assert!(
        container.exists(),
        "close_file_vault must NOT delete the container file"
    );
    assert_eq!(
        count_loops_by_sysfs(&container),
        0,
        "loop must be detached after close"
    );
    // Стража «симлинка нет» здесь БЫТЬ НЕ ДОЛЖНО: create_file_container его не
    // создаёт, поэтому такая проверка не могла бы покраснеть никогда (Б-5
    // ревью раунда 1). Настоящая проверка — после второго закрытия, ниже.

    // Открываем заново.
    let opened = open_file_vault(&ud, &container, &label, &pass, &home)
        .await
        .expect("reopen must succeed");
    assert!(
        !opened.loop_was_reused,
        "we raised this loop ourselves, so loop_was_reused must be false"
    );
    assert!(
        findmnt_options(&opened.mount_point).contains("noexec"),
        "mount must carry noexec, findmnt says: {}",
        findmnt_options(&opened.mount_point)
    );
    let link = std::fs::read_link(home.join("panzir-t14")).expect("symlink exists");
    assert_eq!(link, opened.mount_point, "symlink must point at the mount");

    // И закрываем обратно — файл снова на месте, а симлинк снят.
    close_file_vault(
        &ud,
        &opened.loop_object,
        &label,
        &home,
        !opened.loop_was_reused,
    )
    .await
    .expect("second close");
    assert!(container.exists(), "container file still present");
    // symlink_metadata, а не exists(): exists() идёт ПО ссылке и вернул бы
    // false даже для зависшего линка на пропавшую точку монтирования (Б-5).
    assert!(
        std::fs::symlink_metadata(home.join("panzir-t14")).is_err(),
        "symlink must be gone after closing an opened vault"
    );

    std::fs::remove_file(&container).ok();
}

/// T-15: повторное открытие уже открытого хранилища не поднимает второй loop.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t15_second_open_does_not_raise_second_loop() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = fake_home(dir.path());
    let container = dir.path().join("panzir-t15.vault");
    let _cleanup = TestCleanup {
        container: container.clone(),
    };
    let label = Label::new("t15").expect("label");
    let pass = SecretString::from("t15-passphrase");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(&ud, &container, 64 * 1024 * 1024, &label, &pass)
        .await
        .expect("container created");
    assert_eq!(
        count_loops_by_sysfs(&container),
        1,
        "exactly one loop so far"
    );

    let opened = open_file_vault(&ud, &container, &label, &pass, &home)
        .await
        .expect("open on an already-open vault must be idempotent");
    assert!(
        opened.loop_was_reused,
        "loop already existed, so loop_was_reused must be true"
    );
    assert_eq!(
        count_loops_by_sysfs(&container),
        1,
        "second open must NOT raise a second loop"
    );
    assert_eq!(
        opened.mount_point, created.mount_point,
        "same vault, same mount point"
    );

    close_file_vault(
        &ud,
        &opened.loop_object,
        &label,
        &home,
        !opened.loop_was_reused,
    )
    .await
    .expect("close");
    std::fs::remove_file(&container).ok();
}

/// T-16: probe различает четыре живых состояния.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t16_probe_classifies_live_states() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = fake_home(dir.path());
    let container = dir.path().join("panzir-t16.vault");
    let _cleanup = TestCleanup {
        container: container.clone(),
    };
    let label = Label::new("t16").expect("label");
    let pass = SecretString::from("t16-passphrase");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(&ud, &container, 64 * 1024 * 1024, &label, &pass)
        .await
        .expect("container created");

    // 1. Создан и смонтирован → AttachedOpen.
    match probe_file_vault(&ud, &container).await.expect("probe") {
        VaultProbe::AttachedOpen { mount_point, .. } => {
            assert_eq!(mount_point, created.mount_point);
        }
        other => panic!("expected AttachedOpen, got {other:?}"),
    }

    // 2. После закрытия → Detached.
    close_file_vault(&ud, &created.loop_object, &label, &home, true)
        .await
        .expect("close");
    assert!(
        matches!(
            probe_file_vault(&ud, &container).await.expect("probe"),
            VaultProbe::Detached
        ),
        "closed container must probe as Detached"
    );

    // 3. Поднят loop, том заперт → AttachedLocked.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&container)
        .expect("open container");
    let loop_object = ud.loop_setup(file).await.expect("loop setup");
    let locked = probe_file_vault(&ud, &container).await.expect("probe");
    assert!(
        matches!(locked, VaultProbe::AttachedLocked { .. }),
        "locked volume must probe as AttachedLocked, got {locked:?}"
    );

    // 4. Отперт, но не смонтирован → AttachedUnlocked.
    let cleartext = ud.unlock(&loop_object, &pass).await.expect("unlock");
    let unlocked = probe_file_vault(&ud, &container).await.expect("probe");
    assert!(
        matches!(unlocked, VaultProbe::AttachedUnlocked { .. }),
        "unlocked-but-not-mounted volume must probe as AttachedUnlocked, got {unlocked:?}"
    );

    // 5. Смонтирован → снова AttachedOpen.
    let mount_point = ud.mount_noexec(&cleartext).await.expect("mount");
    match probe_file_vault(&ud, &container).await.expect("probe") {
        VaultProbe::AttachedOpen {
            mount_point: mp, ..
        } => assert_eq!(mp, mount_point),
        other => panic!("expected AttachedOpen after mount, got {other:?}"),
    }

    teardown_file_container(&ud, &loop_object, &container)
        .await
        .expect("teardown");
}

/// T-17: неверная парольная фраза не оставляет висячий loop.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t17_wrong_passphrase_leaves_no_stale_loop() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = fake_home(dir.path());
    let container = dir.path().join("panzir-t17.vault");
    let _cleanup = TestCleanup {
        container: container.clone(),
    };
    let label = Label::new("t17").expect("label");
    let pass = SecretString::from("t17-correct-passphrase");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(&ud, &container, 64 * 1024 * 1024, &label, &pass)
        .await
        .expect("container created");
    assert_counter_can_see(&container, 1); // положительный контроль (М-14)
    close_file_vault(&ud, &created.loop_object, &label, &home, true)
        .await
        .expect("close before the wrong-passphrase attempt");
    assert_eq!(count_loops_by_sysfs(&container), 0, "clean start");

    let wrong = SecretString::from("t17-WRONG-passphrase");
    let err = open_file_vault(&ud, &container, &label, &wrong, &home)
        .await
        .expect_err("wrong passphrase must fail");
    eprintln!("T-17: open with wrong passphrase failed as expected: {err}");

    assert_eq!(
        count_loops_by_sysfs(&container),
        0,
        "failed open must clean up the loop it raised"
    );
    assert!(
        !home.join("panzir-t17").exists(),
        "no symlink after a failed open"
    );
    assert!(container.exists(), "failed open must not delete the file");

    std::fs::remove_file(&container).ok();
}

/// T-19 (условие ревью раунда 2): два loop на одном файле — уже случившаяся
/// порча; probe обязан сказать об этом, а не молча взять первый.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t19_two_loops_on_one_container_are_reported() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = fake_home(dir.path());
    let container = dir.path().join("panzir-t19.vault");
    let _cleanup = TestCleanup {
        container: container.clone(),
    };
    let label = Label::new("t19").expect("label");
    let pass = SecretString::from("t19-passphrase");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(&ud, &container, 64 * 1024 * 1024, &label, &pass)
        .await
        .expect("container created");
    close_file_vault(&ud, &created.loop_object, &label, &home, true)
        .await
        .expect("close");

    // Два loop-setup подряд на один и тот же файл.
    let f1 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&container)
        .expect("open #1");
    let l1 = ud.loop_setup(f1).await.expect("loop setup #1");
    let f2 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&container)
        .expect("open #2");
    let l2 = ud.loop_setup(f2).await.expect("loop setup #2");

    assert_eq!(
        count_loops_by_sysfs(&container),
        2,
        "test setup itself must produce two loops"
    );

    let err = probe_file_vault(&ud, &container)
        .await
        .expect_err("probe must refuse to guess which loop is the right one");
    match err {
        Error::MultipleLoopsAttached { count, .. } => {
            assert_eq!(count, 2, "must report how many loops were found");
        }
        other => panic!("expected MultipleLoopsAttached, got {other:?}"),
    }

    // Уборка: оба loop, потом файл.
    teardown_file_container(&ud, &l1, &container).await.ok();
    teardown_file_container(&ud, &l2, &container).await.ok();
    std::fs::remove_file(&container).ok();
    assert_eq!(count_loops_by_sysfs(&container), 0, "cleanup left no loops");
}

/// T-20 (блокер Б-1/Б-3 раунда 1): провал ПОСЛЕ успешного отпирания не
/// оставляет отпертый том и висячий loop.
///
/// Ни один тест первой редакции не ронял шаг после `unlock` — именно там и
/// пряталась дыра: уборка снимала loop, не закрыв dm-crypt поверх него.
/// Препятствие ставим честное: занятый чужой путь симлинка, который
/// `create_symlink` обязан отвергнуть (`mountpoint.rs`).
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t20_failure_after_unlock_leaves_nothing_behind() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = fake_home(dir.path());
    let container = dir.path().join("panzir-t20.vault");
    let _cleanup = TestCleanup {
        container: container.clone(),
    };
    let label = Label::new("t20").expect("label");
    let pass = SecretString::from("t20-passphrase");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(&ud, &container, 64 * 1024 * 1024, &label, &pass)
        .await
        .expect("container created");
    assert_counter_can_see(&container, 1);
    close_file_vault(&ud, &created.loop_object, &label, &home, true)
        .await
        .expect("close before the test");
    assert_eq!(count_loops_by_sysfs(&container), 0, "clean start");

    // Препятствие: на месте будущего симлинка — обычный файл, не наш.
    std::fs::write(home.join("panzir-t20"), b"not a symlink").expect("obstacle");

    let err = open_file_vault(&ud, &container, &label, &pass, &home)
        .await
        .expect_err("open must fail on an occupied symlink path");
    eprintln!("T-20: open failed as expected: {err}");

    // Главное: том не остался отпертым, а loop — поднятым.
    assert_eq!(
        count_loops_by_sysfs(&container),
        0,
        "cleanup after a post-unlock failure must detach the loop"
    );
    let dm = Command::new("dmsetup")
        .args(["ls", "--target", "crypt"])
        .output()
        .expect("dmsetup runs");
    let dm = String::from_utf8_lossy(&dm.stdout);
    assert!(
        !dm.contains(&format!("{}-", label.as_str())) && !dm.contains("luks-"),
        "no dm-crypt device may survive a failed open, dmsetup says:\n{dm}"
    );
    assert!(container.exists(), "failed open must not delete the file");

    std::fs::remove_file(home.join("panzir-t20")).ok();
    std::fs::remove_file(&container).ok();
}

/// T-21 (блокер Б-4 раунда 1): том, запертый ЧУЖОЙ утилитой, остаётся своим.
///
/// После `Lock` udisks2 обнуляет `SetupByUID`. Если считать ноль «чужим
/// владельцем», пользователь, закрывший том штатной утилитой дисков, больше
/// никогда не откроет своё хранилище из приложения.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t21_locked_volume_with_cleared_owner_is_still_ours() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = fake_home(dir.path());
    let container = dir.path().join("panzir-t21.vault");
    let _cleanup = TestCleanup {
        container: container.clone(),
    };
    let label = Label::new("t21").expect("label");
    let pass = SecretString::from("t21-passphrase");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(&ud, &container, 64 * 1024 * 1024, &label, &pass)
        .await
        .expect("container created");

    // Запираем том, НЕ отвязывая loop — ровно то, что делает сторонняя утилита
    // дисков: том закрыт, устройство осталось, владелец обнулён.
    ud.unmount_wait(&created.cleartext_object)
        .await
        .expect("unmount");
    ud.lock(&created.loop_object).await.expect("lock");
    assert_counter_can_see(&container, 1);

    let uid = Command::new("id").arg("-u").output().expect("id runs");
    let uid = String::from_utf8_lossy(&uid.stdout).trim().to_owned();
    eprintln!("T-21: our uid is {uid}; SetupByUID is expected to be 0 after Lock");

    // Состояние обязано читаться как «наш, заперт», а не «чужой».
    match probe_file_vault(&ud, &container).await.expect("probe") {
        VaultProbe::AttachedLocked { .. } => {}
        VaultProbe::Foreign { uid, .. } => panic!(
            "locked-but-attached vault reported as Foreign(uid={uid}) — \
             the user would be locked out of their own vault"
        ),
        other => panic!("expected AttachedLocked, got {other:?}"),
    }

    // И оно обязано открываться.
    let opened = open_file_vault(&ud, &container, &label, &pass, &home)
        .await
        .expect("a vault locked by another tool must still open");
    assert!(opened.loop_was_reused, "loop existed before us");

    close_file_vault(
        &ud,
        &opened.loop_object,
        &label,
        &home,
        !opened.loop_was_reused,
    )
    .await
    .expect("close");
    // loop подняли не мы — отвязку не форсировали; убираем сами.
    teardown_file_container(&ud, &created.loop_object, &container)
        .await
        .ok();
    std::fs::remove_file(&container).ok();
}

/// T-22 (минор М-3): у контейнера, которого нет на диске, — понятный ответ.
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t22_missing_container_is_reported() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("panzir-t22.vault");
    let ud = Udisks::connect().await.expect("udisks2 on the bus");

    match probe_file_vault(&ud, &missing).await {
        Err(Error::ContainerMissing { path }) => {
            assert!(
                path.contains("panzir-t22.vault"),
                "path must be named: {path}"
            );
        }
        other => panic!("expected ContainerMissing, got {other:?}"),
    }
}

/// T-23 (блокер Б-7 раунда 1): на уже отпертом томе парольная фраза всё равно
/// проверяется.
///
/// Без этого поле «парольная фраза» переставало быть проверкой в двух
/// состояниях из пяти: любая строка «открывала» хранилище, если том отпер
/// кто-то другой. Заодно тест исполняет ветку `AttachedUnlocked` целиком —
/// раньше её не проходил ни один тест (М-4).
#[tokio::test]
#[ignore = "requires live udisks2/polkit; run with --ignored"]
async fn t23_wrong_passphrase_rejected_on_already_unlocked_volume() {
    require_it_flag();
    let _serial = UDISKS_LOCK.lock().await;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = fake_home(dir.path());
    let container = dir.path().join("panzir-t23.vault");
    let _cleanup = TestCleanup {
        container: container.clone(),
    };
    let label = Label::new("t23").expect("label");
    let pass = SecretString::from("t23-correct-passphrase");

    let ud = Udisks::connect().await.expect("udisks2 on the bus");
    let created = create_file_container(&ud, &container, 64 * 1024 * 1024, &label, &pass)
        .await
        .expect("container created");

    // Приводим том в состояние «отперт, но не смонтирован» — то самое, где
    // приложение раньше не спрашивало пароль вовсе.
    ud.unmount_wait(&created.cleartext_object)
        .await
        .expect("unmount");
    assert!(
        matches!(
            probe_file_vault(&ud, &container).await.expect("probe"),
            VaultProbe::AttachedUnlocked { .. }
        ),
        "precondition: volume must be unlocked but not mounted"
    );

    // Неверная фраза обязана быть отвергнута, хотя отпирать уже нечего.
    let wrong = SecretString::from("t23-WRONG-passphrase");
    let err = open_file_vault(&ud, &container, &label, &wrong, &home)
        .await
        .expect_err("wrong passphrase must be rejected even on an unlocked volume");
    eprintln!("T-23: rejected as expected: {err}");
    assert!(
        std::fs::symlink_metadata(home.join("panzir-t23")).is_err(),
        "no symlink may appear after a rejected open"
    );

    // А верная — открывает, и это та же ветка AttachedUnlocked.
    let opened = open_file_vault(&ud, &container, &label, &pass, &home)
        .await
        .expect("correct passphrase must open an already-unlocked volume");
    assert!(opened.loop_was_reused, "loop existed before this call");
    assert!(
        findmnt_options(&opened.mount_point).contains("noexec"),
        "mount must carry noexec even when we only mounted an existing volume"
    );

    teardown_file_container(&ud, &opened.loop_object, &container)
        .await
        .expect("teardown");
    std::fs::remove_file(home.join("panzir-t23")).ok();
}
