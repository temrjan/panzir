//! Мастер создания файл-контейнера (спека v1.1, п.1 скоупа).
//!
//! Порядок обязателен (план §4.8): на btrfs `chattr +C` ставится на ПУСТОЙ
//! файл, до наполнения — иначе CoW уже включён для существующих экстентов.
//! Аллокация полная (fallocate), sparse запрещён.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::udisks::{ObjPath, Udisks};
use crate::vault::Label;
use crate::{Error, Result};

/// Результат создания контейнера: объектные пути udisks2 и фактическая
/// точка монтирования. После возврата том **открыт и смонтирован**
/// (факт §4.6 плана — Format сам отпирает и монтирует).
#[derive(Debug, Clone)]
pub struct CreatedVault {
    /// Объект loop-устройства.
    pub loop_object: ObjPath,
    /// Объект расшифрованного устройства (dm-crypt).
    pub cleartext_object: ObjPath,
    /// Фактическая точка монтирования (сообщена udisks2, не угадана).
    pub mount_point: PathBuf,
}

/// Запускает утилиту и проверяет код завершения. Аргументы — `&OsStr`:
/// пути в Linux — байты, `display().to_string()` калечит не-UTF-8 имена.
/// Секретов в argv нет никогда — пароль уходит в udisks2 по D-Bus, а в
/// cryptsetup (PR-2) будет передан через stdin.
async fn run(cmd: &str, args: &[&OsStr]) -> Result<()> {
    let status = tokio::process::Command::new(cmd)
        .args(args)
        .status()
        .await?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Command {
            cmd: format!(
                "{cmd} {}",
                args.iter()
                    .map(|a| a.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            status: status.to_string(),
        })
    }
}

/// Файловая система, на которой лежит путь (по `stat -f`).
async fn fs_type(path: &Path) -> Result<String> {
    let output = tokio::process::Command::new("stat")
        .args(["-f", "-c", "%T"])
        .arg(path)
        .output()
        .await?;
    if !output.status.success() {
        return Err(Error::Command {
            cmd: format!("stat -f -c %T {}", path.display()),
            status: output.status.to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Создаёт файл-контейнер LUKS2 и возвращает его открытым и смонтированным
/// с `noexec`.
///
/// # Errors
/// Все системные шаги могут упасть: см. [`Error`]. При ЛЮБОЙ ошибке после
/// создания файла мастер убирает за собой полностью (unmount → autoclear →
/// lock → loop → файл) и возвращает исходную ошибку — недоделанных
/// контейнеров и занятых путей не остаётся.
pub async fn create_file_container(
    ud: &Udisks,
    path: &Path,
    size_bytes: u64,
    label: &Label,
    passphrase: &SecretString,
) -> Result<CreatedVault> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::InvalidContainerPath(path.display().to_string()))?;
    let on_btrfs = fs_type(parent).await? == "btrfs";

    // Файл с режимом 0600 АТОМАРНО при open(2) — не chmod'ом после:
    // иначе в окне между open и chmod чужой локальный процесс успевает
    // открыть файл и сохранить чтение навсегда (Гейт-2, Н-2).
    let file = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .await?
        .into_std()
        .await;

    let result = prepare_and_format(ud, file, path, size_bytes, on_btrfs, label, passphrase).await;
    if result.is_err() {
        // Cleanup без маскировки исходной ошибки; файл — последним,
        // после того как отработал cleanup устройств.
        if let Err(e) = tokio::fs::remove_file(path).await {
            tracing::warn!("cleanup: failed to remove {}: {e}", path.display());
        }
    }
    result
}

/// Всё после создания файла: подготовка ФС и работа с устройством.
/// Любая ошибка здесь обязана оставить систему чистой.
async fn prepare_and_format(
    ud: &Udisks,
    file: std::fs::File,
    path: &Path,
    size_bytes: u64,
    on_btrfs: bool,
    label: &Label,
    passphrase: &SecretString,
) -> Result<CreatedVault> {
    if on_btrfs {
        // +C на пустой файл, ДО fallocate (план §4.8).
        run("chattr", &[OsStr::new("+C"), path.as_os_str()]).await?;
    }
    run(
        "fallocate",
        &[
            OsStr::new("-l"),
            OsStr::new(&size_bytes.to_string()),
            path.as_os_str(),
        ],
    )
    .await?;

    let loop_object = ud.loop_setup(file).await?;

    let result = async {
        ud.format_luks2(&loop_object, label.as_str(), passphrase)
            .await?;
        let cleartext_object = ud.cleartext_device(&loop_object).await?;
        // Автомонт udisks2 — БЕЗ noexec (замер спайка); mount_noexec сам
        // разруливает гонку с ним (AlreadyMounted → unmount → mount).
        let mount_point = ud.mount_noexec(&cleartext_object).await?;
        Ok(CreatedVault {
            loop_object: loop_object.clone(),
            cleartext_object,
            mount_point,
        })
    }
    .await;

    if result.is_err() {
        teardown_partial(ud, &loop_object).await;
    }
    result
}

/// Откат при ошибке ПОСЛЕ Format: том может быть отперт и смонтирован.
/// Тот же оркестрированный порядок закрытия, что в проде (Гейт-2,
/// Н-1 + Н-26): close_encrypted; на живом dm-crypt loop_delete бессилен,
/// поэтому он — только страховка после, для случая «заперто, но loop жив».
async fn teardown_partial(ud: &Udisks, loop_object: &ObjPath) {
    if let Err(e) = ud.close_encrypted(loop_object).await {
        tracing::warn!("teardown: close_encrypted failed: {e}");
    }
    if let Err(e) = ud.loop_delete(loop_object).await {
        tracing::warn!("teardown: loop_delete failed: {e}");
    }
}
