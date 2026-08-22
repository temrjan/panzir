//! Второй keyslot для LUKS2-тома.
//!
//! Файл-контейнер — `cryptsetup luksAddKey` без root.
//! Флешка — `pkexec cryptsetup luksAddKey` (один системный диалог).
//!
//! Пароли не попадают в argv/env/логи. cryptsetup 2.8 не умеет читать
//! два пароля из одного stdin корректно (план §3.2 предполагал иначе),
//! поэтому каждый пароль пишется во временный файл с mode 0600 и
//! передаётся через `--key-file` / `--new-keyfile`.

use std::path::{Path, PathBuf};

use tokio::fs;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

use crate::passphrase::Passphrase;
use crate::{Error, Result};

/// Результат добавления keyslot.
#[derive(Debug, Clone)]
pub struct AddedKeyslot;

/// Добавить второй пароль к файлу-контейнеру.
///
/// По контракту вызывающий гарантирует, что том заперт:
/// `cryptsetup luksAddKey` сам вернёт ошибку, если это не так.
/// Пароли не попадают в argv/env/логи.
pub async fn add_keyslot_to_file(
    container: &Path,
    existing: &Passphrase,
    new: &Passphrase,
) -> Result<AddedKeyslot> {
    luks_add_key(container, existing, new, false).await
}

/// Добавить второй пароль к флешке.
///
/// Использует ровно один `pkexec` — системный диалог polkit.
/// Пароли не попадают в argv/env/логи.
pub async fn add_keyslot_to_device(
    device: &Path,
    existing: &Passphrase,
    new: &Passphrase,
) -> Result<AddedKeyslot> {
    luks_add_key(device, existing, new, true).await
}

/// Создать временный keyfile с mode 0600, содержащий ровно passphrase.
async fn keyfile_from_passphrase(passphrase: &Passphrase) -> Result<PathBuf> {
    let dir = std::env::temp_dir();
    fs::create_dir_all(&dir).await.map_err(Error::Io)?;
    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let file = dir.join(format!(
        "panzir-keyfile-{}-{}.tmp",
        std::process::id(),
        uniq
    ));
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&file)
        .await
        .map_err(Error::Io)?
        .write_all(passphrase.as_str().as_bytes())
        .await
        .map_err(Error::Io)?;
    Ok(file)
}

async fn luks_add_key(
    path: &Path,
    existing: &Passphrase,
    new: &Passphrase,
    use_pkexec: bool,
) -> Result<AddedKeyslot> {
    let existing_file = keyfile_from_passphrase(existing).await?;
    let new_file = keyfile_from_passphrase(new).await?;

    let result = async {
        let mut cmd = if use_pkexec {
            let mut c = Command::new("pkexec");
            c.arg("cryptsetup");
            c
        } else {
            Command::new("cryptsetup")
        };

        cmd.arg("luksAddKey")
            .arg("--key-file")
            .arg(&existing_file)
            .arg("--new-keyfile")
            .arg(&new_file)
            .arg(path);

        let status = cmd.status().await.map_err(Error::Io)?;
        if status.success() {
            Ok(AddedKeyslot)
        } else {
            Err(Error::Command {
                cmd: format!("cryptsetup luksAddKey {}", path.display()),
                status: status.to_string(),
            })
        }
    }
    .await;

    // Лучшая попытка убрать секрет с диска в любом случае.
    let _ = fs::remove_file(&existing_file).await;
    let _ = fs::remove_file(&new_file).await;

    result
}
