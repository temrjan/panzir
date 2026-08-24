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
use std::time::Duration;

use tokio::fs;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

use crate::passphrase::Passphrase;
use crate::{Error, Result};

/// Временный keyfile с секретом. Удаляет файл в `Drop`, даже если future
/// отменена (Б-2 ревью PR-2). Публичен внутри крейта для header.rs.
pub(crate) struct TempKeyfile {
    path: PathBuf,
    // Handle держим открытым, чтобы guard существовал сразу после open.
    // Если future отменится между open и write/flush, файл всё равно удалится.
    _file: fs::File,
}

impl TempKeyfile {
    pub(crate) async fn from_passphrase(passphrase: &Passphrase) -> Result<Self> {
        let dir = std::env::temp_dir();
        fs::create_dir_all(&dir).await.map_err(Error::Io)?;
        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = dir.join(format!(
            "panzir-keyfile-{}-{}.tmp",
            std::process::id(),
            uniq
        ));
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .await
            .map_err(Error::Io)?;
        // Guard конструируется сразу после open (М-*).
        let mut guard = Self { path, _file: file };
        guard
            ._file
            .write_all(passphrase.as_str().as_bytes())
            .await
            .map_err(Error::Io)?;
        guard._file.flush().await.map_err(Error::Io)?;
        Ok(guard)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempKeyfile {
    fn drop(&mut self) {
        // Синхронное удаление вне async-контекста — допустимо для файла.
        let _ = std::fs::remove_file(&self.path);
    }
}

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

async fn luks_add_key(
    path: &Path,
    existing: &Passphrase,
    new: &Passphrase,
    use_pkexec: bool,
) -> Result<AddedKeyslot> {
    let existing_key = TempKeyfile::from_passphrase(existing).await?;
    let new_key = TempKeyfile::from_passphrase(new).await?;

    let mut cmd = if use_pkexec {
        let mut c = Command::new("pkexec");
        c.arg("cryptsetup");
        c
    } else {
        Command::new("cryptsetup")
    };

    cmd.arg("luksAddKey")
        .arg("--key-file")
        .arg(existing_key.path())
        .arg("--new-keyfile")
        .arg(new_key.path())
        .arg(path)
        .kill_on_drop(true);

    let mut child = cmd.spawn().map_err(Error::Io)?;
    let status = match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => return Err(Error::Io(e)),
        Err(_) => {
            let _ = child.kill().await;
            return Err(Error::Command {
                cmd: format!("cryptsetup luksAddKey {}", path.display()),
                status: "timeout".to_owned(),
            });
        }
    };

    if status.success() {
        Ok(AddedKeyslot)
    } else {
        Err(Error::Command {
            cmd: format!("cryptsetup luksAddKey {}", path.display()),
            status: status.to_string(),
        })
    }
}
