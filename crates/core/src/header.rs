//! Бэкап LUKS-заголовка.
//!
//! Файл-контейнер — `cryptsetup luksHeaderBackup` без root.
//! Флешка — `pkexec cryptsetup luksHeaderBackup` (один системный диалог).
//! udisks2 `Encrypted.HeaderBackup` не используем: он создаёт файл 0400 root
//! (план §4.5). Результат бэкапа читаем текущим пользователем.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Stdio;

use tokio::fs;
use tokio::process::Command;

use crate::passphrase::Passphrase;
use crate::{Error, Result};

/// Предупреждение, которое показываем пользователю перед бэкапом.
#[derive(Debug, Clone)]
pub enum HeaderBackupWarning {
    /// Бэкап на той же ФС, что и контейнер — погибнут вместе.
    SameFilesystem,
}

/// Бэкап заголовка файла-контейнера.
pub async fn backup_header_from_file(
    container: &Path,
    backup: &Path,
    passphrase: &Passphrase,
) -> Result<Option<HeaderBackupWarning>> {
    backup_header(container, backup, passphrase, false).await
}

/// Бэкап заголовка флешки.
pub async fn backup_header_from_device(
    device: &Path,
    backup: &Path,
    passphrase: &Passphrase,
) -> Result<Option<HeaderBackupWarning>> {
    backup_header(device, backup, passphrase, true).await
}

async fn backup_header(
    source: &Path,
    backup: &Path,
    passphrase: &Passphrase,
    use_pkexec: bool,
) -> Result<Option<HeaderBackupWarning>> {
    let parent = backup
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| Error::InvalidContainerPath(backup.display().to_string()))?;

    let same_fs = same_filesystem(source, parent).await?;
    let warning = same_fs.then_some(HeaderBackupWarning::SameFilesystem);

    // Создаём родительский каталог с правильными правами, если нужно.
    // Сам backup-файл создаёт cryptsetup: он отказывается перезаписывать
    // существующий файл. Mode 0600 выставляем после.
    fs::create_dir_all(parent).await.map_err(Error::Io)?;
    fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(Error::Io)?;

    let mut cmd = if use_pkexec {
        let mut c = Command::new("pkexec");
        c.arg("cryptsetup");
        c
    } else {
        Command::new("cryptsetup")
    };

    cmd.arg("luksHeaderBackup")
        .arg("--header-backup-file")
        .arg(backup)
        .arg("--key-file")
        .arg("-")
        .arg(source)
        .stdin(Stdio::piped());

    let mut child = cmd.spawn().map_err(Error::Io)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::Io(std::io::Error::other("stdin not piped")))?;
    passphrase.write_to_stdin(&mut stdin).await?;

    let status = child.wait().await.map_err(Error::Io)?;
    if !status.success() {
        return Err(Error::Command {
            cmd: format!(
                "cryptsetup luksHeaderBackup {} {}",
                source.display(),
                backup.display()
            ),
            status: status.to_string(),
        });
    }

    // Страховка: mode 0600 независимо от того, сохранил ли cryptsetup его.
    fs::set_permissions(backup, std::fs::Permissions::from_mode(0o600))
        .await
        .map_err(Error::Io)?;

    Ok(warning)
}

/// Одна и та же ли ФС у двух путей (по `stat -f -c %T`).
async fn same_filesystem(a: &Path, b: &Path) -> Result<bool> {
    let fs_a = fs_type(a).await?;
    let fs_b = fs_type(b).await?;
    Ok(fs_a == fs_b && !fs_a.is_empty())
}

async fn fs_type(path: &Path) -> Result<String> {
    let output = Command::new("stat")
        .args(["-f", "-c", "%T"])
        .arg(path)
        .output()
        .await
        .map_err(Error::Io)?;
    if !output.status.success() {
        return Err(Error::Command {
            cmd: format!("stat -f -c %T {}", path.display()),
            status: output.status.to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
