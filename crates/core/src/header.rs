//! Бэкап LUKS-заголовка.
//!
//! Файл-контейнер — `cryptsetup luksHeaderBackup` без root.
//! Флешка — `pkexec sh -c 'cryptsetup ... && chown'` (один системный диалог
//! polkit); результат chown'ится текущему пользователю, чтобы читался без root.
//! udisks2 `Encrypted.HeaderBackup` не используем: он создаёт файл 0400 root
//! (план §4.5).

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::fs;
use tokio::process::Command;

use crate::keyslot::TempKeyfile;
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

    // Создаём родительский каталог ДО same_filesystem: stat -f по несуществующему
    // пути упадёт (Б-10). Права выставляем только если каталог создали мы (С-4).
    let parent_existed = fs::metadata(parent).await.is_ok();
    if !parent_existed {
        fs::create_dir_all(parent).await.map_err(Error::Io)?;
        fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(Error::Io)?;
    }

    let same_fs = same_filesystem(source, parent).await?;
    let warning = same_fs.then_some(HeaderBackupWarning::SameFilesystem);

    if use_pkexec {
        backup_header_device(source, backup, passphrase).await?;
    } else {
        backup_header_file(source, backup, passphrase).await?;
    }

    // Страховка: mode 0600 независимо от того, сохранил ли cryptsetup его.
    fs::set_permissions(backup, std::fs::Permissions::from_mode(0o600))
        .await
        .map_err(Error::Io)?;

    Ok(warning)
}

async fn backup_header_file(source: &Path, backup: &Path, passphrase: &Passphrase) -> Result<()> {
    let mut cmd = Command::new("cryptsetup");
    cmd.arg("luksHeaderBackup")
        .arg("--header-backup-file")
        .arg(backup)
        .arg("--key-file")
        .arg("-")
        .arg(source)
        .stdin(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().map_err(Error::Io)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::Io(std::io::Error::other("stdin not piped")))?;
    passphrase.write_to_stdin(&mut stdin).await?;

    let status = match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => return Err(Error::Io(e)),
        Err(_) => {
            let _ = child.kill().await;
            return Err(Error::Command {
                cmd: format!(
                    "cryptsetup luksHeaderBackup {} {}",
                    source.display(),
                    backup.display()
                ),
                status: "timeout".to_owned(),
            });
        }
    };
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
    Ok(())
}

async fn current_id(name: &str) -> Result<String> {
    let output = Command::new("id")
        .arg(name)
        .output()
        .await
        .map_err(Error::Io)?;
    if !output.status.success() {
        return Err(Error::Command {
            cmd: format!("id {name}"),
            status: output.status.to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

async fn backup_header_device(source: &Path, backup: &Path, passphrase: &Passphrase) -> Result<()> {
    // pkexec cryptsetup создаёт файл 0400 root; в том же вызове chown'им его
    // текущему пользователю, чтобы результат остался читаемым (Б-11).
    let keyfile = TempKeyfile::from_passphrase(passphrase).await?;
    let uid = current_id("-u").await?;
    let gid = current_id("-g").await?;

    let mut cmd = Command::new("pkexec");
    cmd.arg("sh")
        .arg("-c")
        .arg("cryptsetup luksHeaderBackup --header-backup-file \"$1\" --key-file \"$2\" \"$3\" && chown \"$4:$5\" \"$1\"")
        .arg("_")
        .arg(backup)
        .arg(keyfile.path())
        .arg(source)
        .arg(&uid)
        .arg(&gid)
        .kill_on_drop(true);

    let status = cmd.status().await.map_err(Error::Io)?;
    if !status.success() {
        return Err(Error::Command {
            cmd: format!(
                "pkexec cryptsetup luksHeaderBackup {} {}",
                source.display(),
                backup.display()
            ),
            status: status.to_string(),
        });
    }
    Ok(())
}

/// Одна и та же ли ФС у двух путей (по `stat -f -c %T`).
async fn same_filesystem(a: &Path, b: &Path) -> Result<bool> {
    let fs_a = fs_type(a).await?;
    let fs_b = fs_type(b).await?;
    Ok(fs_a == fs_b && !fs_a.is_empty())
}

async fn fs_type(path: &Path) -> Result<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("stat")
            .args(["-f", "-c", "%T"])
            .arg(path)
            .output(),
    )
    .await
    .map_err(|_| Error::Command {
        cmd: format!("stat -f -c %T {}", path.display()),
        status: "timeout".to_owned(),
    })?
    .map_err(Error::Io)?;
    if !output.status.success() {
        return Err(Error::Command {
            cmd: format!("stat -f -c %T {}", path.display()),
            status: output.status.to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
