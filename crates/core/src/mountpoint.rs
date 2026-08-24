//! Симлинки `~/panzir-<метка>` на фактические точки монтирования.
//!
//! Правила (спека п.3):
//! - симлинк создаётся только если целевого пути нет или он уже наш симлинк;
//! - чужой путь (`~/panzir-x`, обычный файл/каталог) не перезаписывается;
//! - симлинк указывает на точку монтирования из udisks2, а не на угаданный путь;
//! - при закрытии/отключении симлинк снимается.

use std::path::{Path, PathBuf};

use tokio::fs;

use crate::vault::Label;
use crate::{Error, Result};

/// Путь симлинка `~/panzir-<метка>`.
///
/// Каноническая функция построения пути; [`Vault::symlink_path`] — обёртка.
pub fn symlink_path(home: &Path, label: &Label) -> PathBuf {
    home.join(format!("panzir-{label}"))
}

/// Создать симлинк, указывающий на фактическую точку монтирования.
///
/// # Errors
/// - [`Error::Io`] — ошибка FS.
/// - [`Error::UnexpectedUdisksState`] — целевой путь существует и не наш симлинк.
pub async fn create_symlink(home: &Path, label: &Label, mount_point: &Path) -> Result<()> {
    let link = symlink_path(home, label);

    if let Ok(meta) = fs::symlink_metadata(&link).await {
        // Путь существует. Если это симлинк и указывает туда же — идемпотентно.
        if meta.is_symlink() {
            let current = fs::read_link(&link).await.map_err(Error::Io)?;
            if current == mount_point {
                return Ok(());
            }
        }
        return Err(Error::UnexpectedUdisksState(format!(
            "symlink path {} already exists and is not ours",
            link.display()
        )));
    }

    fs::symlink(mount_point, &link).await.map_err(Error::Io)?;
    Ok(())
}

/// Удалить симлинк.
///
/// Удаляем только если basename совпадает с `panzir-<label>` — target при
/// закрытом/отключённом томе уже может не существовать.
pub async fn remove_symlink(home: &Path, label: &Label) -> Result<()> {
    let link = symlink_path(home, label);

    match fs::symlink_metadata(&link).await {
        Ok(meta) if meta.is_symlink() => {
            fs::remove_file(&link).await.map_err(Error::Io)?;
            Ok(())
        }
        Ok(_) => Err(Error::UnexpectedUdisksState(format!(
            "{} exists but is not a symlink; refusing to remove",
            link.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Прочитать куда указывает симлинк.
pub async fn read_symlink(home: &Path, label: &Label) -> Result<PathBuf> {
    let link = symlink_path(home, label);
    fs::read_link(&link).await.map_err(Error::Io)
}
