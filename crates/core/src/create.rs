//! Мастер создания файл-контейнера (спека v1.1, п.1 скоупа).
//!
//! Порядок обязателен (план §4.8): на btrfs `chattr +C` ставится на ПУСТОЙ
//! файл, до наполнения — иначе CoW уже включён для существующих экстентов.
//! Аллокация полная (fallocate), sparse запрещён.

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::mountpoint;
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
/// Все системные шаги могут упасть: см. [`Error`]. При любой ошибке до
/// поднятия loop-устройства файл удаляется здесь. При ошибке после поднятия
/// loop уборку выполняет [`teardown_file_container`], которая удаляет файл
/// только после подтверждения отвязки loop от sysfs. Исходная ошибка
/// возвращается наружу в любом случае.
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

    match prepare_and_format(ud, file, path, size_bytes, on_btrfs, label, passphrase).await {
        Ok(created) => Ok(created),
        Err(SetupError::BeforeLoop { source }) => {
            // loop ещё не был создан — безопасно удалить файл здесь.
            if let Err(e) = tokio::fs::remove_file(path).await {
                tracing::warn!(
                    "create_file_container: failed to remove {}: {e}",
                    path.display()
                );
            }
            Err(source)
        }
        Err(SetupError::AfterLoop { source, .. }) => Err(source),
    }
}

/// Ошибка создания с фазой, на которой она произошла: до или после поднятия
/// loop-устройства. Фаза определяет, кто и когда может удалить файл контейнера.
enum SetupError {
    BeforeLoop { source: Error },
    AfterLoop { source: Error },
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
) -> std::result::Result<CreatedVault, SetupError> {
    if on_btrfs {
        // +C на пустой файл, ДО fallocate (план §4.8).
        if let Err(e) = run("chattr", &[OsStr::new("+C"), path.as_os_str()]).await {
            return Err(SetupError::BeforeLoop { source: e });
        }
    }
    if let Err(e) = run(
        "fallocate",
        &[
            OsStr::new("-l"),
            OsStr::new(&size_bytes.to_string()),
            path.as_os_str(),
        ],
    )
    .await
    {
        return Err(SetupError::BeforeLoop { source: e });
    }

    let loop_object = match ud.loop_setup(file).await {
        Ok(lo) => lo,
        Err(e) => return Err(SetupError::BeforeLoop { source: e }),
    };

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

    match result {
        Ok(created) => Ok(created),
        Err(source) => {
            // loop уже создан — уборку и удаление файла делает teardown_file_container.
            if let Err(e) = teardown_file_container(ud, &loop_object, path).await {
                tracing::warn!("prepare_and_format: teardown after error: {e}");
            }
            Err(SetupError::AfterLoop { source })
        }
    }
}

/// Убрать файл-контейнер: закрыть зашифрованный том, отвязать loop,
/// дождаться исчезновения из sysfs и только потом удалить файл.
/// Публичная для интеграционных тестов, но скрыта из API крейта.
#[doc(hidden)]
pub async fn teardown_file_container(
    ud: &Udisks,
    loop_object: &ObjPath,
    container: &Path,
) -> Result<()> {
    // 1. Оркестрированное закрытие (close_encrypted делает unmount/lock/retries).
    if let Err(e) = ud.close_encrypted(loop_object).await {
        tracing::warn!("teardown: close_encrypted failed: {e}");
    }

    // 2-3. Подтолкнуть Delete, если autoclear не сработал, и дождаться
    // исчезновения из sysfs. Общий шаг с продуктовым закрытием
    // (`lifecycle::close_file_vault`) — разойтись в нём два вызывающих
    // не имеют права.
    //
    // Успех этого шага УЖЕ означает, что loop исчез из sysfs, — повторно
    // спрашивать ядро незачем (М-9 ревью раунда 1).
    if let Err(e) = ud.ensure_loop_detached(loop_object).await {
        tracing::warn!("teardown: ensure_loop_detached: {e}");
        return Err(Error::UnexpectedUdisksState(format!(
            "stale loop device left for {loop_object}; refusing to remove {}",
            container.display()
        )));
    }

    // 4. Только после подтверждения отвязки удаляем файл.
    match tokio::fs::remove_file(container).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => {
            tracing::warn!("teardown: failed to remove {}: {e}", container.display());
            Err(Error::from(e))
        }
    }
}

/// Создаёт родительскую папку контейнера (`~/.local/share/panzir/`) с правами
/// 0700, если её ещё нет. Образец — `Registry::with_write_lock_at`
/// (`registry.rs`): та же пара `create_dir_all` + `set_permissions`.
async fn ensure_container_dir(container: &Path) -> Result<()> {
    let parent = container
        .parent()
        .ok_or_else(|| Error::InvalidContainerPath(container.display().to_string()))?;
    tokio::fs::create_dir_all(parent).await.map_err(Error::Io)?;
    tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(Error::Io)?;
    Ok(())
}

/// Создаёт файл-хранилище целиком: папка 0700 → контейнер (ядро возвращает его
/// открытым и смонтированным) → симлинк `~/panzir-<метка>`.
///
/// Симлинк ядро внутри `create_file_container` не делает (в отличие от
/// открытия) — поэтому шаг здесь. При отказе на нём — откат
/// ([`rollback_created_file_vault`]): иначе остался бы живой расшифрованный
/// смонтированный том без записи в реестре, который приложение не может закрыть.
/// Полный откат обязан жить в ядре: `ensure_loop_detached` — `pub(crate)`.
///
/// # Errors
/// Любой шаг может упасть — см. [`Error`]; при отказе симлинка том уже откачен.
pub async fn create_file_vault(
    ud: &Udisks,
    home: &Path,
    label: &Label,
    container: &Path,
    size_bytes: u64,
    passphrase: &SecretString,
) -> Result<CreatedVault> {
    ensure_container_dir(container).await?;
    let created = create_file_container(ud, container, size_bytes, label, passphrase).await?;
    if let Err(e) = mountpoint::create_symlink(home, label, &created.mount_point).await {
        rollback_created_file_vault(ud, home, label, &created.loop_object, container).await;
        return Err(e);
    }
    Ok(created)
}

/// Откат неудавшегося создания: снять симлинк, закрыть том, отвязать loop.
/// Best-effort — вызывается уже на ошибке, поэтому шаги логируются, но не
/// прерывают друг друга.
///
/// **Файл контейнера НЕ удаляет.** Удалять ли осиротевший файл (которого
/// пользователь не видел зарегистрированным) — открытый вопрос Капитану,
/// дефолт «оставить». При «удалять» здесь добавляется `remove_file(container)`
/// ПОСЛЕ подтверждённой отвязки loop (как в [`teardown_file_container`]),
/// поэтому `container` уже в сигнатуре.
pub async fn rollback_created_file_vault(
    ud: &Udisks,
    home: &Path,
    label: &Label,
    loop_object: &ObjPath,
    _container: &Path,
) {
    if let Err(e) = mountpoint::remove_symlink(home, label).await {
        tracing::warn!("rollback_create: remove_symlink: {e}");
    }
    if let Err(e) = ud.close_encrypted(loop_object).await {
        tracing::warn!("rollback_create: close_encrypted: {e}");
    }
    if let Err(e) = ud.ensure_loop_detached(loop_object).await {
        tracing::warn!("rollback_create: ensure_loop_detached: {e}");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// Папка контейнера создаётся с правами 0700 (не дефолт 0755) — проверяемо
    /// без udisks2, ради этого mkdir+chmod и живёт в ядре, а не в `crates/gui`.
    #[tokio::test]
    async fn ensure_container_dir_creates_parent_0700() {
        let home = tempfile::tempdir().expect("временный каталог");
        let container = home.path().join(".local/share/panzir/work.vault");
        ensure_container_dir(&container)
            .await
            .expect("создать папку");
        let mode = std::fs::metadata(container.parent().expect("родитель"))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "папка контейнера не 0700");
    }
}
