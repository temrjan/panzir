//! Жизненный цикл СУЩЕСТВУЮЩЕГО хранилища: открыть, закрыть, узнать состояние.
//!
//! `create.rs` владеет одноразовым событием — созданием контейнера. Здесь
//! живут повторяемые операции: те, что пользователь делает каждый день.
//!
//! Модуль не трогает реестр (`registry.rs`). Причины две, обе несущие:
//! запись в реестр идёт под advisory-локом, а держать лок всё время закрытия
//! (в худшем случае ≈ 52 с) нельзя — второй экземпляр приложения всё это
//! время получал бы «уже запущено»; и тесты не должны писать в боевой
//! `~/.config/panzir/vaults.toml`. Факт возвращается наружу, запись делает
//! вызывающий.

use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::udisks::{ObjPath, Udisks};
use crate::vault::Label;
use crate::{Error, Result};

/// Хранилище открыто: объекты udisks2 и фактическая точка монтирования.
#[derive(Debug, Clone)]
pub struct OpenedVault {
    /// Объект loop-устройства.
    pub loop_object: ObjPath,
    /// Объект расшифрованного устройства (dm-crypt).
    pub cleartext_object: ObjPath,
    /// Фактическая точка монтирования (сообщена udisks2, не угадана).
    pub mount_point: PathBuf,
    /// `true` — loop уже существовал, мы его переиспользовали;
    /// `false` — loop подняли мы сами в этом вызове.
    ///
    /// Различие не выводится из `SetupByUID`: он отвечает на вопрос «чей
    /// ПОЛЬЗОВАТЕЛЬ», и хранилище, подключённое другой программой под тем же
    /// пользователем (например, штатной утилитой дисков), отдаёт тот же uid.
    /// Здесь фиксируется именно происхождение — восстановить его позже нечем.
    pub loop_was_reused: bool,
}

/// Фактическое состояние контейнера — что о нём знает система прямо сейчас.
///
/// Каждый вариант требует своей реакции при открытии; меньше вариантов
/// означало бы, что часть случаев обрабатывается угадыванием.
#[derive(Debug, Clone)]
pub enum VaultProbe {
    /// Файл не подключён ни к одному loop-устройству.
    Detached,
    /// Подключён нашим uid, том заперт.
    AttachedLocked {
        /// Объект loop-устройства.
        loop_object: ObjPath,
    },
    /// Подключён нашим uid, отперт, но не смонтирован.
    AttachedUnlocked {
        /// Объект loop-устройства.
        loop_object: ObjPath,
        /// Объект расшифрованного устройства.
        cleartext_object: ObjPath,
    },
    /// Подключён нашим uid, отперт и смонтирован.
    AttachedOpen {
        /// Объект loop-устройства.
        loop_object: ObjPath,
        /// Объект расшифрованного устройства.
        cleartext_object: ObjPath,
        /// Фактическая точка монтирования.
        mount_point: PathBuf,
    },
    /// Подключён под ДРУГИМ uid. Трогать нельзя: второй loop на тот же файл —
    /// это две dm-crypt поверх одного LUKS-тома.
    Foreign {
        /// Объект loop-устройства.
        loop_object: ObjPath,
        /// Владелец существующего loop.
        uid: u32,
    },
}

/// Узнать фактическое состояние контейнера.
///
/// Спрашивает систему, а не реестр: после падения приложения запись в реестре
/// может врать, а loop-устройства и точки монтирования — нет.
///
/// # Errors
/// - [`Error::ContainerMissing`] — файла контейнера нет на диске;
/// - [`Error::MultipleLoopsAttached`] — на файле больше одного loop (порча);
/// - ошибки udisks2/D-Bus пробрасываются как есть.
pub async fn probe_file_vault(ud: &Udisks, container: &Path) -> Result<VaultProbe> {
    if !tokio::fs::try_exists(container).await.map_err(Error::Io)? {
        return Err(Error::ContainerMissing {
            path: container.display().to_string(),
        });
    }

    let mut loops = crate::udisks::find_loops_for_backing_file(container)?.into_iter();
    let Some(loop_object) = loops.next() else {
        return Ok(VaultProbe::Detached);
    };
    let extra = loops.count();
    if extra > 0 {
        return Err(Error::MultipleLoopsAttached {
            path: container.display().to_string(),
            count: extra + 1,
        });
    }

    let uid = ud.loop_setup_by_uid(&loop_object).await?;
    if uid != crate::udisks::current_uid() {
        return Ok(VaultProbe::Foreign { loop_object, uid });
    }

    // «Заперто» — ТОЛЬКО типизированный сентинел. Любая другая ошибка
    // (шина отвалилась, объект пропал) — не «заперто»: трактовать её так
    // значит уверенно соврать о состоянии хранилища.
    let cleartext_object = match ud.cleartext_device(&loop_object).await {
        Ok(obj) => obj,
        Err(Error::VolumeLocked { .. }) => {
            return Ok(VaultProbe::AttachedLocked { loop_object });
        }
        Err(e) => return Err(e),
    };

    match ud
        .mount_points(&cleartext_object)
        .await?
        .into_iter()
        .next()
    {
        Some(mount_point) => Ok(VaultProbe::AttachedOpen {
            loop_object,
            cleartext_object,
            mount_point,
        }),
        None => Ok(VaultProbe::AttachedUnlocked {
            loop_object,
            cleartext_object,
        }),
    }
}

/// Открыть существующее хранилище: до смонтированного тома и симлинка.
///
/// Идемпотентна: на уже открытом хранилище возвращает его же, второго
/// loop-устройства не поднимает.
///
/// # Errors
/// - [`Error::ContainerMissing`] — файла нет;
/// - [`Error::VaultAlreadyAttached`] — контейнер держит другой пользователь;
/// - [`Error::MultipleLoopsAttached`] — порча: два loop на одном файле;
/// - ошибки udisks2 (неверная парольная фраза приходит от `Unlock`).
///
/// При ошибке после того, как loop подняли МЫ, он отвязывается здесь же:
/// иначе каждая опечатка в парольной фразе оставляла бы зомби-устройство.
/// Loop, который уже существовал, не трогаем — мы его не поднимали.
pub async fn open_file_vault(
    ud: &Udisks,
    container: &Path,
    label: &Label,
    passphrase: &SecretString,
    home: &Path,
) -> Result<OpenedVault> {
    match probe_file_vault(ud, container).await? {
        VaultProbe::Foreign { uid, .. } => Err(Error::VaultAlreadyAttached {
            path: container.display().to_string(),
            uid,
        }),

        // Ветки Attached*: loop подняли не мы → loop_was_reused = true,
        // и при ошибке мы его не отвязываем.
        VaultProbe::AttachedOpen {
            loop_object,
            cleartext_object,
            mount_point,
        } => {
            crate::mountpoint::create_symlink(home, label, &mount_point).await?;
            Ok(OpenedVault {
                loop_object,
                cleartext_object,
                mount_point,
                loop_was_reused: true,
            })
        }

        VaultProbe::AttachedUnlocked {
            loop_object,
            cleartext_object,
        } => {
            let mount_point = ud.mount_noexec(&cleartext_object).await?;
            crate::mountpoint::create_symlink(home, label, &mount_point).await?;
            Ok(OpenedVault {
                loop_object,
                cleartext_object,
                mount_point,
                loop_was_reused: true,
            })
        }

        VaultProbe::AttachedLocked { loop_object } => {
            let cleartext_object = ud.unlock(&loop_object, passphrase).await?;
            let mount_point = ud.mount_noexec(&cleartext_object).await?;
            crate::mountpoint::create_symlink(home, label, &mount_point).await?;
            Ok(OpenedVault {
                loop_object,
                cleartext_object,
                mount_point,
                loop_was_reused: true,
            })
        }

        // Единственная ветка, где loop поднимаем МЫ → loop_was_reused = false,
        // и только здесь действует уборка при ошибке.
        VaultProbe::Detached => {
            let file = tokio::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(container)
                .await
                .map_err(Error::Io)?
                .into_std()
                .await;

            let loop_object = ud.loop_setup(file).await?;

            let result = async {
                let cleartext_object = ud.unlock(&loop_object, passphrase).await?;
                let mount_point = ud.mount_noexec(&cleartext_object).await?;
                crate::mountpoint::create_symlink(home, label, &mount_point).await?;
                Ok(OpenedVault {
                    loop_object: loop_object.clone(),
                    cleartext_object,
                    mount_point,
                    loop_was_reused: false,
                })
            }
            .await;

            match result {
                Ok(opened) => Ok(opened),
                Err(source) => {
                    // Наш loop — наша уборка. Исходная ошибка важнее ошибки
                    // уборки, поэтому вторая только логируется.
                    if let Err(e) = ud.ensure_loop_detached(&loop_object).await {
                        tracing::warn!("open_file_vault: cleanup after error: {e}");
                    }
                    Err(source)
                }
            }
        }
    }
}

/// Закрыть хранилище, ОСТАВИВ файл контейнера на месте.
///
/// Отличие от [`crate::create::teardown_file_container`] ровно одно: та
/// удаляет файл (уборка тестового контейнера), эта — не трогает его никогда.
/// Общий путь у них один и тот же, чтобы не разойтись.
///
/// # Errors
/// [`Error::UnexpectedUdisksState`], если loop не удалось отвязать; ошибки
/// udisks2 при размонтировании/запирании — как есть.
pub async fn close_file_vault(
    ud: &Udisks,
    loop_object: &ObjPath,
    label: &Label,
    home: &Path,
) -> Result<()> {
    let close_result = ud.close_encrypted(loop_object).await;
    let detach_result = ud.ensure_loop_detached(loop_object).await;

    match (close_result, detach_result) {
        // Loop отвязан — том закрыт фактически, что бы ни ответил close.
        (_, Ok(())) => {
            crate::mountpoint::remove_symlink(home, label).await?;
            Ok(())
        }
        // Не отвязан: исходная причина информативнее «stale loop».
        (Err(source), Err(_)) => Err(source),
        (Ok(()), Err(detach)) => Err(detach),
    }
}
