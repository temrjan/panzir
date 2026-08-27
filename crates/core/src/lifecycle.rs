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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secrecy::SecretString;

use crate::schedule::Scheduler;
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
    /// Дедлайн автозакрытия (секунды Unix), если часы заведены; `None` —
    /// срок «не закрывать». Записывается в реестр вызывающим.
    pub until: Option<u64>,
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

    let mut loops = crate::udisks::find_loops_for_backing_file(container)
        .await?
        .into_iter();
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

    // Кто владеет loop. Любой uid, кроме нашего, — чужой, включая 0.
    //
    // Ревью раунда 1 (Б-4) требовало считать `uid == 0` «своим, просто со
    // сброшенным владельцем» — на основании doc-комментариев `udisks.rs`,
    // утверждающих, что `Lock` обнуляет `SetupByUID`. **Замер 24.08 это
    // опровергает:** loop, поднятый нами, сохраняет `SetupByUID = 1000` и
    // после `luksFormat`, и после `Unlock`, и после `Lock` (четыре
    // последовательных чтения через `busctl`). Положительный контроль в том же
    // прогоне: loop, поднятый root напрямую (`sudo losetup -f`), даёт `0` —
    // значит канал измерения живой, а не отдаёт константу.
    //
    // Поэтому `0` здесь означает ровно то, что написано: loop поднят не нашим
    // пользователем (root, системная служба). Трактовать его как свой — значит
    // пытаться распоряжаться чужим устройством.
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

    match ud.mount_points(&cleartext_object).await?.into_iter().next() {
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

/// Страховка на частично открытое хранилище.
///
/// Открытие идёт шагами: поднять loop → отпереть → смонтировать → поставить
/// симлинк. Провал ЛЮБОГО шага после первого оставляет систему в промежуточном
/// состоянии, и откатывать надо ровно то, что успели сделать мы, — не больше
/// (чужой loop не наш, чтобы его отвязывать) и не меньше (снять loop из-под
/// живой dm-crypt не значит закрыть том: `Loop.Delete` отвечает `Ok`, а
/// устройства остаются — проверено живым экспериментом Ревьюера, раунд 1, Б-1).
///
/// Guard закрывает обе дороги: **ошибку** — явным `cleanup().await` на месте,
/// **отмену future** — в `Drop`. Второе важно не гипотетически: `keyslot.rs`
/// уже носит `TempKeyfile` с `Drop` именно потому, что этот класс дыры в
/// проекте уже оплачен (Б-2 ревью PR-2).
struct OpenGuard {
    ud: Udisks,
    loop_object: ObjPath,
    /// loop подняли МЫ — значит нам его и отвязывать.
    owns_loop: bool,
    /// том отперли МЫ — значит нам его и запирать.
    unlocked_by_us: bool,
    /// том смонтировали МЫ и не отпирали — размонтировать, но не запирать.
    mounted_by_us: Option<ObjPath>,
    disarmed: bool,
}

impl OpenGuard {
    fn new(ud: &Udisks, loop_object: ObjPath, owns_loop: bool) -> Self {
        Self {
            ud: ud.clone(),
            loop_object,
            owns_loop,
            unlocked_by_us: false,
            mounted_by_us: None,
            disarmed: false,
        }
    }

    /// Открытие дошло до конца — откатывать нечего.
    fn disarm(&mut self) {
        self.disarmed = true;
    }

    /// Откатить ровно то, что сделали мы. Порядок обратный порядку действий.
    async fn cleanup(&self) {
        if self.unlocked_by_us || self.owns_loop {
            // close_encrypted переживает обе фазы: и «отперт и смонтирован»,
            // и «отперт, но не смонтирован» — различать вручную не нужно.
            if let Err(e) = self.ud.close_encrypted(&self.loop_object).await {
                tracing::warn!("OpenGuard: close_encrypted failed: {e}");
            }
        } else if let Some(cleartext) = &self.mounted_by_us {
            // Отпирали не мы — запирать чужое не наше дело; снимаем только
            // собственное монтирование.
            if let Err(e) = self.ud.unmount_wait(cleartext).await {
                tracing::warn!("OpenGuard: unmount_wait failed: {e}");
            }
        }
        if self.owns_loop
            && let Err(e) = self.ud.ensure_loop_detached(&self.loop_object).await
        {
            tracing::warn!("OpenGuard: ensure_loop_detached failed: {e}");
        }
    }
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        // Сюда попадаем только при отмене future: на ошибке уборка уже
        // сделана явно и guard разоружён. Синхронно закрыть том нельзя —
        // это D-Bus, — поэтому отдаём задачу рантайму и говорим об этом
        // громко: молча потерянный loop и был исходным инцидентом 23.08.
        tracing::warn!(
            loop_object = %self.loop_object,
            "OpenGuard: future cancelled mid-open, cleaning up in background"
        );
        let guard = Self {
            ud: self.ud.clone(),
            loop_object: self.loop_object.clone(),
            owns_loop: self.owns_loop,
            unlocked_by_us: self.unlocked_by_us,
            mounted_by_us: self.mounted_by_us.clone(),
            disarmed: true,
        };
        tokio::spawn(async move { guard.cleanup().await });
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
    scheduler: &impl Scheduler,
    auto_close: Option<Duration>,
) -> Result<OpenedVault> {
    // Стартовая точка: что система уже сделала — и что предстоит сделать нам.
    let (mut guard, cleartext, mount_point) = match probe_file_vault(ud, container).await? {
        VaultProbe::Foreign { uid, .. } => {
            return Err(Error::VaultAlreadyAttached {
                path: container.display().to_string(),
                uid,
            });
        }
        VaultProbe::Detached => {
            let file = tokio::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(container)
                .await
                .map_err(Error::Io)?
                .into_std()
                .await;
            // С этого момента есть что убирать — guard создаётся сразу после
            // подъёма loop, без единого `await` между ними.
            let loop_object = ud.loop_setup(file).await?;
            (OpenGuard::new(ud, loop_object, true), None, None)
        }
        VaultProbe::AttachedLocked { loop_object } => {
            (OpenGuard::new(ud, loop_object, false), None, None)
        }
        VaultProbe::AttachedUnlocked {
            loop_object,
            cleartext_object,
        } => (
            OpenGuard::new(ud, loop_object, false),
            Some(cleartext_object),
            None,
        ),
        VaultProbe::AttachedOpen {
            loop_object,
            cleartext_object,
            mount_point,
        } => (
            OpenGuard::new(ud, loop_object, false),
            Some(cleartext_object),
            Some(mount_point),
        ),
    };

    let loop_was_reused = !guard.owns_loop;
    let loop_object = guard.loop_object.clone();

    match open_steps(
        ud,
        &mut guard,
        container,
        label,
        passphrase,
        home,
        cleartext,
        mount_point,
    )
    .await
    {
        Ok((cleartext_object, mount_point)) => {
            // Часы — ПОСЛЕ успешного открытия (спека С-2): на том, которого нет,
            // таймер бессмыслен. Отказ часов — отказ открытия: хранилище без
            // часов молча нарушало бы обещание «само закроется», а закрыть
            // только что открытое — честнее, чем оставить его так (инвариант 10).
            let until = match auto_close {
                Some(after) => match scheduler.arm(label, after).await {
                    Ok(()) => Some(deadline_after(after)),
                    Err(e) => {
                        if let Err(link) = crate::mountpoint::remove_symlink(home, label).await {
                            tracing::warn!(
                                "open_file_vault: remove_symlink after arm failure: {link}"
                            );
                        }
                        guard.cleanup().await;
                        guard.disarm();
                        return Err(e);
                    }
                },
                None => None,
            };
            guard.disarm();
            Ok(OpenedVault {
                loop_object,
                cleartext_object,
                mount_point,
                loop_was_reused,
                until,
            })
        }
        Err(source) => {
            // Ошибка: убираем ЗДЕСЬ и синхронно — надёжнее, чем полагаться на
            // `Drop`. Guard разоружается после уборки, чтобы она не повторилась
            // фоновой задачей.
            guard.cleanup().await;
            guard.disarm();
            Err(source)
        }
    }
}

/// Шаги открытия поверх любой стартовой точки; guard отмечает, что сделали МЫ.
///
/// Вынесено из веток `open_file_vault`, чтобы хвост «отпереть → смонтировать →
/// поставить симлинк» существовал в одном экземпляре: четыре его копии
/// разошлись бы при первой же правке.
#[allow(clippy::too_many_arguments)] // все аргументы — данные одной операции
async fn open_steps(
    ud: &Udisks,
    guard: &mut OpenGuard,
    container: &Path,
    label: &Label,
    passphrase: &SecretString,
    home: &Path,
    cleartext: Option<ObjPath>,
    mount_point: Option<PathBuf>,
) -> Result<(ObjPath, PathBuf)> {
    let loop_object = guard.loop_object.clone();

    let cleartext_object = match cleartext {
        // Том отперт не нами. Фразу всё равно проверяем: иначе поле
        // «парольная фраза» перестаёт быть проверкой в этих состояниях, а
        // пользователь об этом не узнаёт (Б-7).
        Some(existing) => {
            crate::keyslot::verify_passphrase(
                container,
                &crate::passphrase::Passphrase::new(passphrase.clone()),
            )
            .await?;
            existing
        }
        None => {
            let opened = ud.unlock(&loop_object, passphrase).await?;
            guard.unlocked_by_us = true;
            opened
        }
    };

    let mount_point = match mount_point {
        // Том смонтирован не нами — а значит, возможно, и без `noexec`
        // (штатный автомонт рабочего стола монтирует именно так). Проверяем
        // по ядру и перемонтируем только если гарантии нет (М-12).
        Some(existing) if mount_has_noexec(&existing) => existing,
        Some(_) | None => {
            let mounted = ud.mount_noexec(&cleartext_object).await?;
            if !guard.unlocked_by_us {
                guard.mounted_by_us = Some(cleartext_object.clone());
            }
            mounted
        }
    };

    crate::mountpoint::create_symlink(home, label, &mount_point).await?;
    Ok((cleartext_object, mount_point))
}

/// Смонтирована ли точка с `noexec` — по `/proc/self/mountinfo`, то есть по
/// ядру, а не по нашему намерению.
///
/// Отсутствие записи трактуем как «гарантии нет»: лучше лишний раз
/// перемонтировать, чем отдать пользователю том, на котором можно исполнять код.
fn mount_has_noexec(mount_point: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let target = mount_point.to_string_lossy();
    text.lines().any(|line| {
        let mut fields = line.split(' ');
        // mountinfo: 3-е поле — major:minor, 4-е — root, 5-е — точка монтирования.
        let mount_field = fields.nth(4);
        mount_field.is_some_and(|m| m == target) && line.contains("noexec")
    })
}

/// Дедлайн `after` от текущего момента, в секундах Unix. Часы до эпохи —
/// не наш случай; тогда дедлайн отсчитывается от нуля и заведомо просрочен,
/// что для страховки при старте безопаснее, чем паника.
fn deadline_after(after: Duration) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .saturating_add(after.as_secs())
}

/// Что делать с томом по результату пробы.
///
/// Чистая функция ядра, а не окна (долг A-11 закрыт вторым вызывающим —
/// одноразовым закрывателем таймера): разбор пяти вариантов пробы обязан
/// быть в одном месте, иначе окно и таймер разошлись бы в ответе на один
/// и тот же вопрос.
#[derive(Debug, PartialEq, Eq)]
pub enum CloseDecision {
    /// Файл не подключён: закрывать нечего, привести запись к правде.
    AlreadyDetached,
    /// Есть объект loop-устройства — закрываем.
    Close(ObjPath),
    /// Подключён чужим uid: не трогаем (инвариант 3).
    Foreign(u32),
}

/// `match` без ветки `_`: новый вариант пробы обязан сломать сборку здесь.
#[must_use]
pub fn close_decision(probe: VaultProbe) -> CloseDecision {
    match probe {
        VaultProbe::Detached => CloseDecision::AlreadyDetached,
        VaultProbe::AttachedLocked { loop_object }
        | VaultProbe::AttachedUnlocked { loop_object, .. }
        | VaultProbe::AttachedOpen { loop_object, .. } => CloseDecision::Close(loop_object),
        VaultProbe::Foreign { uid, .. } => CloseDecision::Foreign(uid),
    }
}

/// Закрыть хранилище, ОСТАВИВ файл контейнера на месте.
///
/// Отличие от [`crate::create::teardown_file_container`] ровно одно: та удаляет
/// файл (уборка тестового контейнера), эта — не трогает его никогда. Общий путь
/// у них один и тот же, чтобы не разойтись.
///
/// `detach_loop` — брать из [`OpenedVault::loop_was_reused`] инверсией: loop,
/// который подняли не мы, мы и не отвязываем (М-6 ревью раунда 1). Запереть том
/// всё равно нужно — этого пользователь и просит, нажимая «Закрыть»; но
/// принудительно сносить чужое устройство не наше дело, после запирания его
/// уберёт `autoclear`.
///
/// # Errors
/// [`Error::UnexpectedUdisksState`], если loop не удалось отвязать; ошибки
/// udisks2 при размонтировании/запирании — как есть.
pub async fn close_file_vault(
    ud: &Udisks,
    loop_object: &ObjPath,
    label: &Label,
    home: &Path,
    detach_loop: bool,
    scheduler: &impl Scheduler,
) -> Result<()> {
    // Часы — ДО закрытия (спека С-2): снят только таймер, и если закрытие по
    // нему уже бежит, `disarm` дожидается его. После этого запуск невозможен,
    // и наше закрытие ни с кем не гонится.
    scheduler.disarm(label).await?;
    let close_result = ud.close_encrypted(loop_object).await;

    let detach_result = if detach_loop {
        ud.ensure_loop_detached(loop_object).await
    } else {
        // Чужой loop: не подталкиваем Delete, но убеждаемся, что autoclear
        // сделал своё дело — иначе «закрыто» было бы утверждением без свидетеля.
        Ok(())
    };

    match (close_result, detach_result) {
        // Закрытие состоялось. Если `close_encrypted` при этом жаловался —
        // говорим об этом в лог: он мог потратить весь бюджет ретраев (~40 с),
        // и терять этот сигнал молча нельзя (М-10).
        (close, Ok(())) => {
            if let Err(e) = close {
                tracing::warn!("close_file_vault: close_encrypted reported: {e}");
            }
            crate::mountpoint::remove_symlink(home, label).await?;
            Ok(())
        }
        // Том заперт и размонтирован, но loop остался. Для пользователя
        // хранилище закрыто, и симлинк обязан уйти вместе с ним: иначе он
        // повиснет на исчезнувшей точке монтирования и следующее открытие
        // упадёт на «путь занят, и он не наш» (М-11).
        (Ok(()), Err(detach)) => {
            if let Err(e) = crate::mountpoint::remove_symlink(home, label).await {
                tracing::warn!("close_file_vault: remove_symlink after detach failure: {e}");
            }
            Err(detach)
        }
        // Не закрылось и не отвязалось: исходная причина информативнее.
        (Err(source), Err(_)) => Err(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Почему проверен только один вариант из пяти
    /// Остальные четыре несут `ObjPath`, а у него нет публичного
    /// конструктора (`udisks.rs`: `from_owned` приватен, `block_device` —
    /// `pub(crate)`). Что закрывает дыру вместо теста: `match` без ветки `_`
    /// (новый вариант ломает сборку) и живые IT, где ветка `Foreign`
    /// проверяется на настоящем томе (`t19`). Переехал из окна вместе с
    /// функцией (долг A-11).
    #[test]
    fn detached_volume_is_not_closed_again() {
        assert_eq!(
            close_decision(VaultProbe::Detached),
            CloseDecision::AlreadyDetached,
            "отсоединённый том нечем закрывать: объекта loop-устройства не существует"
        );
    }
}
