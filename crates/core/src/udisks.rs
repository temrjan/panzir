//! Единственный модуль, говорящий с udisks2 по D-Bus (спека: «владелец
//! системных вызовов»). Весь root-код живёт в системном демоне, не здесь.
//! Таксономия D-Bus-ошибок (NotMounted/AlreadyMounted/…) не покидает этот
//! модуль: снаружи — типы panzir-core.
//!
//! Жёсткое правило (план §4.2): udisks2 молча игнорирует неизвестные опции.
//! «Метод не вернул ошибку» ничего не значит — применение опций проверяется
//! тестами по результату (заголовок LUKS, `findmnt`, метка ФС), не по возврату.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use secrecy::{ExposeSecret as _, SecretString};
use zbus::zvariant::{Fd, ObjectPath, OwnedObjectPath, Value};
use zbus::{Connection, proxy};

use crate::{AuthRefusal, Error, Result};

/// Словарь опций udisks2 (`a{sv}`).
type Options<'a> = HashMap<&'a str, Value<'a>>;

/// Пустой словарь опций.
fn no_options() -> Options<'static> {
    HashMap::new()
}

/// Опции, запрещающие D-Bus показывать интерактивные диалоги авторизации.
/// Все teardown-вызовы идут с этой опцией, чтобы уборка не могла открыть
/// модальное окно в проде (план cleanup-PR, инвариант №3).
fn no_interaction_options() -> Options<'static> {
    let mut opts = Options::new();
    opts.insert("auth.no_user_interaction", Value::from(true));
    opts
}

/// D-Bus ошибка-метод с заданным именем (таксономия udisks2 — только здесь).
fn dbus_error_is(e: &zbus::Error, name: &str) -> bool {
    matches!(e, zbus::Error::MethodError(n, _, _) if n.as_str() == name)
}

/// Оттенок отказа polkit по имени D-Bus-ошибки; `None` — это не отказ в правах.
/// Карта — из самого udisks (`udisksdaemonutil.c`): `dismissed → Dismissed`,
/// `is_challenge → CanObtain`, иначе `NotAuthorized`. Описание ошибки не
/// участвует: оно бывает пустым.
fn auth_refusal(e: &zbus::Error) -> Option<AuthRefusal> {
    let zbus::Error::MethodError(name, _, _) = e else {
        return None;
    };
    match name.as_str() {
        "org.freedesktop.UDisks2.Error.NotAuthorized" => Some(AuthRefusal::Denied),
        "org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain" => {
            Some(AuthRefusal::NeedsConfirmation)
        }
        "org.freedesktop.UDisks2.Error.NotAuthorizedDismissed" => Some(AuthRefusal::Dismissed),
        _ => None,
    }
}

/// Единственная конверсия `zbus::Error` → [`Error`]: отказ polkit получает
/// собственный вариант, всё остальное остаётся [`Error::Udisks`]. Ручная, а
/// не `#[from]`, ровно затем, чтобы имена отказа жили здесь — рядом с
/// остальной таксономией udisks2 — и покрывали каждый `?` на прокси-вызове
/// разом, без обёртки на каждом.
impl From<zbus::Error> for Error {
    fn from(e: zbus::Error) -> Self {
        match auth_refusal(&e) {
            Some(reason) => Error::NotAuthorized { reason },
            None => Error::Udisks(e),
        }
    }
}

/// «Том не смонтирован».
fn is_not_mounted(e: &zbus::Error) -> bool {
    dbus_error_is(e, "org.freedesktop.UDisks2.Error.NotMounted")
}

/// «Устройство занято» при lock (Гейт-2, Н-26). Замер 22.08: udisks2 шлёт
/// это как `Error.Failed` с текстом «Failed to deactivate device: Device or
/// resource busy» (имени `Error.DeviceBusy` в ответе нет — проверено живьём).
/// Точного кода нет — ловим оба представления, только слово «busy» в Failed.
fn is_device_busy(e: &zbus::Error) -> bool {
    if dbus_error_is(e, "org.freedesktop.UDisks2.Error.DeviceBusy") {
        return true;
    }
    matches!(
        e,
        zbus::Error::MethodError(name, Some(desc), _)
            if name.as_str() == "org.freedesktop.UDisks2.Error.Failed"
                && desc.to_lowercase().contains("busy")
    )
}

/// «Том уже смонтирован» (гонка с автомонтом после Format).
fn is_already_mounted(e: &zbus::Error) -> bool {
    dbus_error_is(e, "org.freedesktop.UDisks2.Error.AlreadyMounted")
}

/// Объектный путь udisks2 (например, `/org/freedesktop/UDisks2/block_devices/loop5`).
///
/// Ньютайп, чтобы типы zbus не утекали в публичный API panzir-core:
/// GUI не обязан знать про zbus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjPath(String);

impl ObjPath {
    fn from_owned(p: OwnedObjectPath) -> Self {
        Self(p.to_string())
    }

    /// Объект блочного устройства по его имени в ядре (`loop3` →
    /// `/org/freedesktop/UDisks2/block_devices/loop3`).
    ///
    /// Конвенция путей udisks2 проверена живьём (`busctl --system tree`,
    /// 24.08) и уже используется в обратную сторону в
    /// [`loop_backing_sysfs`] — новой зависимости здесь не появляется.
    pub(crate) fn block_device(name: &str) -> Self {
        Self(format!("/org/freedesktop/UDisks2/block_devices/{name}"))
    }

    /// Путь строкой.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Последний сегмент пути (`loop5`, `dm_2d6`).
    pub fn basename(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }

    fn as_zbus(&self) -> Result<OwnedObjectPath> {
        OwnedObjectPath::try_from(self.0.clone()).map_err(|e| {
            Error::UnexpectedUdisksState(format!("invalid object path {}: {e}", self.0))
        })
    }
}

impl std::fmt::Display for ObjPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[proxy(
    interface = "org.freedesktop.UDisks2.Manager",
    default_service = "org.freedesktop.UDisks2",
    default_path = "/org/freedesktop/UDisks2/Manager"
)]
trait Manager {
    /// Поднять loop-устройство из файла.
    fn loop_setup(&self, fd: Fd<'_>, options: Options<'_>) -> zbus::Result<OwnedObjectPath>;

    /// Версия демона; используется как проверка присутствия udisks2 на шине.
    #[zbus(property)]
    fn version(&self) -> zbus::Result<String>;
}

/// NB: удаления loop в Manager НЕТ — оно живёт на интерфейсе Loop самого
/// устройства (проверено интроспекцией 22.08; Manager умеет только LoopSetup).
#[proxy(
    interface = "org.freedesktop.UDisks2.Loop",
    default_service = "org.freedesktop.UDisks2"
)]
trait Loop {
    /// Удалить loop-устройство (свои loop — без polkit-запроса).
    fn delete(&self, options: Options<'_>) -> zbus::Result<()>;

    /// Автоочистка при последнем close.
    fn set_autoclear(&self, value: bool, options: Options<'_>) -> zbus::Result<()>;

    /// Файл-основа; используется как проверка существования объекта.
    #[zbus(property)]
    fn backing_file(&self) -> zbus::Result<Vec<u8>>;

    /// UID пользователя, поднявшего loop. Замер 24.08 (`busctl introspect`):
    /// свойство `u`, для loop, поднятого нами, равно нашему uid. После `Lock`
    /// udisks2 сбрасывает его в 0 — см. [`Udisks::set_autoclear`].
    ///
    /// Отвечает на вопрос «чей ПОЛЬЗОВАТЕЛЬ», а не «чей процесс»: loop,
    /// поднятый другой программой под тем же пользователем, отдаст тот же uid.
    ///
    /// Имя свойства задано ЯВНО: из `setup_by_uid` zbus выводит `SetupByUid`,
    /// а udisks2 объявляет `SetupByUID` — расхождение в одной букве, которое
    /// компилятор пропускает, а живой вызов возвращает
    /// `No such property "SetupByUid"` (поймано живым прогоном 24.08).
    #[zbus(property, name = "SetupByUID")]
    fn setup_by_uid(&self) -> zbus::Result<u32>;
}

#[proxy(
    interface = "org.freedesktop.UDisks2.Block",
    default_service = "org.freedesktop.UDisks2"
)]
trait Block {
    /// Отформатировать устройство. Для зашифрованного тома: `type` — это ФС
    /// на расшифрованном устройстве, а параметры шифрования уходят опциями
    /// `encrypt.type` / `encrypt.passphrase`.
    fn format(&self, type_: &str, options: Options<'_>) -> zbus::Result<()>;

    /// Пересканировать заголовок устройства. Нужен после внешних изменений
    /// заголовка LUKS (например, `cryptsetup luksAddKey`), чтобы udisks2
    /// снова предоставил интерфейс `Encrypted`.
    fn rescan(&self, options: Options<'_>) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.freedesktop.UDisks2.Encrypted",
    default_service = "org.freedesktop.UDisks2"
)]
trait Encrypted {
    /// Отпереть LUKS-том парольной фразой.
    fn unlock(&self, passphrase: &str, options: Options<'_>) -> zbus::Result<OwnedObjectPath>;

    /// Запереть том (cryptsetup close).
    fn lock(&self, options: Options<'_>) -> zbus::Result<()>;

    /// Объект расшифрованного устройства; для ЗАПЕРТОГО тома — сентинел `/`.
    #[zbus(property)]
    fn cleartext_device(&self) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    interface = "org.freedesktop.UDisks2.Filesystem",
    default_service = "org.freedesktop.UDisks2"
)]
trait Filesystem {
    /// Смонтировать ФС; возвращает фактическую точку монтирования.
    fn mount(&self, options: Options<'_>) -> zbus::Result<String>;

    /// Размонтировать ФС.
    fn unmount(&self, options: Options<'_>) -> zbus::Result<()>;

    /// Текущие точки монтирования (NUL-терминированные байтовые строки).
    #[zbus(property)]
    fn mount_points(&self) -> zbus::Result<Vec<Vec<u8>>>;
}

#[proxy(
    interface = "org.freedesktop.DBus.ObjectManager",
    default_service = "org.freedesktop.UDisks2",
    default_path = "/org/freedesktop/UDisks2"
)]
trait ObjectManager {
    /// Объект потерял часть или все интерфейсы (спека п.11).
    #[zbus(signal)]
    fn interfaces_removed(
        &self,
        object_path: ObjectPath<'_>,
        interfaces: Vec<String>,
    ) -> zbus::Result<()>;
}

/// Клиент udisks2. Создаётся через [`Udisks::connect`], который заодно
/// проверяет присутствие демона на шине.
///
/// `Clone` дешёвый: `zbus::Connection` внутри — счётчик ссылок, не новое
/// соединение. Нужен, чтобы RAII-страховка на частично открытом хранилище
/// (`lifecycle::OpenGuard`) могла унести клиента в `Drop`, где ссылок на
/// вызывающего уже нет.
#[derive(Clone)]
pub struct Udisks {
    conn: Connection,
    /// Версия демона — доказательство, что udisks2 жив (для diagnostics).
    version: String,
}

impl Udisks {
    /// Подключается к системной шине и проверяет, что udisks2 отвечает.
    ///
    /// # Errors
    /// [`Error::MissingDependency`], если udisks2 нет на шине — с подсказкой
    /// установки. Без sudo-фолбэка, по спеке.
    pub async fn connect() -> Result<Self> {
        let conn = Connection::system().await?;
        let mgr = ManagerProxy::new(&conn).await?;
        let version = mgr.version().await.map_err(|_| Error::MissingDependency {
            name: "udisks2",
            hint: "установите и запустите udisks2 (dnf install udisks2); без него panzir \
                       не работает и не откатывается на sudo — это осознанное решение"
                .to_owned(),
        })?;
        Ok(Self { conn, version })
    }

    /// Версия udisks2, прочитанная при подключении.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Поднять loop-устройство из открытого файла контейнера.
    ///
    /// Намеренно БЕЗ autoclear на этом шаге (замер 22.08): у loop с
    /// autoclear последующий `Format` требует polkit-авторизацию
    /// (modify-device-system), а без него — проходит молча. Autoclear
    /// включается в потоке закрытия, ДО Lock, пока loop ещё наш.
    pub async fn loop_setup(&self, file: std::fs::File) -> Result<ObjPath> {
        let mgr = ManagerProxy::new(&self.conn).await?;
        let fd = Fd::from(std::os::fd::OwnedFd::from(file));
        Ok(ObjPath::from_owned(mgr.loop_setup(fd, no_options()).await?))
    }

    /// Включить autoclear — поток закрытия файл-контейнера:
    /// `unmount → set_autoclear → lock`, и устройство отвяжется само.
    ///
    /// Звать строго ДО `lock` (замер 22.08): пока loop наш, операции идут молча.
    ///
    /// **Уточнение по замеру 24.08.** Прежняя редакция этого комментария
    /// объясняла необходимость порядка тем, что «после `Lock` udisks2
    /// сбрасывает `SetupByUID` в 0». Это неверно: четыре последовательных
    /// чтения свойства через `busctl` (после `LoopSetup`, `luksFormat`,
    /// `Unlock` и `Lock`) дают неизменное `1000`; положительный контроль —
    /// loop, поднятый root напрямую, отдаёт `0`. Само наблюдение «после `Lock`
    /// `Delete` начинает спрашивать пароль» не опровергнуто — опровергнуто
    /// только это объяснение, и порядок вызовов остаётся обязательным.
    pub async fn set_autoclear(&self, loop_object: &ObjPath) -> Result<()> {
        let lp = self.loop_proxy(loop_object).await?;
        Ok(lp.set_autoclear(true, no_interaction_options()).await?)
    }

    /// Удалить loop-устройство напрямую. `pub(crate)`: снаружи крейта эта
    /// операция не должна быть достижима вовсе (ответ Ревьюера на В-2) —
    /// иначе случайный вызов из GUI покажет пользователю диалог polkit.
    ///
    /// Только для СВОИХ loop (SetupByUID = наш uid — тогда молча). После
    /// `Lock` `Delete` наблюдался как требующий пароль; механизм не в
    /// обнулении `SetupByUID` (замер 24.08 это опроверг, см.
    /// [`Udisks::set_autoclear`]) — в штатном закрытии всё равно используйте
    /// [`Udisks::set_autoclear`] до запирания.
    ///
    /// Каприз udisks2 2.11 (наблюдено вживую 22.08): `Loop.Delete` нередко
    /// ВОЗВРАЩАЕТ ошибку ENXIO («Failed to detach the backing file»), потому
    /// что демон сам держит устройство открытым, — при этом ядро убирает
    /// устройство при последнем close. По правилу §4.2 судим по результату,
    /// а не по ошибке: после ошибки ждём исчезновения из sysfs.
    pub(crate) async fn loop_delete(&self, loop_object: &ObjPath) -> Result<()> {
        let lp = self.loop_proxy(loop_object).await?;
        match lp.delete(no_interaction_options()).await {
            Ok(()) => Ok(()),
            Err(first) => {
                for _ in 0..15 {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    if loop_detached_in_sysfs(loop_object) {
                        return Ok(());
                    }
                }
                Err(Error::from(first))
            }
        }
    }

    /// Создать LUKS2-том и ФС внутри него одним вызовом `Format`.
    ///
    /// После `Format` том остаётся **отпертым**; монтирование может идти
    /// асинхронно (гонка с автомонтом — см. [`Udisks::mount_noexec`]).
    pub async fn format_luks2(
        &self,
        block_object: &ObjPath,
        label: &str,
        passphrase: &SecretString,
    ) -> Result<()> {
        let block = BlockProxy::builder(&self.conn)
            .path(block_object.as_zbus()?)?
            .build()
            .await?;
        let mut options = Options::new();
        options.insert("encrypt.type", Value::from("luks2"));
        options.insert(
            "encrypt.passphrase",
            Value::from(passphrase.expose_secret()),
        );
        options.insert("label", Value::from(label));
        Ok(block.format("ext4", options).await?)
    }

    /// Отпереть существующий LUKS-том.
    pub async fn unlock(
        &self,
        block_object: &ObjPath,
        passphrase: &SecretString,
    ) -> Result<ObjPath> {
        let enc = self.encrypted_proxy(block_object).await?;
        Ok(ObjPath::from_owned(
            enc.unlock(passphrase.expose_secret(), no_options()).await?,
        ))
    }

    /// Запереть том — одна попытка. Для штатного закрытия используйте
    /// [`Udisks::close_encrypted`]: она оркестрирует unmount/lock с ретраями.
    pub async fn lock(&self, block_object: &ObjPath) -> Result<()> {
        let enc = self.encrypted_proxy(block_object).await?;
        Ok(enc.lock(no_interaction_options()).await?)
    }

    /// Пересканировать блочное устройство (после изменения LUKS-заголовка
    /// вне udisks2, например `cryptsetup luksAddKey`).
    pub async fn rescan(&self, block_object: &ObjPath) -> Result<()> {
        let block = BlockProxy::builder(&self.conn)
            .path(block_object.as_zbus()?)?
            .build()
            .await?;
        Ok(block.rescan(no_options()).await?)
    }

    /// Штатное закрытие зашифрованного тома на loop-контейнере.
    ///
    /// Гейт-2, Н-26 плюс наблюдение 22.08: между нашим unmount и lock том
    /// может оказаться заново смонтирован автомонтёром окружения, а Lock
    /// отвечает busy, пока размонтирование/udev не доехали. Поэтому цикл:
    /// снять монтирование (с ожиданием результата) → lock → busy? повтор.
    /// Autoclear ставится ДО lock, пока loop ещё наш (план §4.13).
    /// Предел — 8 итераций; дальше — честная ошибка, не вечный цикл.
    pub async fn close_encrypted(&self, loop_object: &ObjPath) -> Result<()> {
        self.set_autoclear(loop_object).await?;
        let mut last_err: Option<Error> = None;
        for iteration in 0..8 {
            // Если том отперт — сначала размонтировать и дождаться.
            if let Ok(cleartext) = self.cleartext_device(loop_object).await {
                match self.unmount_wait(&cleartext).await {
                    Ok(()) => {}
                    Err(e) if Self::is_retryable_unmount(&e) => {
                        tracing::warn!(
                            "close_encrypted: unmount_wait retryable on iteration {iteration}: {e}"
                        );
                        last_err = Some(e);
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            match self.lock(loop_object).await {
                Ok(()) => return Ok(()),
                Err(e) if matches!(&e, Error::Udisks(z) if is_device_busy(z)) => {
                    tracing::warn!("close_encrypted: lock busy on iteration {iteration}: {e}");
                    last_err = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                Err(e) => return Err(e),
            }
        }
        let cleartext = self.cleartext_device(loop_object).await.ok();
        let mount_points = match &cleartext {
            Some(c) => self.mount_points(c).await.ok(),
            None => None,
        };
        let backing_file = self.loop_backing_file(loop_object).await.ok();
        tracing::error!(
            loop_object = %loop_object,
            cleartext_device = ?cleartext.as_ref().map(|c| c.to_string()),
            mount_points = ?mount_points,
            backing_file = ?backing_file.as_ref().map(|b| String::from_utf8_lossy(b)),
            "close_encrypted: retry budget spent"
        );
        Err(last_err.unwrap_or_else(|| {
            Error::UnexpectedUdisksState(format!("cannot close {loop_object}: retry budget spent"))
        }))
    }

    fn is_retryable_unmount(e: &Error) -> bool {
        match e {
            Error::Udisks(z) => is_device_busy(z),
            Error::UnexpectedUdisksState(msg) => msg.contains("still mounted after unmount"),
            _ => false,
        }
    }

    /// Смонтировать ФС с `noexec` (параметр вызова, allow-лист udisks2 —
    /// факт §4.9 плана; файл в /etc не нужен).
    ///
    /// Идемпотентно по отношению к автомонту: если udisks2 успел смонтировать
    /// том сам (гонка после Format), снимаем его монтирование и монтируем
    /// с нашими опциями. Никакого ожидания опросом — до 3 попыток.
    ///
    /// Возвращает фактическую точку монтирования — её сообщает udisks2,
    /// угадывать путь запрещено (план §4.3).
    pub async fn mount_noexec(&self, block_object: &ObjPath) -> Result<PathBuf> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            match self.try_mount_noexec(block_object).await {
                Ok(p) => return Ok(p),
                Err(e)
                    if attempts < 3 && matches!(&e, Error::Udisks(z) if is_already_mounted(z)) =>
                {
                    // Идемпотентный unmount: гонка могла уже рассосаться.
                    self.unmount(block_object).await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn try_mount_noexec(&self, block_object: &ObjPath) -> Result<PathBuf> {
        let fs = self.fs_proxy(block_object).await?;
        let mut options = Options::new();
        options.insert("options", Value::from("noexec"));
        Ok(PathBuf::from(fs.mount(options).await?))
    }

    /// Размонтировать ФС. Идемпотентно: «уже не смонтировано» — успех.
    pub async fn unmount(&self, block_object: &ObjPath) -> Result<()> {
        let fs = self.fs_proxy(block_object).await?;
        match fs.unmount(no_interaction_options()).await {
            Ok(()) => Ok(()),
            Err(e) if is_not_mounted(&e) => Ok(()),
            Err(e) => Err(Error::from(e)),
        }
    }

    /// Размонтировать и ДОЖДАТЬСЯ результата (Гейт-2, Н-26): `Unmount`
    /// возвращается до того, как точка реально исчезла, — `lock` сразу
    /// после него ловит EBUSY. Опрашиваем mount_points до пустого
    /// (≤5 с), иначе — ошибка, а не молчание.
    pub async fn unmount_wait(&self, block_object: &ObjPath) -> Result<()> {
        self.unmount(block_object).await?;
        for _ in 0..25 {
            if self.mount_points(block_object).await?.is_empty() {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        Err(Error::UnexpectedUdisksState(format!(
            "still mounted after unmount: {block_object}"
        )))
    }

    /// Объект расшифрованного устройства для отпертого тома.
    ///
    /// # Errors
    /// [`Error::VolumeLocked`], если том заперт: udisks2 в этом случае
    /// возвращает сентинел `/`, а не ошибку (документация Encrypted).
    /// Отдельный вариант ошибки нужен, чтобы вызывающий отличал «заперто» от
    /// «шина отвалилась» матчем по типу: любая другая ошибка этой функции —
    /// не «заперто», и трактовать её так значит уверенно соврать о состоянии
    /// хранилища.
    pub async fn cleartext_device(&self, block_object: &ObjPath) -> Result<ObjPath> {
        let enc = self.encrypted_proxy(block_object).await?;
        let path = enc.cleartext_device().await?;
        if path.as_str() == "/" {
            return Err(Error::VolumeLocked {
                object: block_object.to_string(),
            });
        }
        Ok(ObjPath::from_owned(path))
    }

    /// UID, поднявший loop-устройство (`SetupByUID`).
    pub(crate) async fn loop_setup_by_uid(&self, loop_object: &ObjPath) -> Result<u32> {
        let lp = self.loop_proxy(loop_object).await?;
        Ok(lp.setup_by_uid().await?)
    }

    /// Довести loop-устройство до отвязки: подтолкнуть, если само не ушло, и
    /// дождаться исчезновения из sysfs.
    ///
    /// Общий шаг для продуктового закрытия ([`crate::lifecycle::close_file_vault`])
    /// и для уборки файл-контейнера ([`crate::create::teardown_file_container`]).
    /// Держать его в одном месте обязательно: фолбэк `Loop.Delete` нужен ровно
    /// тогда, когда `autoclear` не сработал сам, и разойтись в этом два
    /// вызывающих не имеют права.
    ///
    /// # Errors
    /// [`Error::UnexpectedUdisksState`], если через 5 с loop всё ещё в sysfs.
    pub(crate) async fn ensure_loop_detached(&self, loop_object: &ObjPath) -> Result<()> {
        // Фолбэк Delete — только если loop всё ещё виден в sysfs.
        if !loop_detached_in_sysfs(loop_object)
            && let Err(e) = self.loop_delete(loop_object).await
        {
            tracing::warn!("ensure_loop_detached: loop_delete failed: {e}");
        }

        // Ждём исчезновения из sysfs, макс. 5 с.
        for _ in 0..25 {
            if loop_detached_in_sysfs(loop_object) {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        Err(Error::UnexpectedUdisksState(format!(
            "stale loop device left for {loop_object}"
        )))
    }

    /// Текущие точки монтирования устройства (может быть пусто).
    pub async fn mount_points(&self, block_object: &ObjPath) -> Result<Vec<PathBuf>> {
        let fs = self.fs_proxy(block_object).await?;
        let points = fs
            .mount_points()
            .await?
            .into_iter()
            .map(|raw| {
                use std::os::unix::ffi::OsStrExt as _;
                let trimmed = raw.split(|&b| b == 0).next().unwrap_or(&raw);
                PathBuf::from(std::ffi::OsStr::from_bytes(trimmed))
            })
            .collect();
        Ok(points)
    }

    /// Подписка на снятие интерфейсов с объектов udisks2 (спека п.11:
    /// извлечение носителя на живом приложении).
    pub async fn interfaces_removed_stream(&self) -> Result<DeviceRemovedStream> {
        let mgr = ObjectManagerProxy::new(&self.conn).await?;
        Ok(DeviceRemovedStream {
            inner: Box::pin(mgr.receive_interfaces_removed().await?),
        })
    }

    async fn loop_proxy(&self, object: &ObjPath) -> Result<LoopProxy<'_>> {
        Ok(LoopProxy::builder(&self.conn)
            .path(object.as_zbus()?)?
            .build()
            .await?)
    }

    async fn encrypted_proxy(&self, object: &ObjPath) -> Result<EncryptedProxy<'_>> {
        Ok(EncryptedProxy::builder(&self.conn)
            .path(object.as_zbus()?)?
            .build()
            .await?)
    }

    async fn fs_proxy(&self, object: &ObjPath) -> Result<FilesystemProxy<'_>> {
        Ok(FilesystemProxy::builder(&self.conn)
            .path(object.as_zbus()?)?
            .build()
            .await?)
    }

    async fn loop_backing_file(&self, loop_object: &ObjPath) -> Result<Vec<u8>> {
        let lp = self.loop_proxy(loop_object).await?;
        Ok(lp.backing_file().await?)
    }
}

/// Событие снятия интерфейсов с объекта udisks2.
///
/// Сигнал `InterfacesRemoved` стреляет и при ЧАСТИЧНОМ снятии (например,
/// Format меняет fs-сигнатуру живого объекта) — поэтому набор интерфейсов
/// прокинут наружу: судить об извлечении носителя можно только по нему.
#[derive(Debug, Clone)]
pub struct DeviceRemoved {
    /// Объектный путь.
    pub path: ObjPath,
    /// Снятые интерфейсы.
    pub interfaces: Vec<String>,
}

impl DeviceRemoved {
    /// Снят ли интерфейс Block — устройство перестало быть блочным
    /// (наш случай «носитель извлечён»).
    pub fn block_interface_gone(&self) -> bool {
        self.interfaces
            .iter()
            .any(|i| i == "org.freedesktop.UDisks2.Block")
    }
}

/// Поток событий снятия интерфейсов. Реализует [`futures_util::Stream`],
/// чтобы работать в `select!` и комбинаторах (потребитель — PR-2+).
pub struct DeviceRemovedStream {
    inner: Pin<Box<InterfacesRemovedStream>>,
}

impl futures_util::Stream for DeviceRemovedStream {
    type Item = Result<DeviceRemoved>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx).map(|opt| {
            opt.map(|signal| {
                signal
                    .args()
                    .map(|args| DeviceRemoved {
                        path: ObjPath::from_owned(args.object_path.into()),
                        interfaces: args.interfaces,
                    })
                    .map_err(Error::from)
            })
        })
    }
}

/// Путь к sysfs-записи backing-файла loop-устройства по имени объекта.
/// `loop5p1` (раздел на loop) — НЕ loop-устройство: живёт не в
/// /sys/block/loop5p1/, а под /sys/block/loop5/ — такие имена отвергаем.
fn loop_backing_sysfs(name: &str) -> Option<PathBuf> {
    let digits = name.strip_prefix("loop")?;
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(PathBuf::from(format!(
        "/sys/block/{name}/loop/backing_file"
    )))
}

/// Отвязан ли loop от backing-файла по sysfs (ядреная правда, не D-Bus).
pub(crate) fn loop_detached_in_sysfs(loop_object: &ObjPath) -> bool {
    loop_backing_sysfs(loop_object.basename()).is_some_and(|p| !p.exists())
}

/// Разобранная бирка `loop/backing_file`.
struct BackingFile<'a> {
    /// Путь без служебных хвостов.
    path: &'a str,
    /// Ядро пометило файл как удалённый: привязка жива, инода уже нет.
    deleted: bool,
}

/// Очистить содержимое `loop/backing_file` до пути и признака удаления.
///
/// Ядро пишет туда путь с завершающим переводом строки (замер 24.08:
/// `od -c` → `… t . v a u l t \n`), а для файла, удалённого при живой
/// привязке, добавляет суффикс `" (deleted)"`. Не срезать перевод строки —
/// значит не совпасть НИ РАЗУ, ни с одним контейнером.
///
/// Признак удаления **выносится наружу, а не выбрасывается**: loop на удалённой
/// иноде не имеет отношения к новому файлу, который позже занял то же имя пути
/// (Б-6 ревью раунда 1).
fn clean_backing_file(raw: &str) -> BackingFile<'_> {
    let trimmed = raw.trim_end_matches(['\n', '\r']);
    match trimmed.strip_suffix(" (deleted)") {
        Some(path) => BackingFile {
            path,
            deleted: true,
        },
        None => BackingFile {
            path: trimmed,
            deleted: false,
        },
    }
}

/// UID текущего процесса.
///
/// `rustix::process::getuid()` — безопасный вызов, поэтому `unsafe_code =
/// "forbid"` в workspace не мешает и внешний процесс (`id -u`) не нужен.
pub(crate) fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Все loop-устройства, привязанные к этому файлу — по sysfs.
///
/// Возвращает СПИСОК, а не первое совпадение: два loop на одном контейнере
/// означают две dm-crypt поверх одного LUKS-тома, то есть уже случившуюся
/// порчу, и молча взять первый нельзя.
///
/// Почему sysfs, а не `ObjectManager.GetManagedObjects`: интерфейс
/// `ObjectManager` в этом крейте объявляет только сигнал, а бирку по шине
/// udisks2 отдаёт байтами с завершающим NUL. sysfs — ядерная правда, на
/// которую крейт уже опирается в [`loop_detached_in_sysfs`].
pub(crate) async fn find_loops_for_backing_file(container: &Path) -> Result<Vec<ObjPath>> {
    // sysfs читается синхронно, но это всё же файловый ввод-вывод в async-пути:
    // уводим его в блокирующий пул, чтобы не занимать исполнитель (М-1).
    let container = container.to_owned();
    tokio::task::spawn_blocking(move || find_loops_blocking(&container))
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))?
}

fn find_loops_blocking(container: &Path) -> Result<Vec<ObjPath>> {
    let target_canon = std::fs::canonicalize(container).ok();
    let mut found = Vec::new();

    for entry in std::fs::read_dir("/sys/block").map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // Не loop и не наша конвенция имён — пропускаем.
        let Some(backing_path) = loop_backing_sysfs(name) else {
            continue;
        };
        // Свободные loop существуют в sysfs БЕЗ файла бирки (замер 24.08):
        // отсутствие файла — норма, а не ошибка.
        let Ok(raw) = std::fs::read_to_string(&backing_path) else {
            continue;
        };
        let backing = clean_backing_file(&raw);
        let candidate = Path::new(backing.path);

        let same = if backing.deleted {
            // Привязка к удалённой иноде. Совпадением её можно считать только
            // если ЦЕЛЕВОЙ файл тоже отсутствует: иначе новый, здоровый
            // контейнер по тому же пути навсегда получил бы диагноз
            // «два loop» из-за чужого мертвеца (Б-6).
            target_canon.is_none() && candidate == container
        } else {
            match (&target_canon, std::fs::canonicalize(candidate).ok()) {
                (Some(target), Some(cand)) => *target == cand,
                _ => candidate == container,
            }
        };
        if same {
            found.push(ObjPath::block_device(name));
        }
    }

    Ok(found)
}

#[cfg(test)]
mod tests {
    // expect в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
    #![allow(clippy::expect_used)]

    use super::*;
    use std::convert::TryInto as _;
    use zbus::Message;

    fn dummy_udisks_error(name: &str, desc: Option<&str>) -> zbus::Error {
        let msg = Message::method_call("/org/freedesktop/UDisks2", "Lock")
            .expect("dummy method call")
            .build(&())
            .expect("dummy message");
        zbus::Error::MethodError(
            name.to_owned().try_into().expect("valid error name"),
            desc.map(|s| s.to_owned()),
            msg,
        )
    }

    /// Круг H: udisks2 отвечает отказом polkit тремя именами. Ни одно из них —
    /// не «шина умерла»: служба ответила безупречно, она сказала «нельзя».
    /// Если такой отказ приезжает как общий `Error::Udisks`, окно скажет
    /// человеку «служба дисков не отвечает» — и он пойдёт чинить не то.
    #[test]
    fn polkit_refusal_is_not_reported_as_a_generic_udisks_failure() {
        for name in [
            "org.freedesktop.UDisks2.Error.NotAuthorized",
            "org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain",
            "org.freedesktop.UDisks2.Error.NotAuthorizedDismissed",
        ] {
            // Описание бывает и пустым: классификация идёт по имени, не по тексту.
            for desc in [Some("Not authorized to perform operation"), None] {
                let err = Error::from(dummy_udisks_error(name, desc));
                assert!(
                    !matches!(err, Error::Udisks(_)),
                    "{name} (desc {desc:?}): отказ в правах приехал как общий сбой udisks2 — \
                     окно скажет «не отвечает»"
                );
            }
        }
    }

    /// Карта имя → оттенок, по исходнику udisks; и контроль, что новый отказ не
    /// глотает соседей: `NotMounted` по-прежнему общий `Udisks`.
    #[test]
    fn polkit_refusal_maps_each_name_to_its_reason() {
        let cases = [
            (
                "org.freedesktop.UDisks2.Error.NotAuthorized",
                AuthRefusal::Denied,
            ),
            (
                "org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain",
                AuthRefusal::NeedsConfirmation,
            ),
            (
                "org.freedesktop.UDisks2.Error.NotAuthorizedDismissed",
                AuthRefusal::Dismissed,
            ),
        ];
        for (name, expected) in cases {
            for desc in [Some("Not authorized to perform operation"), None] {
                match Error::from(dummy_udisks_error(name, desc)) {
                    Error::NotAuthorized { reason } => {
                        assert_eq!(reason, expected, "{name} (desc {desc:?})");
                    }
                    other => {
                        panic!("{name} (desc {desc:?}): ожидался NotAuthorized, пришло {other:?}")
                    }
                }
            }
        }
        let not_mounted = Error::from(dummy_udisks_error(
            "org.freedesktop.UDisks2.Error.NotMounted",
            None,
        ));
        assert!(
            matches!(not_mounted, Error::Udisks(_)),
            "NotMounted — не отказ в правах, обязан остаться общим Udisks: {not_mounted:?}"
        );
    }

    /// Круг H, находка Ревьюера: у классификатора есть третья ветка — ошибка,
    /// которая **вообще не ответ метода**: сокет шины умер, адрес не разобран,
    /// рукопожатие не состоялось. Здесь «служба не отвечает» — правда, и такой
    /// случай обязан остаться [`Error::Udisks`]. Без этого теста регрессия в
    /// `auth_refusal` вернёт ровно ту болезнь, которую лечит весь круг H:
    /// обрыв шины назовётся отказом в правах, и сюит этого не заметит.
    #[test]
    fn a_broken_bus_is_not_mistaken_for_a_refusal() {
        let bus_down = [
            zbus::Error::InputOutput(std::sync::Arc::new(std::io::Error::other(
                "system bus socket closed",
            ))),
            zbus::Error::Address("unix:path=/nonexistent".to_owned()),
            zbus::Error::Handshake("EXTERNAL auth failed".to_owned()),
        ];
        for e in bus_down {
            let shown = format!("{e:?}");
            let err = Error::from(e);
            assert!(
                matches!(err, Error::Udisks(_)),
                "обрыв шины выдан за отказ в правах ({shown}): человеку скажут «нельзя», \
                 когда служба и правда не отвечает"
            );
        }
    }

    #[test]
    fn clean_backing_file_strips_newline_and_deleted_suffix() {
        // Замер 24.08 (`od -c`): ядро пишет путь с завершающим \n. Без обрезки
        // сравнение не совпадёт НИ РАЗУ — защита от второго loop станет немой.
        let live = clean_backing_file("/tmp/panzir-t99.vault\n");
        assert_eq!(live.path, "/tmp/panzir-t99.vault");
        assert!(!live.deleted, "живой файл не помечен удалённым");

        // Файл удалён при живой привязке — признак обязан дойти до вызывающего.
        let gone = clean_backing_file("/tmp/panzir-t99.vault (deleted)\n");
        assert_eq!(gone.path, "/tmp/panzir-t99.vault");
        assert!(gone.deleted, "удалённый файл обязан быть помечен");

        // Без хвостов — как есть.
        let plain = clean_backing_file("/tmp/x.vault");
        assert_eq!(plain.path, "/tmp/x.vault");
        assert!(!plain.deleted);

        // " (deleted)" внутри имени файла не трогаем — суффикс только в конце.
        let tricky = clean_backing_file("/tmp/a (deleted) b.vault\n");
        assert_eq!(tricky.path, "/tmp/a (deleted) b.vault");
        assert!(!tricky.deleted);
    }

    #[test]
    fn block_device_path_follows_udisks_convention() {
        // Конвенция проверена живьём (`busctl --system tree`, 24.08).
        assert_eq!(
            ObjPath::block_device("loop0").as_str(),
            "/org/freedesktop/UDisks2/block_devices/loop0"
        );
    }

    #[test]
    fn is_retryable_unmount_recognizes_busy_and_stale_mount() {
        assert!(Udisks::is_retryable_unmount(&Error::Udisks(
            dummy_udisks_error("org.freedesktop.UDisks2.Error.DeviceBusy", None,)
        )));
        assert!(Udisks::is_retryable_unmount(&Error::Udisks(
            dummy_udisks_error(
                "org.freedesktop.UDisks2.Error.Failed",
                Some("Failed to deactivate device: Device or resource busy"),
            )
        )));
        assert!(Udisks::is_retryable_unmount(&Error::UnexpectedUdisksState(
            "still mounted after unmount: /org/freedesktop/UDisks2/block_devices/dm_2d0".to_owned(),
        )));

        assert!(!Udisks::is_retryable_unmount(&Error::Udisks(
            dummy_udisks_error(
                "org.freedesktop.UDisks2.Error.Failed",
                Some("some other failure"),
            )
        )));
        assert!(!Udisks::is_retryable_unmount(&Error::Io(
            std::io::Error::other("device or resource busy")
        )));
    }

    #[test]
    fn loop_sysfs_path_parsing() {
        assert!(loop_backing_sysfs("loop5").is_some());
        assert!(loop_backing_sysfs("loop0").is_some());
        // Раздел на loop — не loop-устройство: /sys/block/loop5p1 не существует,
        // доверять такому ответу нельзя.
        assert!(loop_backing_sysfs("loop5p1").is_none());
        assert!(loop_backing_sysfs("dm-0").is_none());
        assert!(loop_backing_sysfs("loop").is_none());
        assert!(loop_backing_sysfs("loopx").is_none());
        assert!(loop_backing_sysfs("").is_none());
    }

    #[test]
    fn objpath_basename() {
        let p = ObjPath("/org/freedesktop/UDisks2/block_devices/loop5".to_owned());
        assert_eq!(p.basename(), "loop5");
        assert!(p.as_zbus().is_ok());
        assert!(
            ObjPath("not/a path with spaces".to_owned())
                .as_zbus()
                .is_err()
        );
    }
}
