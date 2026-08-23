//! Единственный модуль, говорящий с udisks2 по D-Bus (спека: «владелец
//! системных вызовов»). Весь root-код живёт в системном демоне, не здесь.
//! Таксономия D-Bus-ошибок (NotMounted/AlreadyMounted/…) не покидает этот
//! модуль: снаружи — типы panzir-core.
//!
//! Жёсткое правило (план §4.2): udisks2 молча игнорирует неизвестные опции.
//! «Метод не вернул ошибку» ничего не значит — применение опций проверяется
//! тестами по результату (заголовок LUKS, `findmnt`, метка ФС), не по возврату.

use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use secrecy::{ExposeSecret as _, SecretString};
use zbus::zvariant::{Fd, ObjectPath, OwnedObjectPath, Value};
use zbus::{Connection, proxy};

use crate::{Error, Result};

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
    /// Звать строго ДО `lock` (замер 22.08): пока loop наш
    /// (`SetupByUID == наш uid`) — молча; после `Lock` udisks2 сбрасывает
    /// `SetupByUID` в 0, и любые операции с loop требуют пароль админа.
    pub async fn set_autoclear(&self, loop_object: &ObjPath) -> Result<()> {
        let lp = self.loop_proxy(loop_object).await?;
        Ok(lp.set_autoclear(true, no_interaction_options()).await?)
    }

    /// Удалить loop-устройство напрямую. `pub(crate)`: снаружи крейта эта
    /// операция не должна быть достижима вовсе (ответ Ревьюера на В-2) —
    /// иначе случайный вызов из GUI покажет пользователю диалог polkit.
    ///
    /// Только для СВОИХ loop (SetupByUID = наш uid — тогда молча). После
    /// Lock loop «чужой», и Delete спросит пароль — в штатном закрытии
    /// используйте [`Udisks::set_autoclear`].
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
    /// [`Error::UnexpectedUdisksState`], если том заперт: udisks2 в этом
    /// случае возвращает сентинел `/`, а не ошибку (документация Encrypted).
    pub async fn cleartext_device(&self, block_object: &ObjPath) -> Result<ObjPath> {
        let enc = self.encrypted_proxy(block_object).await?;
        let path = enc.cleartext_device().await?;
        if path.as_str() == "/" {
            return Err(Error::UnexpectedUdisksState(format!(
                "volume {block_object} is locked (CleartextDevice is '/')"
            )));
        }
        Ok(ObjPath::from_owned(path))
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

#[cfg(test)]
mod tests {
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
