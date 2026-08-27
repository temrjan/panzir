//! Часы автозакрытия — снаружи процесса, в systemd пользователя.
//!
//! Модуль — **единственный**, кто говорит с `systemd --user` (тем же правилом,
//! каким `udisks.rs` — единственный, кто говорит с udisks2). Часы живут в
//! разовом транзиентном таймере `panzir-close-<метка>`: он переживает закрытие
//! и падение окна и по истечении запускает наш же бинарь в одноразовом режиме
//! `--close <метка>` (спека С-2/Т-2).
//!
//! Замеры 27.08, на которых стоит модуль:
//! - повторный завод под тем же именем после срабатывания или падения
//!   **отказывает**; `--collect` и `RemainAfterElapse=no` не помогают —
//!   перед каждым заводом: `stop <u>.timer <u>.service` + `reset-failed`;
//! - `stop <u>.service` **убивает** уже бегущее закрытие; `stop <u>.timer` —
//!   нет. Поэтому снятие трогает только таймер и **ждёт** бегущую службу
//!   вместо того, чтобы запускать своё закрытие рядом с ней.

use std::ffi::OsString;
use std::time::{Duration, Instant};

use tokio::process::Command;

use crate::vault::Label;
use crate::{Error, Result};

/// Часы автозакрытия: завести после открытия, снять перед закрытием.
///
/// Трейт, а не функции, чтобы у `lifecycle` была граница для чистых тестов
/// (`Real > Fake`): живые IT идут через [`SystemdUser`], юнит-тесты — через
/// [`NoScheduler`]. Фьючи `Send`: окно гоняет операции через `tokio::spawn`.
pub trait Scheduler: Send + Sync {
    /// Завести часы на `after` для `label`. Прежний таймер той же метки
    /// снимается — повторный завод под тем же именем иначе отказывает.
    fn arm(&self, label: &Label, after: Duration) -> impl Future<Output = Result<()>> + Send;

    /// Снять часы для `label`. Если закрытие по ним **уже бежит** — дождаться
    /// его, а не убить: после снятия таймера новый запуск невозможен, поэтому
    /// вызывающий, получив `Ok`, вправе пробовать закрывать сам (спека С-2).
    fn disarm(&self, label: &Label) -> impl Future<Output = Result<()>> + Send;
}

/// Часы в `systemd --user`: разовый транзиентный таймер на нашу метку.
#[derive(Debug, Clone)]
pub struct SystemdUser {
    /// Команда-закрыватель: бинарь и его постоянные аргументы; таймер добавит
    /// `--close <метка>`. Префикс, а не путь: служба systemd не наследует
    /// окружение вызывающего, и всё, что закрывателю нужно знать (реестр,
    /// домашний каталог), он получает только аргументами (инвариант 9).
    closer: Vec<OsString>,
    /// Сколько ждать бегущее закрытие в `disarm`, прежде чем сдаться вслух.
    join_timeout: Duration,
}

impl SystemdUser {
    /// Часы, запускающие `<closer…> --close <метка>`.
    #[must_use]
    pub fn new(closer: Vec<OsString>, join_timeout: Duration) -> Self {
        Self {
            closer,
            join_timeout,
        }
    }
}

impl Scheduler for SystemdUser {
    async fn arm(&self, label: &Label, after: Duration) -> Result<()> {
        let unit = unit_name(label);
        // Идемпотентный пролог (спека С-4): коды выхода намеренно не смотрим —
        // «юнит не загружен» (exit 5) здесь такой же штатный исход, как успех.
        // Отсутствие самой `systemctl` — уже отказ, его `quiet` не глотает.
        quiet(
            "systemctl",
            &[
                "--user",
                "stop",
                &format!("{unit}.timer"),
                &format!("{unit}.service"),
            ],
        )
        .await?;
        quiet(
            "systemctl",
            &["--user", "reset-failed", &format!("{unit}.service")],
        )
        .await?;

        let args = systemd_run_args(label, after, &self.closer);
        let status = Command::new("systemd-run")
            .args(&args)
            .status()
            .await
            .map_err(Error::Io)?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::Schedule {
                cmd: format!("systemd-run {}", join_args(&args)),
                status: status.to_string(),
            })
        }
    }

    async fn disarm(&self, label: &Label) -> Result<()> {
        let unit = unit_name(label);
        let service = format!("{unit}.service");
        // Только таймер: снятие службы убило бы бегущее закрытие (замер 27.08).
        quiet("systemctl", &["--user", "stop", &format!("{unit}.timer")]).await?;

        // Источник запусков снят — множество «бежит / не бежит» больше не
        // меняется, окна между проверкой и действием нет. Ждём, если бежит —
        // кроме случая, когда бегущая служба это мы сами (закрыватель,
        // запущенный этим же таймером): ждать себя — зависнуть до таймаута.
        if service_is_self(&main_pid_line(&service).await?, std::process::id()) {
            return Ok(());
        }
        let deadline = Instant::now() + self.join_timeout;
        loop {
            let state = active_state(&service).await?;
            if !is_busy_state(&state) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::Schedule {
                    cmd: format!("systemctl --user is-active {service}"),
                    status: format!("still {state} after {}s", self.join_timeout.as_secs()),
                });
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

/// Часы, которых нет: для тестов `lifecycle` без systemd. В продуктовом
/// маршруте не используется — отсутствие systemd там доходит до человека
/// отказом (инвариант 10), а не тишиной.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoScheduler;

impl Scheduler for NoScheduler {
    async fn arm(&self, _label: &Label, _after: Duration) -> Result<()> {
        Ok(())
    }

    async fn disarm(&self, _label: &Label) -> Result<()> {
        Ok(())
    }
}

/// Имя юнита для метки. Метка уже `[a-z0-9-]` — в имени юнита экранировать
/// нечего.
#[must_use]
pub fn unit_name(label: &Label) -> String {
    format!("panzir-close-{}", label.as_str())
}

/// Аргументы `systemd-run`. В них — только метка и путь бинаря: ни пароля,
/// ни пути контейнера (инвариант 5), тот берётся из реестра при срабатывании.
fn systemd_run_args(label: &Label, after: Duration, closer: &[OsString]) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("--user"),
        OsString::from("--quiet"),
        OsString::from(format!("--unit={}", unit_name(label))),
        OsString::from(on_active_arg(after)),
        // Без этого systemd батчит таймер по умолчанию до минуты (AccuracySec):
        // «закрыть через 15 минут» срабатывало бы в окне [15, 16) мин, а
        // короткий повтор при «занято» — вовсе с минутной задержкой (замер
        // 27.08). Секунда точности этому классу задач с запасом достаточна.
        OsString::from("--timer-property=AccuracySec=1s"),
    ];
    args.extend(closer.iter().cloned());
    args.push(OsString::from("--close"));
    args.push(OsString::from(label.as_str()));
    args
}

/// `--on-active=<N>s` — целые секунды: минуты не выразят таймер живого IT.
fn on_active_arg(after: Duration) -> String {
    format!("--on-active={}s", after.as_secs())
}

/// Совпадает ли `MainPID` службы с нашим: тогда бегущая служба — это мы.
/// `MainPID=0` — службы нет, и это не мы.
fn service_is_self(main_pid_line: &str, own_pid: u32) -> bool {
    main_pid_line
        .trim()
        .strip_prefix("MainPID=")
        .and_then(|pid| pid.parse::<u32>().ok())
        .is_some_and(|pid| pid != 0 && pid == own_pid)
}

/// `systemctl --user show -p MainPID <service>` → строка `MainPID=<n>`.
async fn main_pid_line(service: &str) -> Result<String> {
    let output = Command::new("systemctl")
        .args(["--user", "show", "-p", "MainPID", service])
        .output()
        .await
        .map_err(Error::Io)?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Состояния `is-active`, при которых службу нельзя считать завершённой.
fn is_busy_state(state: &str) -> bool {
    matches!(state, "active" | "activating" | "deactivating")
}

/// Запустить утилиту, не глядя на код выхода. Ошибка — только если её нет.
async fn quiet(program: &str, args: &[&str]) -> Result<()> {
    Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map_err(Error::Io)?;
    Ok(())
}

/// `systemctl --user is-active <service>` → слово состояния из stdout.
/// Код выхода не смотрим: для `inactive` он ненулевой и это не ошибка.
async fn active_state(service: &str) -> Result<String> {
    let output = Command::new("systemctl")
        .args(["--user", "is-active", service])
        .output()
        .await
        .map_err(Error::Io)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn join_args(args: &[OsString]) -> String {
    args.iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
// expect в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::vault::Label;
    use std::time::Duration;

    #[test]
    fn unit_name_is_derived_from_label() {
        let label = Label::new("work-2026").expect("label");
        assert_eq!(unit_name(&label), "panzir-close-work-2026");
    }

    /// В argv таймера — только метка и путь бинаря; ни пароля, ни пути
    /// контейнера (инвариант 5: путь берётся из реестра в момент срабатывания).
    #[test]
    fn systemd_run_args_carry_label_and_closer_only() {
        let label = Label::new("work").expect("label");
        let closer = [
            OsString::from("/opt/panzir"),
            OsString::from("--registry=/r"),
        ];
        let args = systemd_run_args(&label, Duration::from_secs(5), &closer);
        let args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "--user",
                "--quiet",
                "--unit=panzir-close-work",
                "--on-active=5s",
                "--timer-property=AccuracySec=1s",
                "/opt/panzir",
                "--registry=/r",
                "--close",
                "work",
            ]
        );
    }

    /// Секунды, не минуты: живой IT заводит таймер на 5 с.
    #[test]
    fn on_active_is_whole_seconds() {
        assert_eq!(on_active_arg(Duration::from_secs(900)), "--on-active=900s");
        assert_eq!(on_active_arg(Duration::from_millis(1500)), "--on-active=1s");
    }

    /// Закрыватель, запущенный службой таймера, не должен ждать самого себя:
    /// «бегущая служба» с нашим PID — это мы, и ждать её значит зависнуть до
    /// таймаута (поймано живыми T-25/T-26).
    #[test]
    fn running_service_is_recognised_as_self_by_main_pid() {
        assert!(service_is_self("MainPID=4242\n", 4242));
        assert!(!service_is_self("MainPID=4242\n", 1));
        assert!(
            !service_is_self("MainPID=0\n", 0),
            "no main pid is nobody, not us"
        );
        assert!(!service_is_self("garbage", 4242));
    }

    /// «Бежит» — это не только `active`: `activating`/`deactivating` тоже нельзя
    /// перебивать своим закрытием.
    #[test]
    fn busy_states_are_recognised() {
        for busy in ["active", "activating", "deactivating"] {
            assert!(is_busy_state(busy), "{busy} must count as running");
        }
        for idle in ["inactive", "failed", "", "unknown"] {
            assert!(!is_busy_state(idle), "{idle} must count as idle");
        }
    }
}
