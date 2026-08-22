//! Проверка зависимостей при старте (спека v1.1, п.13 скоупа).
//!
//! Приложение обязано упасть с внятным текстом, а не молча не работать
//! и не откатываться на sudo.

use std::ffi::OsStr;

/// Статус одной зависимости.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepStatus {
    /// Имя зависимости.
    pub name: &'static str,
    /// Найдена и работает.
    pub ok: bool,
    /// Подсказка, что установить, если `ok == false`.
    pub hint: String,
}

/// Итог проверки всех зависимостей.
#[derive(Debug, Clone)]
pub struct DepsReport {
    /// По одной записи на зависимость.
    pub statuses: Vec<DepStatus>,
}

impl DepsReport {
    /// Все ли зависимости в порядке. Пустой отчёт — НЕ «всё в порядке»
    /// (fail-closed): пустой Vec означает, что проверки просто не бежали.
    #[must_use]
    pub fn all_ok(&self) -> bool {
        !self.statuses.is_empty() && self.statuses.iter().all(|s| s.ok)
    }

    /// Только сломанные зависимости — для экрана ошибки.
    pub fn broken(&self) -> impl Iterator<Item = &DepStatus> {
        self.statuses.iter().filter(|s| !s.ok)
    }
}

/// Ищет исполняемый файл в заданном PATH (шов для детерминированных тестов).
fn in_path_in(paths: Option<&OsStr>, bin: &str) -> bool {
    paths.is_some_and(|p| {
        std::env::split_paths(p).any(|dir| {
            let candidate = dir.join(bin);
            // is_file, не exists: каталог с таким именем — не бинарь.
            candidate.is_file()
        })
    })
}

/// Ищет исполняемый файл в реальном PATH процесса.
fn in_path(bin: &str) -> bool {
    in_path_in(std::env::var_os("PATH").as_deref(), bin)
}

/// Известные polkit-агенты аутентификации (процесс диалога ввода пароля).
const POLKIT_AGENTS: &[&str] = &[
    "polkit-gnome-authentication-agent",
    "gcr-prompter",
    "polkit-kde-authentication-agent",
    "lxqt-policykit-agent",
    "mate-polkit",
    "pantheon-agent-polkit",
    "polkit-efl-authentication-agent",
];

/// Совпадает ли cmdline с известным агентом — по basename argv[0], не по
/// подстроке: `grep mate-polkit notes.md` не должен считаться агентом.
fn cmdline_is_polkit_agent(cmdline: &[u8]) -> bool {
    let argv0 = cmdline.split(|&b| b == 0).next().unwrap_or(cmdline);
    let base = argv0.rsplit(|&b| b == b'/').next().unwrap_or(argv0);
    let Ok(base) = std::str::from_utf8(base) else {
        return false;
    };
    POLKIT_AGENTS.contains(&base)
}

/// Жив ли хоть один polkit-агент сессии (обход /proc/*/cmdline).
fn polkit_agent_alive() -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    entries
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .chars()
                .all(|c| c.is_ascii_digit())
        })
        .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
        .any(|cmdline| cmdline_is_polkit_agent(&cmdline))
}

/// Проверяет локальные зависимости: утилиты, которыми пользуется прод-путь
/// (stat/chattr/fallocate — создание контейнера; cryptsetup — keyslot/backup,
/// PR-2), pkexec и polkit-агента. udisks2 проверяется отдельно — он требует
/// async-контекста (см. [`crate::udisks::Udisks::connect`]).
#[must_use]
pub fn check_local_deps() -> DepsReport {
    let mut statuses = Vec::new();
    for (name, hint) in [
        ("stat", "coreutils"),
        ("chattr", "e2fsprogs"),
        ("fallocate", "util-linux"),
        ("cryptsetup", "cryptsetup"),
        ("pkexec", "polkit"),
    ] {
        statuses.push(DepStatus {
            name,
            ok: in_path(name),
            hint: format!("установите пакет {hint} (dnf install {hint})"),
        });
    }
    statuses.push(DepStatus {
        name: "polkit agent",
        ok: polkit_agent_alive(),
        hint: "войдите в графическую сессию с агентом аутентификации polkit \
               (в GNOME он встроен)"
            .to_owned(),
    });
    DepsReport { statuses }
}

#[cfg(test)]
// expect в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn in_path_finds_and_rejects_deterministically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = std::env::join_paths([dir.path()]).expect("join");
        // Пустой каталог — бинаря нет.
        assert!(!in_path_in(Some(&paths), "cryptsetup"));
        // Появился файл — находится.
        std::fs::write(dir.path().join("cryptsetup"), b"#!/bin/sh\n").expect("write");
        assert!(in_path_in(Some(&paths), "cryptsetup"));
        // Каталог с тем же именем — не бинарь.
        std::fs::create_dir(dir.path().join("fallocate")).expect("mkdir");
        assert!(!in_path_in(Some(&paths), "fallocate"));
        // PATH отсутствует вовсе.
        assert!(!in_path_in(None, "cryptsetup"));
    }

    #[test]
    fn polkit_agent_cmdline_matches_argv0_basename_only() {
        // Настоящий агент: полный путь в argv[0].
        assert!(cmdline_is_polkit_agent(
            b"/usr/libexec/polkit-gnome-authentication-agent\0".as_slice()
        ));
        // Декой: имя агента в аргументе, не в argv[0].
        assert!(!cmdline_is_polkit_agent(
            b"grep\0mate-polkit\0notes.md\0".as_slice()
        ));
        // Пустой cmdline (kernel thread) — не агент.
        assert!(!cmdline_is_polkit_agent(b"".as_slice()));
    }

    #[test]
    fn empty_report_is_not_ok() {
        let report = DepsReport { statuses: vec![] };
        assert!(!report.all_ok(), "empty report must be fail-closed");
    }

    #[test]
    fn report_splits_ok_and_broken() {
        let report = DepsReport {
            statuses: vec![
                DepStatus {
                    name: "a",
                    ok: true,
                    hint: String::new(),
                },
                DepStatus {
                    name: "b",
                    ok: false,
                    hint: "install b".to_owned(),
                },
            ],
        };
        assert!(!report.all_ok());
        assert_eq!(report.broken().count(), 1);
    }
}
