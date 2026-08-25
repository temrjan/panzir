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

/// Проверяет локальные зависимости: утилиты, которыми пользуется прод-путь
/// (stat/chattr/fallocate — создание контейнера; cryptsetup — keyslot/backup,
/// PR-2) и `pkexec`. udisks2 проверяется отдельно — он требует async-контекста
/// (см. [`crate::udisks::Udisks::connect`]).
///
/// Агента аутентификации polkit здесь нет намеренно, и заводить обратно его
/// не нужно: единственный способ наблюдать регистрацию средствами polkit —
/// попытаться зарегистрировать своего, то есть занять единственный слот
/// агента сессии. У сессии без агента — ровно там, ради чего проверка и
/// существовала бы, — такая проба сама создаёт неисправность, которую должна
/// ловить. Отсутствие прав доходит до человека реактивно, в момент операции
/// (инвариант 10 `CLAUDE.md`).
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
    DepsReport { statuses }
}

#[cfg(test)]
// expect в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// Плашка обязана называть только то, что получено измерением.
    ///
    /// Порядок в ожидании значим намеренно: это порядок строк плашки, которые
    /// увидит человек. Замена на сравнение множеств тихо потеряет эту
    /// проверку — тест останется зелёным, а строки на экране смогут
    /// переставиться.
    #[test]
    fn report_names_only_what_is_actually_measured() {
        let names: Vec<&str> = check_local_deps().statuses.iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            ["stat", "chattr", "fallocate", "cryptsetup", "pkexec"],
            "плашка обязана называть только то, что проверено измерением: \
             запись, чьё значение получено догадкой, — ложная тревога при каждом запуске"
        );
    }

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
