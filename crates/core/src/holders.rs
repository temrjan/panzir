//! Поиск процессов, держащих точку монтирования открытого хранилища.
//!
//! Нужен для сообщения пользователю при отложенном автозакрытии (E-minimal):
//! вместо молчания или принудительного размонтирования окно показывает,
//! какая программа мешает закрыть сейф.

use std::path::{Path, PathBuf};

/// Один процесс: имя и пути, которые он держит (cwd + fd).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEntry {
    /// Имя процесса из `/proc/<pid>/comm`.
    pub name: String,
    /// Абсолютные пути, которые процесс держит открытыми.
    pub paths: Vec<PathBuf>,
}

/// Собрать уникальные имена процессов, у которых есть пути под `mount_point`.
///
/// Чистая функция от итератора путей: реальный `/proc` сканируется отдельно,
/// а эту часть можно протестировать на поддельных путях.
#[must_use]
pub fn holders_from_entries(
    mount_point: &Path,
    entries: impl Iterator<Item = ProcEntry>,
) -> Vec<String> {
    let mut names = Vec::new();
    for entry in entries {
        if entry
            .paths
            .iter()
            .any(|p| is_under_mount_point(p, mount_point))
            && !names.contains(&entry.name)
        {
            names.push(entry.name);
        }
    }
    names
}

/// Лежит ли `path` внутри `mount_point` (включая саму точку монтирования).
fn is_under_mount_point(path: &Path, mount_point: &Path) -> bool {
    path == mount_point || path.starts_with(mount_point)
}

/// Сканировать `/proc` и вернуть имена процессов, держащих `mount_point`.
///
/// Процессы, недоступные текущему пользователю (чужой uid, root и т.п.),
/// пропускаются молча — для них сработает общее сообщение.
#[must_use]
pub fn find_holders(mount_point: &Path) -> Vec<String> {
    holders_from_entries(mount_point, scan_proc().into_iter())
}

fn scan_proc() -> Vec<ProcEntry> {
    let mut entries = Vec::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return entries;
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid_dir = entry.path();
        let Ok(comm) = std::fs::read_to_string(pid_dir.join("comm")) else {
            continue;
        };
        let comm = comm.trim_end().to_owned();
        if comm.is_empty() {
            continue;
        }

        let mut paths = Vec::new();
        if let Ok(target) = std::fs::read_link(pid_dir.join("cwd")) {
            paths.push(target);
        }
        if let Ok(fd_dir) = std::fs::read_dir(pid_dir.join("fd")) {
            for fd in fd_dir.flatten() {
                if let Ok(target) = std::fs::read_link(fd.path()) {
                    paths.push(target);
                }
            }
        }

        entries.push(ProcEntry { name: comm, paths });
    }
    entries
}

#[cfg(test)]
// expect/unwrap в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn holders_collected_from_paths() {
        let mount = PathBuf::from("/run/media/u/panzir-work");
        let entries = vec![
            ProcEntry {
                name: "bash".to_owned(),
                paths: vec![mount.clone()],
            },
            ProcEntry {
                name: "vim".to_owned(),
                paths: vec![mount.join("doc.txt")],
            },
            ProcEntry {
                name: "firefox".to_owned(),
                paths: vec![PathBuf::from("/tmp")],
            },
        ];
        let holders = holders_from_entries(&mount, entries.into_iter());
        assert_eq!(holders, vec!["bash".to_owned(), "vim".to_owned()]);
    }

    #[test]
    fn holders_deduplicated() {
        let mount = PathBuf::from("/run/media/u/panzir-work");
        let entries = vec![ProcEntry {
            name: "vim".to_owned(),
            paths: vec![mount.clone(), mount.join("a.txt"), mount.join("b.txt")],
        }];
        let holders = holders_from_entries(&mount, entries.into_iter());
        assert_eq!(holders, vec!["vim".to_owned()]);
    }

    #[test]
    fn holders_excludes_similar_named_dirs() {
        // `starts_with` по компонентам: `panzir-work` ≠ `panzir-workdir`.
        let mount = PathBuf::from("/home/u/panzir-work");
        let entries = vec![ProcEntry {
            name: "bad".to_owned(),
            paths: vec![PathBuf::from("/home/u/panzir-workdir/secret")],
        }];
        let holders = holders_from_entries(&mount, entries.into_iter());
        assert!(holders.is_empty());
    }
}
