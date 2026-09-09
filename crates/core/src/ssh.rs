//! SSH-связка хранилища: сниппет с Host-записями и строка `Include`
//! в `~/.ssh/config` (спека Ш-7).
//!
//! Модуль-владелец внешней системы ssh (карточка К-3): наружу — типы и
//! чистые функции над текстом конфига, внутрь — разбор отказов. Чужой
//! config молча не редактируем: вставка и починка строки — только по
//! подтверждению пользователя, чужое содержимое сохраняется байт-в-байт.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt as _;

use crate::registry::SshHost;
use crate::vault::Label;

/// Ошибки SSH-связки.
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    /// Поле хоста не прошло валидацию (см. [`SshHost::new`]).
    #[error("invalid ssh host field {field}: {value:?}")]
    InvalidField {
        /// Имя поля (`host`, `hostname`, `user`, `key_file`).
        field: &'static str,
        /// Отвергнутое значение.
        value: String,
    },
    /// Ошибка ввода-вывода при записи сниппета или правке config.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Статус строки `Include` в `~/.ssh/config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncludeStatus {
    /// Строка на месте и выше неё нет `Host`/`Match` — наши записи выигрывают
    /// (first-obtained-wins, допущение Д-1).
    Ok,
    /// Строка есть, но выше неё блок `Host`/`Match` — чужие опции перехватят
    /// наши имена раньше. Лечится поднятием строки первой (М-1).
    Shadowed,
    /// Строки нет (или config отсутствует) — связка не включена.
    Missing,
}

/// Строка без обрамляющих пробелов, BOM и перевода строки — форма для
/// сравнения с нашей строкой `Include` и разбора директив.
fn canonical(line: &str) -> &str {
    line.trim().trim_start_matches('\u{feff}')
}

/// Признак директивы `Host`/`Match`: первое слово строки (без учёта регистра).
/// `HostName` сюда не попадает — сравнение слова целиком, не по префиксу.
fn is_host_or_match(line: &str) -> bool {
    let word = canonical(line)
        .split_whitespace()
        .next()
        .unwrap_or_default();
    word.eq_ignore_ascii_case("host") || word.eq_ignore_ascii_case("match")
}

/// Путь сниппета `<config_dir>/ssh-<метка>.conf`.
pub fn snippet_path(config_dir: &Path, label: &Label) -> PathBuf {
    config_dir.join(format!("ssh-{label}.conf"))
}

/// Строка `Include <абс.путь сниппета>` для вставки в `~/.ssh/config`.
pub fn include_line(snippet: &Path) -> String {
    format!("Include {}", snippet.display())
}

/// Отрендерить сниппет с Host-записями из реестра.
///
/// `IdentityFile` указывает на ключ внутри открытого тома через симлинк
/// `~/panzir-<метка>`; `IdentitiesOnly yes` — всегда (спека Ш-7), чтобы
/// посторонние ключи по умолчанию не участвовали. `Port` пишется только при
/// `Some`. Экранирование не нужно: поля валидированы в [`SshHost::new`].
#[must_use]
pub fn render_snippet(hosts: &[SshHost], symlink: &Path) -> String {
    let mut out = String::new();
    for h in hosts {
        out.push_str("Host ");
        out.push_str(&h.host);
        out.push_str("\n    HostName ");
        out.push_str(&h.hostname);
        out.push_str("\n    User ");
        out.push_str(&h.user);
        out.push('\n');
        if let Some(port) = h.port {
            out.push_str("    Port ");
            out.push_str(&port.to_string());
            out.push('\n');
        }
        out.push_str("    IdentityFile ");
        out.push_str(&symlink.join(&h.key_file).display().to_string());
        out.push_str("\n    IdentitiesOnly yes\n");
    }
    out
}

/// Статус строки `Include` в тексте config (`None` — файла нет).
///
/// Строка первая и выше неё нет `Host`/`Match` (комментарии и пустые строки
/// не считаются) → [`IncludeStatus::Ok`]; выше есть `Host`/`Match` →
/// [`IncludeStatus::Shadowed`]; строки нет → [`IncludeStatus::Missing`].
#[must_use]
pub fn include_status(config: Option<&str>, include_line: &str) -> IncludeStatus {
    let Some(text) = config else {
        return IncludeStatus::Missing;
    };
    let Some(idx) = text.lines().position(|l| canonical(l) == include_line) else {
        return IncludeStatus::Missing;
    };
    let shadowed = text.lines().take(idx).any(|l| {
        let c = canonical(l);
        !c.is_empty() && !c.starts_with('#') && is_host_or_match(l)
    });
    if shadowed {
        IncludeStatus::Shadowed
    } else {
        IncludeStatus::Ok
    }
}

/// Имя нашего хоста уже занято в чужом config → `Some(имя)`.
///
/// Совпадение только внутри нашего сниппета сюда не попадает по построению:
/// на вход подаётся текст чужого config. `Host *` — не совпадение имени
/// (точное равенство токена; перехват опций через `*` ловит
/// [`include_status`] как `Shadowed`).
#[must_use]
pub fn detect_collision(config: &str, hosts: &[SshHost]) -> Option<String> {
    for line in config.lines() {
        let c = canonical(line);
        if c.is_empty() || c.starts_with('#') {
            continue;
        }
        let mut words = c.split_whitespace();
        let Some(keyword) = words.next() else {
            continue;
        };
        if !keyword.eq_ignore_ascii_case("host") {
            continue;
        }
        for pattern in words {
            if let Some(h) = hosts.iter().find(|h| h.host == pattern) {
                return Some(h.host.clone());
            }
        }
    }
    None
}

/// Текст config со строкой `Include` первой. Идемпотентно: строка уже есть
/// (в любом месте) — текст возвращается без изменений. Чужое содержимое
/// сохраняется байт-в-байт ниже вставленной строки; BOM остаётся первым
/// байтом файла.
#[must_use]
pub fn insert_include_line(text: &str, include_line: &str) -> String {
    if text.lines().any(|l| canonical(l) == include_line) {
        return text.to_owned();
    }
    match text.strip_prefix('\u{feff}') {
        Some(rest) => format!("\u{feff}{include_line}\n{rest}"),
        None => format!("{include_line}\n{text}"),
    }
}

/// Починка `Shadowed` (М-1): удалить строку `Include` где бы она ни была и
/// вставить первой. Остальное содержимое сохраняется байт-в-байт, включая
/// чужие переводы строк (CRLF) и BOM.
#[must_use]
pub fn repair_include_first(text: &str, include_line: &str) -> String {
    let without: String = text
        .split_inclusive('\n')
        .filter(|chunk| canonical(chunk) != include_line)
        .collect();
    insert_include_line(&without, include_line)
}

/// Атомарно (пере)записать сниппет с правами 0600 — образец
/// `Registry::save_atomic`: временный файл `create_new` + mode → write →
/// flush → sync_all → rename поверх старого. Сниппет — производная реестра,
/// перезапись штатна. Родительский каталог создаётся 0700, если его нет.
///
/// # Errors
/// [`SshError::Io`] — ошибка FS.
pub async fn write_snippet_atomic(path: &Path, text: &str) -> Result<(), SshError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
        tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;
    }

    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp = path.with_extension(format!("tmp.{}-{}", std::process::id(), uniq));

    let write_result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp)
            .await?;
        file.write_all(text.as_bytes()).await?;
        file.flush().await?;
        file.sync_all().await?;
        Ok::<(), std::io::Error>(())
    }
    .await;

    if let Err(e) = write_result {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(e.into());
    }

    if let Err(e) = tokio::fs::rename(&temp, path).await {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(e.into());
    }
    Ok(())
}

#[cfg(test)]
// expect/unwrap в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const INC: &str = "Include /home/u/.config/panzir/ssh-work.conf";

    fn devbox() -> SshHost {
        SshHost::new("devbox", "192.0.2.10", "devbox", Some(9281), "id_ed25519")
            .expect("valid host")
    }

    fn nas() -> SshHost {
        SshHost::new("nas", "nas.lan", "root", None, "id_nas").expect("valid host")
    }

    /// Сниппет пишется атомарно, с правами 0600 и перезаписывается поверх
    /// старого; родитель создаётся 0700.
    #[tokio::test]
    async fn snippet_write_is_atomic_and_restricted() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("ssh-work.conf");
        write_snippet_atomic(&path, "Host devbox\n")
            .await
            .expect("write snippet");

        let text = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(text, "Host devbox\n");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "snippet mode is {mode:o}, expected 600");
        let parent_mode = std::fs::metadata(path.parent().expect("parent"))
            .expect("parent meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(parent_mode, 0o700, "parent mode is {parent_mode:o}");

        // Перезапись поверх существующего — штатна (производная реестра).
        write_snippet_atomic(&path, "Host nas\n")
            .await
            .expect("rewrite snippet");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "Host nas\n");
        // Временных файлов рядом не остаётся.
        let leftovers = std::fs::read_dir(path.parent().expect("parent"))
            .expect("read dir")
            .count();
        assert_eq!(leftovers, 1, "only the snippet should remain");
    }

    #[test]
    fn snippet_path_and_include_line() {
        let label = Label::new("work").expect("label");
        let p = snippet_path(Path::new("/home/u/.config/panzir"), &label);
        assert_eq!(p, PathBuf::from("/home/u/.config/panzir/ssh-work.conf"));
        assert_eq!(include_line(&p), INC);
    }

    #[test]
    fn render_sets_identities_only_and_identity_via_symlink() {
        let out = render_snippet(&[devbox()], Path::new("/home/u/panzir-work"));
        assert_eq!(
            out,
            "Host devbox\n    HostName 192.0.2.10\n    User devbox\n    Port 9281\n    IdentityFile /home/u/panzir-work/id_ed25519\n    IdentitiesOnly yes\n"
        );
    }

    #[test]
    fn render_writes_port_only_when_some() {
        let out = render_snippet(&[nas()], Path::new("/home/u/panzir-nas"));
        assert!(!out.contains("Port"), "no Port line expected:\n{out}");
        assert!(out.contains("IdentityFile /home/u/panzir-nas/id_nas\n"));
        assert!(out.contains("IdentitiesOnly yes\n"));
    }

    #[test]
    fn render_two_hosts_keeps_both_blocks() {
        let out = render_snippet(&[devbox(), nas()], Path::new("/home/u/panzir-work"));
        assert!(out.starts_with("Host devbox\n"));
        assert!(out.contains("Host nas\n"));
    }

    #[test]
    fn insert_into_empty_text_is_single_line() {
        assert_eq!(insert_include_line("", INC), format!("{INC}\n"));
    }

    #[test]
    fn insert_is_idempotent() {
        let once = insert_include_line("Host *\n", INC);
        assert_eq!(insert_include_line(&once, INC), once);
    }

    #[test]
    fn insert_preserves_foreign_content_byte_for_byte() {
        let foreign = "Host *\n    ServerAliveInterval 30\r\n# мой комментарий\r\n";
        let out = insert_include_line(foreign, INC);
        assert_eq!(out, format!("{INC}\n{foreign}"));
    }

    #[test]
    fn insert_keeps_bom_first_byte() {
        let foreign = "\u{feff}Host *\n";
        let out = insert_include_line(foreign, INC);
        assert_eq!(out, format!("\u{feff}{INC}\nHost *\n"));
    }

    #[test]
    fn status_missing_when_config_absent_or_line_absent() {
        assert_eq!(include_status(None, INC), IncludeStatus::Missing);
        assert_eq!(
            include_status(Some("Host *\n"), INC),
            IncludeStatus::Missing
        );
    }

    #[test]
    fn status_ok_when_line_first_and_only_comments_above() {
        let cfg = format!("# шапка\n\n{INC}\nHost *\n    ServerAliveInterval 30\n");
        assert_eq!(include_status(Some(&cfg), INC), IncludeStatus::Ok);
    }

    #[test]
    fn status_shadowed_when_host_or_match_above() {
        let cfg = format!("Host *\n    ServerAliveInterval 30\n{INC}\n");
        assert_eq!(include_status(Some(&cfg), INC), IncludeStatus::Shadowed);
        let cfg = format!("Match user bob\n{INC}\n");
        assert_eq!(include_status(Some(&cfg), INC), IncludeStatus::Shadowed);
    }

    #[test]
    fn collision_detected_in_foreign_config() {
        let cfg = "Host devbox\n    HostName 203.0.113.5\n";
        assert_eq!(
            detect_collision(cfg, &[devbox()]),
            Some("devbox".to_owned())
        );
    }

    #[test]
    fn collision_none_when_name_only_in_our_snippet() {
        // Чужой config наших имён не содержит — совпадение в нашем сниппете
        // сюда не попадает по построению (на вход только чужой текст).
        let cfg = "Host other\n    HostName 198.51.100.7\n";
        assert_eq!(detect_collision(cfg, &[devbox()]), None);
    }

    #[test]
    fn collision_host_star_is_not_name_match() {
        assert_eq!(detect_collision("Host *\n", &[devbox()]), None);
    }

    #[test]
    fn repair_moves_line_to_first_preserving_foreign_bytes() {
        let foreign = "Host *\n    ServerAliveInterval 30\r\n# хвост\r\n";
        let drifted = format!("{foreign}{INC}\r\n");
        let fixed = repair_include_first(&drifted, INC);
        assert_eq!(fixed, format!("{INC}\n{foreign}"));
        // Повторная починка — без изменений.
        assert_eq!(repair_include_first(&fixed, INC), fixed);
    }
}
