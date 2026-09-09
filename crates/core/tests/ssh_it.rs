//! Т-5 (спека Ш-7): живая семантика OpenSSH против сниппета и строки Include.
//!
//! Харнесс — временный каталог + `ssh -G -F <temp config>` (дельта 3: ssh
//! игнорирует `HOME`, дом берётся из `getpwuid()`; `-F` отсекает и
//! пользовательский, и системный config, поэтому настоящий `~/.ssh/config`
//! разработчика прогонами даже не читается). Сьют бежит в `cargo test
//! --workspace` и в CI каждый прогон — это страж семантики OpenSSH
//! (премортем Б3.4): `Include` первой строкой выигрывает у всего ниже,
//! а сломанная механика должна ронять сьют, а не молчать.
//!
//! Skip-страж: без `ssh` в PATH тесты пропускаются (М-4) — сьют не `#[ignore]`.
//!
//! Шов назван вслух (Д-5): реальное соединение не поднимается (нет сервера);
//! доказательство — резолюция конфигурации по результату (К-7).

#![cfg(unix)]
// expect в тестах — осознанно (закон №3: unwrap/expect только в тестах и main).
#![allow(clippy::expect_used)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::Duration;

use panzir_core::registry::SshHost;
use panzir_core::ssh::{
    self, IncludeStatus, apply_include, include_line, include_status, insert_include_line,
    render_snippet, repair_include, resolution_confirms, snippet_path, write_snippet_atomic,
};
use panzir_core::vault::Label;

const SSH_G_TIMEOUT: Duration = Duration::from_secs(10);

/// Skip-страж: ssh есть в PATH?
fn ssh_available() -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join("ssh").is_file()))
}

macro_rules! require_ssh {
    () => {
        if !ssh_available() {
            eprintln!("skip: нет ssh в PATH — Т-5 пропущен (М-4)");
            return;
        }
    };
}

/// Поле работы одного сценария: временный каталог с «домом» приложения.
struct Field {
    /// Держит временный каталог живым до конца теста (RAII-уборка при Drop);
    /// пути ниже построены от него в `new`.
    _dir: tempfile::TempDir,
    /// `~/.ssh/config` поля.
    config: PathBuf,
    /// `~/.config/panzir/ssh-work.conf` поля.
    snippet: PathBuf,
    /// Симлинк `~/panzir-work` поля.
    symlink: PathBuf,
}

impl Field {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let label = Label::new("work").expect("label");
        Self {
            config: root.join(".ssh").join("config"),
            snippet: snippet_path(&root.join(".config").join("panzir"), &label),
            symlink: root.join("panzir-work"),
            _dir: dir,
        }
    }

    fn devbox(&self) -> SshHost {
        SshHost::new("devbox", "192.0.2.10", "devbox", None, "id_ed25519").expect("valid host")
    }

    /// Записать сниппет из реестра (здесь — из одного хоста), как делает
    /// приложение при добавлении/открытии.
    async fn write_snippet(&self) {
        let text = render_snippet(&[self.devbox()], &self.symlink);
        write_snippet_atomic(&self.snippet, &text)
            .await
            .expect("snippet write");
    }

    fn read_config(&self) -> String {
        std::fs::read_to_string(&self.config).expect("config readable")
    }

    fn config_mode(&self) -> u32 {
        std::fs::metadata(&self.config)
            .expect("config meta")
            .permissions()
            .mode()
            & 0o777
    }

    async fn resolves(&self, host: &str) -> ssh::ResolvedHost {
        ssh::ssh_g(host, Some(&self.config), SSH_G_TIMEOUT)
            .await
            .expect("ssh -G must run")
    }
}

/// Сценарий 1: вставка первой строкой → руками подсунутый `Host *` выше
/// ловится сверкой как `Shadowed` → починка поднимает строку первой (М-1);
/// чужое содержимое и mode сохранены (М-2). Резолюция подтверждается по
/// `ssh -G` до дрейфа и после починки (К-7).
#[tokio::test]
async fn insert_shadow_repair_cycle() {
    require_ssh!();
    let field = Field::new();
    let ssh_dir = field.config.parent().expect(".ssh").to_path_buf();
    std::fs::create_dir(&ssh_dir).expect("mkdir .ssh");
    // Чужой config: CRLF и mode 0644 — контроль байтовой сохранности.
    let foreign = "# мой конфиг\r\nHost *\r\n    ServerAliveInterval 30\r\n";
    std::fs::write(&field.config, foreign).expect("write foreign config");
    std::fs::set_permissions(&field.config, std::fs::Permissions::from_mode(0o644))
        .expect("chmod 644");
    field.write_snippet().await;
    let line = include_line(&field.snippet);

    // Вставка по подтверждению: строка первая, чужое ниже байт-в-байт.
    assert!(
        apply_include(&field.config, &field.snippet)
            .await
            .expect("apply")
    );
    assert_eq!(field.read_config(), format!("{line}\n{foreign}"));
    assert_eq!(field.config_mode(), 0o644, "mode must survive insert");
    assert_eq!(
        include_status(Some(&field.read_config()), &line),
        IncludeStatus::Ok
    );
    let resolved = field.resolves("devbox").await;
    assert!(
        resolution_confirms(&resolved, &field.symlink.join("id_ed25519")),
        "fresh insert must resolve our identity: {resolved:?}"
    );

    // Премортем Б3.1: между прогонами человек правит config и строка
    // оказывается под чужим блоком, который ставит ТЕ ЖЕ опции нашему имени
    // (безобидный `Host *` с чужими опциями не перехватывает — first-obtained
    // -wins действует поопционно, замер этого прогона). Тогда наши опции
    // проигрывают: identitiesonly из чужого блока выигрывает у сниппета.
    let hostile = "# мой конфиг\r\nHost devbox\r\n    IdentitiesOnly no\r\n";
    let drifted = format!("{hostile}{line}\n");
    std::fs::write(&field.config, &drifted).expect("hand edit");
    assert_eq!(
        include_status(Some(&field.read_config()), &line),
        IncludeStatus::Shadowed,
        "drift must be detected"
    );
    let shadowed = field.resolves("devbox").await;
    assert!(
        !resolution_confirms(&shadowed, &field.symlink.join("id_ed25519")),
        "shadowed include must NOT confirm: {shadowed:?}"
    );

    // Починка по подтверждению: строка первая (наш блок выигрывает обратно),
    // чужое нетронуто, mode тот же.
    assert!(
        repair_include(&field.config, &field.snippet)
            .await
            .expect("repair")
    );
    assert_eq!(field.read_config(), format!("{line}\n{hostile}"));
    assert_eq!(field.config_mode(), 0o644, "mode must survive repair");
    let repaired = field.resolves("devbox").await;
    assert!(
        resolution_confirms(&repaired, &field.symlink.join("id_ed25519")),
        "repaired include must confirm again: {repaired:?}"
    );
}

/// Сценарий 2: посторонний ключ по умолчанию не участвует — резолюция
/// отдаёт ровно один `identityfile` (наш) и `identitiesonly yes`.
#[tokio::test]
async fn foreign_default_key_does_not_participate() {
    require_ssh!();
    let field = Field::new();
    field.write_snippet().await;
    assert!(
        apply_include(&field.config, &field.snippet)
            .await
            .expect("apply")
    );

    let resolved = field.resolves("devbox").await;
    assert!(resolved.identities_only, "identitiesonly must be yes");
    assert_eq!(
        resolved.identity_files,
        vec![field.symlink.join("id_ed25519").display().to_string()],
        "only our identity must be listed: {resolved:?}"
    );
}

/// Сценарий 3: закрытое хранилище — config валиден, `ssh -G` резолвит наши
/// записи, но `identityfile` указывает в мёртвый симлинк: соединение упадёт
/// по аутентификации (замер 08.09, воспроизводится тестом).
#[tokio::test]
async fn closed_vault_resolves_to_dead_key_path() {
    require_ssh!();
    let field = Field::new();
    field.write_snippet().await;
    assert!(
        apply_include(&field.config, &field.snippet)
            .await
            .expect("apply")
    );
    // Хранилище закрыто: симлинка ~/panzir-work не существует вовсе.

    // `ssh -G` отдаёт конфиг без ошибок (resolve выше паникует иначе),
    // identityfile — наш, но путь мёртв.
    let resolved = field.resolves("devbox").await;
    let expected = field.symlink.join("id_ed25519");
    assert!(resolution_confirms(&resolved, &expected));
    assert!(
        !expected.exists(),
        "key path must be dead while vault is closed"
    );
}

/// Сценарий 4: пустая машина — `~/.ssh` отсутствует; вставка создаёт его
/// 0700 (М-3), config получает 0600 и одну строку.
#[tokio::test]
async fn empty_machine_gets_dotssh_0700() {
    require_ssh!();
    let field = Field::new();
    field.write_snippet().await;

    assert!(
        apply_include(&field.config, &field.snippet)
            .await
            .expect("apply")
    );
    let dir_mode = std::fs::metadata(field.config.parent().expect(".ssh"))
        .expect("meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, ".ssh mode is {dir_mode:o}");
    assert_eq!(field.config_mode(), 0o600, "new config mode");
    assert_eq!(
        field.read_config(),
        format!("{}\n", include_line(&field.snippet))
    );
    let resolved = field.resolves("devbox").await;
    assert!(resolution_confirms(
        &resolved,
        &field.symlink.join("id_ed25519")
    ));
}

/// Чистая вставка в текст — повторный вызов не плодит дубль, и это видно
/// на уровне резолюции тоже: после повторной вставки связка подтверждается.
#[tokio::test]
async fn double_insert_is_noop_and_still_resolves() {
    require_ssh!();
    let field = Field::new();
    field.write_snippet().await;
    let line = include_line(&field.snippet);

    assert!(
        apply_include(&field.config, &field.snippet)
            .await
            .expect("first")
    );
    let once = field.read_config();
    assert!(
        !apply_include(&field.config, &field.snippet)
            .await
            .expect("second")
    );
    assert_eq!(field.read_config(), once, "no duplicate line");
    assert_eq!(insert_include_line(&once, &line), once);
    let resolved = field.resolves("devbox").await;
    assert!(resolution_confirms(
        &resolved,
        &field.symlink.join("id_ed25519")
    ));
}
