//! Экран 1 — список хранилищ, управление записями и плашка окружения.
//!
//! Экран ничего не знает про асинхронность: он рисует данные и возвращает
//! намерение человека. Превращает намерение в операцию [`crate::app::App`].

use eframe::egui;
use panzir_core::registry::VaultEntry;
use panzir_core::ssh::IncludeStatus;
use panzir_core::vault::{Label, VaultKind, VaultState};

use crate::app::{
    DeleteDraft, EnvLine, HolderStatus, ListLoad, Notice, NoticeScope, Operation, SshCardStatus,
    SshConfirm, busy_message, kind_text, state_text,
};

/// Начатое переименование: какую запись меняем и что уже набрано.
pub(crate) struct RenameDraft {
    /// Метка, которую меняем.
    pub(crate) target: Label,
    /// Текущий ввод.
    pub(crate) text: String,
}

/// Начатый ввод парольной фразы: для какой записи и что набрано.
///
/// Буфер здесь — обычная `String`: другого способа принять ввод у egui нет.
/// Живёт он ровно до нажатия кнопки — [`crate::app::App`] забирает содержимое
/// `mem::take` и сразу кладёт в `SecretString`.
pub(crate) struct UnlockDraft {
    /// Метка записи, которую открывают.
    pub(crate) target: Label,
    /// Набранное.
    pub(crate) text: String,
}

/// Начатое добавление SSH-хоста: для какой записи и что набрано.
/// Поля — сырые строки; проверяет ядро (`SshHost::new`) при отправке.
pub(crate) struct SshHostDraft {
    /// Метка записи, к которой добавляют хоста.
    pub(crate) target: Label,
    /// Алиас (`Host`), как его наберут в командной строке.
    pub(crate) host: String,
    /// Адрес (`HostName`).
    pub(crate) hostname: String,
    /// Логин (`User`).
    pub(crate) user: String,
    /// Порт — пусто или число (`Port` пишется только при числе).
    pub(crate) port: String,
    /// Имя файла ключа внутри хранилища.
    pub(crate) key_file: String,
}

use crate::theme::{self, ButtonKind};

/// Намерения, которые применяет App после последнего store виджетов кадра.
pub(crate) enum ListAction {
    BeginUnlock(Label),
    ToggleDetails(Label),
    BeginRename(Label),
    BeginSshHost(Label),
    Cancel,
    Open(Label),
    Close(Label),
    AskDelete(Label),
    ConfirmDelete,
    CommitRename {
        old: Label,
        new: String,
    },
    StartCreate,
    Reload,
    AddSshHost {
        target: Label,
        host: String,
        hostname: String,
        user: String,
        port: String,
        key_file: String,
    },
    AskSshInclude {
        target: Label,
        repair: bool,
    },
    ConfirmSshInclude,
    Dismiss(NoticeScope),
}

/// Данные и предоставленные App буферы; view не заменяет черновики.
pub(crate) struct ListInput<'a> {
    pub(crate) entries: &'a [VaultEntry],
    pub(crate) env: &'a [EnvLine],
    pub(crate) message: Option<&'a str>,
    pub(crate) validation_scope: &'a NoticeScope,
    pub(crate) notices: &'a [Notice],
    pub(crate) read_error: Option<&'a str>,
    pub(crate) load: ListLoad,
    pub(crate) busy: bool,
    pub(crate) operation: Option<&'a Operation>,
    pub(crate) holder: Option<&'a HolderStatus>,
    pub(crate) rename: &'a mut Option<RenameDraft>,
    pub(crate) unlock: &'a mut Option<UnlockDraft>,
    pub(crate) ssh_draft: &'a mut Option<SshHostDraft>,
    pub(crate) ssh_status: &'a Option<SshCardStatus>,
    pub(crate) ssh_confirm: &'a mut Option<SshConfirm>,
    pub(crate) delete: &'a mut Option<DeleteDraft>,
    pub(crate) expanded: &'a Option<Label>,
}

pub(crate) fn notice(ui: &mut egui::Ui, n: &Notice) -> Option<ListAction> {
    let mut action = None;
    egui::Frame::new()
        .fill(theme::DANGER_BG)
        .stroke(egui::Stroke::new(1.0, theme::DANGER_BORDER))
        .corner_radius(7)
        .inner_margin(14)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.colored_label(theme::DANGER, &n.title);
            if let NoticeScope::Card(label) | NoticeScope::Create(label) = &n.scope {
                theme::helper(ui, &format!("Хранилище: {label}"));
            }
            ui.add(egui::Label::new(&n.text).wrap().selectable(true));
            if theme::button(
                ui,
                &n.scope.key(),
                "dismiss",
                "Скрыть сообщение",
                "Скрыть сообщение",
                true,
                ButtonKind::Neutral,
            )
            .clicked()
            {
                action = Some(ListAction::Dismiss(n.scope.clone()));
            }
        });
    action
}

pub(crate) fn show(ui: &mut egui::Ui, mut input: ListInput<'_>) -> Option<ListAction> {
    theme::centered(ui, 660.0, |ui| {
        let mut action = None;
        let create_width = theme::button_width(ui, "Создать хранилище");
        ui.horizontal_wrapped(|ui| {
            let title_width = (ui.available_width() - create_width - 28.0).max(170.0);
            ui.allocate_ui_with_layout(
                egui::vec2(title_width, 42.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.set_min_width(title_width);
                    ui.heading("Хранилища");
                },
            );
            if theme::button(
                ui,
                "list",
                "create",
                "Создать хранилище",
                "Создать хранилище",
                !input.busy,
                ButtonKind::Primary,
            )
            .clicked()
            {
                action = Some(ListAction::StartCreate);
            }
        });
        if input.load == ListLoad::Loading {
            ui.label("Загружаем список…");
        } else if let Some(op) = input.operation {
            let r = ui.add(
                egui::Label::new(op.status())
                    .sense(egui::Sense::focusable_noninteractive())
                    .wrap(),
            );
            if ui
                .ctx()
                .data(|d| d.get_temp::<egui::Id>(egui::Id::new("panzir-focus-request")))
                == Some(theme::id("list", "status"))
            {
                r.request_focus();
                ui.ctx()
                    .data_mut(|d| d.remove::<egui::Id>(egui::Id::new("panzir-focus-request")));
            }
        }
        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt("vault-list-scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                show_env(ui, input.env);
                if let Some(error) = input.read_error {
                    ui.colored_label(theme::DANGER, "Не удалось прочитать список хранилищ");
                    ui.add(egui::Label::new(error).wrap().selectable(true));
                    if theme::button(
                        ui,
                        "list",
                        "reload",
                        "Обновить список",
                        "Обновить список",
                        !input.busy,
                        ButtonKind::Neutral,
                    )
                    .clicked()
                    {
                        action = Some(ListAction::Reload);
                    }
                }
                for n in input.notices.iter().filter(|n| match &n.scope {
                    NoticeScope::Card(label) => !input.entries.iter().any(|e| e.label() == label),
                    _ => true,
                }) {
                    if let Some(a) = notice(ui, n) {
                        action = Some(a);
                    }
                }
                if matches!(
                    input.validation_scope,
                    NoticeScope::Global | NoticeScope::Create(_)
                ) && let Some(message) = input.message
                {
                    ui.colored_label(theme::DANGER, message);
                }
                if input.entries.is_empty() && input.load == ListLoad::Loaded {
                    theme::card(ui).show(ui, |ui| {
                        ui.label(egui::RichText::new("Хранилищ пока нет").size(22.0));
                        ui.label("Создайте хранилище для файлов");
                    });
                }
                for entry in input.entries {
                    ui.scope_builder(
                        egui::UiBuilder::new().id(theme::id(entry.label().as_str(), "card")),
                        |ui| {
                            if let Some(a) = show_entry(ui, entry, &mut input) {
                                action = Some(a);
                            }
                        },
                    );
                    ui.add_space(4.0); // item_spacing 12 + 4 = 16
                }
            });
        action
    })
}

fn show_env(ui: &mut egui::Ui, env: &[EnvLine]) {
    if !env.iter().any(|l| !l.ok) {
        return;
    }
    ui.colored_label(theme::DANGER, "Для работы не хватает компонентов");
    for line in env.iter().filter(|l| !l.ok) {
        ui.add(
            egui::Label::new(format!("{}: {}", line.name, line.hint))
                .wrap()
                .selectable(true),
        );
    }
    ui.separator();
}

fn show_entry(
    ui: &mut egui::Ui,
    entry: &VaultEntry,
    input: &mut ListInput<'_>,
) -> Option<ListAction> {
    let label = entry.label();
    let name = label.as_str();
    let enabled = !input.busy;
    let expanded = input.expanded.as_ref() == Some(label);
    let mut action = None;
    theme::card(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        let primary_text = if matches!(entry.state(), VaultState::Open { .. }) { "Закрыть" } else { "Открыть" };
        let primary_width = theme::button_width(ui, primary_text);
        ui.horizontal_wrapped(|ui| {
            let title_width = (ui.available_width() - primary_width - 28.0).max(160.0);
            ui.allocate_ui_with_layout(egui::vec2(title_width, 58.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                ui.set_min_width(title_width);
                ui.label(egui::RichText::new(name).size(22.0).strong());
                let state = if entry.close_attempts() > 0 && matches!(entry.state(), VaultState::Open { .. }) { "Открыто · закрытие отложено" } else { state_text(entry.state()) };
                ui.label(egui::RichText::new(format!("{} · {state}", kind_text(entry.kind()))).size(16.0).color(theme::MUTED));
            });
            let open = matches!(entry.state(), VaultState::Open { .. });
            let text = if open { "Закрыть" } else { "Открыть" };
            if theme::button(ui, name, "primary", text, &format!("{text} хранилище {name}"), enabled, ButtonKind::Neutral).clicked() {
                action = Some(if open { ListAction::Close(label.clone()) } else { ListAction::BeginUnlock(label.clone()) });
            }
        });
        if let VaultState::Open { mount_point, .. } = entry.state() {
            theme::helper(ui, "Папка хранилища"); theme::technical(ui, mount_point.display().to_string());
            if entry.close_attempts() > 0 {
                let names = input.holder.filter(|h| h.label == *label && h.mount_point == *mount_point).map_or(&[][..], |h| h.names.as_slice());
                ui.label(busy_message(names));
            }
        }
        if let Some(op) = input.operation.filter(|o| o.target.as_ref() == Some(label)) { ui.label(op.status()); }
        for n in input.notices.iter().filter(|n| n.scope == NoticeScope::Card(label.clone())) { if let Some(a) = notice(ui, n) { action = Some(a); } }
        if *input.validation_scope == NoticeScope::Card(label.clone()) && let Some(message) = input.message { ui.colored_label(theme::DANGER, message); }
        if let Some(d) = input.unlock.as_mut().filter(|d| d.target == *label) {
            let response = theme::field(ui, (name, "unlock"), "Пароль хранилища", &mut d.text, true, enabled, "");
            let valid = !d.text.is_empty() && enabled;
            let enter = theme::enter(ui, &[response]);
            ui.horizontal_wrapped(|ui| {
                if theme::button(ui, name, "unlock-submit", "Открыть", &format!("Открыть с паролем {name}"), valid, ButtonKind::Primary).clicked() || (valid && enter) { action = Some(ListAction::Open(label.clone())); }
                if theme::button(ui, name, "cancel", "Отмена", "Отмена", true, ButtonKind::Neutral).clicked() { action = Some(ListAction::Cancel); }
            });
        }
        let details = if expanded { "Свернуть" } else { "Подробнее" };
        if theme::button(ui, name, "details", details, &format!("{details} {name}"), true, ButtonKind::Neutral).clicked() { action = Some(ListAction::ToggleDetails(label.clone())); }
        if !expanded { return; }
        ui.separator();
        match entry.kind() { VaultKind::File(path) => { theme::helper(ui, "Файл хранилища"); theme::technical(ui, path.display().to_string()); }, VaultKind::Device { uuid } => { theme::helper(ui, "UUID тома"); theme::technical(ui, uuid); } }
        theme::helper(ui, "Формат: стандартный LUKS2 — открывается GNOME Disks и cryptsetup");
        if let Some(a) = show_ssh(ui, entry, input) { action = Some(a); }
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            if theme::button(ui, name, "rename", "Переименовать", &format!("Переименовать {name}"), enabled, ButtonKind::Neutral).clicked() { action = Some(ListAction::BeginRename(label.clone())); }
            if theme::button(ui, name, "delete", "Удалить из списка", &format!("Удалить из списка {name}"), enabled, ButtonKind::Danger).clicked() { action = Some(ListAction::AskDelete(label.clone())); }
        });
        if let Some(d) = input.rename.as_mut().filter(|d| d.target == *label) {
            let field = theme::field(ui, (name, "rename-field"), "Новое название", &mut d.text, false, enabled, "");
            let enter = theme::enter(ui, &[field]);
            ui.horizontal_wrapped(|ui| {
                if theme::button(ui, name, "rename-submit", "Сохранить", "Сохранить", enabled, ButtonKind::Primary).clicked() || (enabled && enter) { action = Some(ListAction::CommitRename { old: label.clone(), new: d.text.clone() }); }
                if theme::button(ui, name, "cancel", "Отмена", "Отмена", true, ButtonKind::Neutral).clicked() { action = Some(ListAction::Cancel); }
            });
        }
        if let Some(d) = input.delete.as_mut().filter(|d| d.target == *label) {
            ui.separator();
            ui.label(if d.orphan {
                "Файла хранилища нет на месте. Если он на отключённом носителе — подключите его и отмените удаление. Если переместили или удалили — удалится только запись и SSH-след, хранилище из списка придётся добавлять заново.".to_owned()
            } else {
                format!("Будет удалено: — запись «{label}» из списка; — SSH-связка (строка в ~/.ssh/config и файл-сниппет); — симлинк ~/panzir-{label}. Если хранилище открыто, оно будет закрыто. Файл хранилища остаётся на диске — данные не пострадают, хранилище можно добавить заново. Для подтверждения введите парольную фразу хранилища.")
            });
            if !d.orphan { theme::field(ui, (name, "delete-password"), "Парольная фраза:", &mut d.passphrase, true, enabled, ""); }
            ui.horizontal_wrapped(|ui| {
                if theme::button(ui, name, "delete-submit", "Удалить", "Удалить", enabled && (d.orphan || !d.passphrase.is_empty()), ButtonKind::Danger).clicked() { action = Some(ListAction::ConfirmDelete); }
                if theme::button(ui, name, "cancel", "Отмена", "Отмена", true, ButtonKind::Neutral).clicked() { action = Some(ListAction::Cancel); }
            });
        }
    });
    action
}

fn show_ssh(
    ui: &mut egui::Ui,
    entry: &VaultEntry,
    input: &mut ListInput<'_>,
) -> Option<ListAction> {
    let label = entry.label();
    let name = label.as_str();
    let enabled = !input.busy;
    let mut action = None;
    ui.label("SSH-подключения");
    if entry.ssh_hosts().is_empty() {
        theme::helper(ui, "Хостов пока нет");
    } else {
        for h in entry.ssh_hosts() {
            theme::technical(
                ui,
                format!(
                    "{} → {}@{}{} · ключ {}",
                    h.host,
                    h.user,
                    h.hostname,
                    h.port.map_or(String::new(), |p| format!(":{p}")),
                    h.key_file
                ),
            );
        }
        if !matches!(entry.state(), VaultState::Open { .. }) {
            ui.label("Хранилище закрыто — SSH-ключи недоступны");
        }
        if let Some(status) = input.ssh_status.as_ref().filter(|s| s.label == *label) {
            if let Some(e) = &status.error {
                ui.colored_label(
                    theme::DANGER,
                    format!("Ваш ~/.ssh/config не прочитался: {e}"),
                );
            }
            match status.include {
                IncludeStatus::Ok => {
                    ui.label("связка включена: строка Include — первая в ~/.ssh/config");
                }
                IncludeStatus::Missing => {
                    if theme::button(
                        ui,
                        name,
                        "include",
                        "Включить SSH-связку",
                        &format!("Включить SSH-связку {name}"),
                        enabled,
                        ButtonKind::Neutral,
                    )
                    .clicked()
                    {
                        action = Some(ListAction::AskSshInclude {
                            target: label.clone(),
                            repair: false,
                        });
                    }
                }
                IncludeStatus::Shadowed => {
                    ui.colored_label(theme::DANGER, "строка Include съехала ниже чужого блока Host/Match — наши имена будут перехвачены");
                    if theme::button(
                        ui,
                        name,
                        "include",
                        "Поднять строку первой",
                        &format!("Поднять строку первой {name}"),
                        enabled,
                        ButtonKind::Neutral,
                    )
                    .clicked()
                    {
                        action = Some(ListAction::AskSshInclude {
                            target: label.clone(),
                            repair: true,
                        });
                    }
                }
            }
            if let Some(n) = &status.collision {
                ui.colored_label(theme::DANGER, format!("имя «{n}» уже занято в вашем ~/.ssh/config — переименуйте хоста, иначе сработает чужая запись"));
            }
            for r in &status.resolutions {
                if r.ok {
                    ui.label(format!("{}: ssh -G подтверждает связку", r.host));
                } else {
                    ui.colored_label(theme::DANGER, format!("{}: {}", r.host, r.detail.as_deref().unwrap_or("ssh -G не подтверждает связку — нет нашего identityfile или identitiesonly yes")));
                }
            }
        } else {
            theme::helper(ui, "Проверяем SSH-настройки…");
        }
    }
    if let Some(c) = input.ssh_confirm.as_ref().filter(|c| c.target == *label) {
        ui.label(if c.repair {
            "Строка будет поднята первой:"
        } else {
            "В ваш ~/.ssh/config будет вставлена строка:"
        });
        theme::technical(ui, &c.line);
        ui.horizontal_wrapped(|ui| {
            if theme::button(
                ui,
                name,
                "include-submit",
                "Подтвердить",
                "Подтвердить",
                enabled,
                ButtonKind::Primary,
            )
            .clicked()
            {
                action = Some(ListAction::ConfirmSshInclude);
            }
            if theme::button(
                ui,
                name,
                "cancel",
                "Отмена",
                "Отмена",
                true,
                ButtonKind::Neutral,
            )
            .clicked()
            {
                action = Some(ListAction::Cancel);
            }
        });
    }
    if theme::button(
        ui,
        name,
        "ssh-host",
        "Добавить хост",
        &format!("Добавить хост {name}"),
        enabled,
        ButtonKind::Neutral,
    )
    .clicked()
    {
        action = Some(ListAction::BeginSshHost(label.clone()));
    }
    if let Some(d) = input.ssh_draft.as_mut().filter(|d| d.target == *label) {
        let fields = [
            theme::field(
                ui,
                (name, "ssh-host-field"),
                "Имя хоста",
                &mut d.host,
                false,
                enabled,
                "devbox",
            ),
            theme::field(
                ui,
                (name, "ssh-address"),
                "Адрес",
                &mut d.hostname,
                false,
                enabled,
                "",
            ),
            theme::field(
                ui,
                (name, "ssh-user"),
                "Логин",
                &mut d.user,
                false,
                enabled,
                "",
            ),
            theme::field(
                ui,
                (name, "ssh-port"),
                "Порт (необязательно)",
                &mut d.port,
                false,
                enabled,
                "",
            ),
            theme::field(
                ui,
                (name, "ssh-key"),
                "Файл ключа",
                &mut d.key_file,
                false,
                enabled,
                "id_ed25519",
            ),
        ];
        let enter = theme::enter(ui, &fields);
        ui.horizontal_wrapped(|ui| {
            if theme::button(
                ui,
                name,
                "ssh-submit",
                "Сохранить хост",
                "Сохранить хост",
                enabled,
                ButtonKind::Primary,
            )
            .clicked()
                || (enabled && enter)
            {
                action = Some(ListAction::AddSshHost {
                    target: label.clone(),
                    host: d.host.clone(),
                    hostname: d.hostname.clone(),
                    user: d.user.clone(),
                    port: d.port.clone(),
                    key_file: d.key_file.clone(),
                });
            }
            if theme::button(
                ui,
                name,
                "cancel",
                "Отмена",
                "Отмена",
                true,
                ButtonKind::Neutral,
            )
            .clicked()
            {
                action = Some(ListAction::Cancel);
            }
        });
    }
    action
}
