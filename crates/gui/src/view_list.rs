//! Экран 1 — список хранилищ, управление записями и плашка окружения.
//!
//! Экран ничего не знает про асинхронность: он рисует данные и возвращает
//! намерение человека. Превращает намерение в операцию [`crate::app::App`].

use eframe::egui;
use panzir_core::registry::VaultEntry;
use panzir_core::ssh::IncludeStatus;
use panzir_core::vault::{Label, VaultKind, VaultState};
use secrecy::zeroize::Zeroize as _;

use crate::app::{EnvLine, SshCardStatus, SshConfirm, busy_message, kind_text, state_text};

/// Начатое переименование: какую запись меняем и что уже набрано.
pub struct RenameDraft {
    /// Метка, которую меняем.
    pub target: Label,
    /// Текущий ввод.
    pub text: String,
}

/// Начатый ввод парольной фразы: для какой записи и что набрано.
///
/// Буфер здесь — обычная `String`: другого способа принять ввод у egui нет.
/// Живёт он ровно до нажатия кнопки — [`crate::app::App`] забирает содержимое
/// `mem::take` и сразу кладёт в `SecretString`.
pub struct UnlockDraft {
    /// Метка записи, которую открывают.
    pub target: Label,
    /// Набранное.
    pub text: String,
}

/// Начатое добавление SSH-хоста: для какой записи и что набрано.
/// Поля — сырые строки; проверяет ядро (`SshHost::new`) при отправке.
pub struct SshHostDraft {
    /// Метка записи, к которой добавляют хоста.
    pub target: Label,
    /// Алиас (`Host`), как его наберут в командной строке.
    pub host: String,
    /// Адрес (`HostName`).
    pub hostname: String,
    /// Логин (`User`).
    pub user: String,
    /// Порт — пусто или число (`Port` пишется только при числе).
    pub port: String,
    /// Имя файла ключа внутри хранилища.
    pub key_file: String,
}

/// Всё, что карточке нужно для секции SSH-связки (спека Ш-7).
/// Собрано в одну структуру, чтобы сигнатуры рендера не расползались.
pub struct SshCard<'a> {
    /// Черновик добавления хоста.
    pub draft: &'a mut Option<SshHostDraft>,
    /// Статус связки — результат фоновой пробы.
    pub status: &'a Option<SshCardStatus>,
    /// Ожидающее подтверждение вставление/починка строки `Include`.
    pub confirm: &'a mut Option<SshConfirm>,
}

/// Что человек попросил сделать.
pub enum ListAction {
    /// Открыть хранилище набранной фразой.
    Open(Label),
    /// Закрыть хранилище.
    Close(Label),
    /// Убрать запись из списка. Файл на диске не трогается.
    Remove(Label),
    /// Применить новое имя.
    CommitRename {
        /// Старая метка.
        old: Label,
        /// Набранное имя, ещё не проверенное ядром.
        new: String,
    },
    /// Перейти на экран создания нового хранилища.
    StartCreate,
    /// Добавить SSH-хоста к записи. Поля — сырые строки из черновика.
    AddSshHost {
        /// Метка записи.
        target: Label,
        /// Набранный алиас.
        host: String,
        /// Набранный адрес.
        hostname: String,
        /// Набранный логин.
        user: String,
        /// Набранный порт (пусто — без порта).
        port: String,
        /// Набранное имя файла ключа.
        key_file: String,
    },
    /// Показать точную строку `Include` и спросить подтверждение.
    AskSshInclude {
        /// Метка записи.
        target: Label,
        /// `true` — починка `Shadowed` (поднять строку первой).
        repair: bool,
    },
    /// Человек подтвердил вставку/починку строки `Include`.
    ConfirmSshInclude,
}

/// Всё, что экрану нужно для отрисовки.
pub struct ListInput<'a> {
    /// Записи реестра.
    pub entries: &'a [VaultEntry],
    /// Строки плашки окружения.
    pub env: &'a [EnvLine],
    /// Последнее сообщение человеку.
    pub message: Option<&'a str>,
    /// Идёт операция — кнопки записей неактивны.
    pub busy: bool,
    /// Начатое переименование.
    pub rename: &'a mut Option<RenameDraft>,
    /// Начатый ввод парольной фразы.
    pub unlock: &'a mut Option<UnlockDraft>,
    /// Начатое добавление SSH-хоста.
    pub ssh_draft: &'a mut Option<SshHostDraft>,
    /// Статус SSH-связки раскрытой карточки (результат пробы).
    pub ssh_status: &'a Option<SshCardStatus>,
    /// Ожидающее подтверждение вставление/починка строки `Include`.
    pub ssh_confirm: &'a mut Option<SshConfirm>,
    /// Метка записи, чья карточка раскрыта. Раскрыта не более одной: операция
    /// всё равно идёт одна за раз, а два раскрытых поля пароля означали бы два
    /// секрета в памяти вместо одного.
    pub expanded: &'a mut Option<Label>,
}

/// Рисует экран и возвращает намерение человека, если оно было.
pub fn show(ui: &mut egui::Ui, input: ListInput<'_>) -> Option<ListAction> {
    let mut action = None;

    show_env(ui, input.env);
    ui.separator();

    if let Some(text) = input.message {
        ui.colored_label(ui.visuals().error_fg_color, text);
        ui.separator();
    }

    // `!busy`, как у остальных действий списка: иначе клик во время операции
    // увёл бы на экран создания и утопил её сообщение об отказе (инвариант 10).
    ui.add_enabled_ui(!input.busy, |ui| {
        if ui.button("Создать хранилище").clicked() {
            action = Some(ListAction::StartCreate);
        }
    });
    ui.separator();

    if input.entries.is_empty() {
        ui.label("Хранилищ пока нет");
    } else {
        for entry in input.entries {
            let mut ssh = SshCard {
                draft: &mut *input.ssh_draft,
                status: input.ssh_status,
                confirm: &mut *input.ssh_confirm,
            };
            if let Some(a) = show_entry(
                ui,
                entry,
                input.busy,
                input.rename,
                input.expanded,
                input.unlock,
                &mut ssh,
            ) {
                action = Some(a);
            }
        }
    }

    action
}

fn show_env(ui: &mut egui::Ui, env: &[EnvLine]) {
    let broken: Vec<&EnvLine> = env.iter().filter(|l| !l.ok).collect();
    if broken.is_empty() {
        return;
    }
    ui.heading("Чего не хватает в системе");
    for line in broken {
        ui.label(format!("{}: {}", line.name, line.hint));
    }
}

fn show_entry(
    ui: &mut egui::Ui,
    entry: &VaultEntry,
    busy: bool,
    rename: &mut Option<RenameDraft>,
    expanded: &mut Option<Label>,
    unlock: &mut Option<UnlockDraft>,
    ssh: &mut SshCard,
) -> Option<ListAction> {
    let mut action = None;
    let label = entry.label().clone();
    // Считаем ДО кнопки: переключение вступает в силу следующим кадром, иначе
    // карточка раскрывалась бы и схлопывалась в одном и том же кадре.
    let is_expanded = expanded
        .as_ref()
        .is_some_and(|l| l.as_str() == label.as_str());

    ui.horizontal(|ui| {
        ui.label(format!(
            "{} · {} · {}",
            label.as_str(),
            kind_text(entry.kind()),
            state_text(entry.state())
        ));

        let editing = rename
            .as_ref()
            .is_some_and(|draft| draft.target.as_str() == label.as_str());

        if editing {
            ui.add_enabled_ui(!busy, |ui| {
                if let Some(draft) = rename.as_mut() {
                    ui.text_edit_singleline(&mut draft.text);
                }
                // Черновик здесь НЕ забираем: его чистит `app.rs`, и только
                // если операция действительно ушла в работу. Иначе набранное
                // имя пропадало бы молча — поле закрылось, имя прежнее,
                // сообщения нет.
                if ui.button("Сохранить").clicked()
                    && let Some(draft) = rename.as_ref()
                {
                    action = Some(ListAction::CommitRename {
                        old: draft.target.clone(),
                        new: draft.text.clone(),
                    });
                }
                if ui.button("Отмена").clicked() {
                    *rename = None;
                }
            });
        } else {
            ui.add_enabled_ui(!busy, |ui| {
                if ui.button("Удалить из списка").clicked() {
                    action = Some(ListAction::Remove(label.clone()));
                }
                if ui.button("Переименовать").clicked() {
                    *rename = Some(RenameDraft {
                        target: label.clone(),
                        text: label.as_str().to_owned(),
                    });
                }
            });
        }

        // Раскрытие карточки доступно и во время операции: оно ничего не
        // меняет ни в системе, ни в реестре — только показывает.
        if ui
            .button(if is_expanded {
                "Свернуть"
            } else {
                "Подробнее"
            })
            .clicked()
        {
            *expanded = if is_expanded {
                None
            } else {
                Some(label.clone())
            };
        }
    });

    if is_expanded
        && let Some(a) = ui
            .indent(label.as_str(), |ui| show_card(ui, entry, busy, unlock, ssh))
            .inner
    {
        action = Some(a);
    }

    action
}

/// Карточка хранилища: где лежит, где смонтировано и что с ним можно сделать.
fn show_card(
    ui: &mut egui::Ui,
    entry: &VaultEntry,
    busy: bool,
    unlock: &mut Option<UnlockDraft>,
    ssh: &mut SshCard,
) -> Option<ListAction> {
    match entry.kind() {
        VaultKind::File(path) => ui.label(format!("Файл: {}", path.display())),
        VaultKind::Device { uuid } => ui.label(format!("Носитель, UUID тома: {uuid}")),
    };

    // Обещание продукта (инвариант про стандартный LUKS2): том — обычный LUKS2,
    // открывается штатным инструментом без panzir. Показываем ПОСЛЕ `match`, а не
    // в ветке `File`: обещание одинаково верно и для файла, и для носителя.
    ui.label("Формат: стандартный LUKS2 — открывается GNOME Disks и cryptsetup");

    // Точка монтирования — фактическая, из ответа udisks2, сохранённая в
    // записи. Путь симлинка сюда не подставляется: симлинк — наша выдумка,
    // а человеку нужно место, где лежат его файлы.
    if let VaultState::Open { mount_point, .. } = entry.state() {
        ui.label(format!("Смонтировано: {}", mount_point.display()));

        // E-minimal: автозакрытие отложено из-за «занято» — показываем держателей.
        if entry.close_attempts() > 0 {
            let holders = panzir_core::holders::find_holders(mount_point);
            ui.colored_label(ui.visuals().error_fg_color, busy_message(&holders));
        }
    }

    let label = entry.label().clone();
    let mut action = show_ssh_section(ui, entry, busy, ssh);

    ui.add_enabled_ui(!busy, |ui| {
        if matches!(entry.state(), VaultState::Open { .. }) {
            if ui.button("Закрыть").clicked() {
                action = Some(ListAction::Close(label.clone()));
            }
            return;
        }

        // Закрыто или отключено — предлагаем открыть. Носители в этом круге
        // не поддержаны; отказ произносится словами в `app.rs`, а не молчанием.
        let typing = unlock
            .as_ref()
            .is_some_and(|d| d.target.as_str() == label.as_str());
        if typing {
            if let Some(draft) = unlock.as_mut() {
                ui.horizontal(|ui| {
                    ui.label("Парольная фраза:");
                    ui.add(
                        egui::TextEdit::singleline(&mut draft.text)
                            .password(true)
                            .hint_text("фраза хранилища"),
                    );
                });
            }
            if ui.button("Открыть").clicked() {
                action = Some(ListAction::Open(label.clone()));
            }
            if ui.button("Отмена").clicked() {
                // Отмена — уход секрета из памяти, а не закрытие поля: буфер
                // затирается ДО того, как черновик выпадет из области видимости.
                if let Some(draft) = unlock.as_mut() {
                    draft.text.zeroize();
                }
                *unlock = None;
            }
        } else if ui.button("Открыть").clicked() {
            *unlock = Some(UnlockDraft {
                target: label.clone(),
                text: String::new(),
            });
        }
    });
    action
}

/// Секция SSH-связки на карточке (спека Ш-7): список хостов из реестра,
/// статус строки `Include` из пробы, подтверждение вставки/починки и
/// черновик добавления хоста.
fn show_ssh_section(
    ui: &mut egui::Ui,
    entry: &VaultEntry,
    busy: bool,
    ssh: &mut SshCard,
) -> Option<ListAction> {
    let mut action = None;
    let label = entry.label().clone();

    ui.separator();
    ui.label("SSH-связка:");
    if entry.ssh_hosts().is_empty() {
        ui.label("хостов нет");
    } else {
        for h in entry.ssh_hosts() {
            let port = h.port.map_or(String::new(), |p| format!(":{p}"));
            ui.label(format!(
                "{} → {}@{}{} · ключ {}",
                h.host, h.user, h.hostname, port, h.key_file
            ));
        }
        // Контракт, видимый пользователю: закрытое хранилище — ключи
        // недоступны (IdentityFile указывает в мёртвый симлинк).
        if !matches!(entry.state(), VaultState::Open { .. }) {
            ui.label("хранилище закрыто — ключи недоступны");
        }

        // Статус связки — результат пробы; `None` — проба ещё не вернулась,
        // и кадр ничего не утверждает, вместо того чтобы соврать на кадр.
        if let Some(status) = ssh
            .status
            .as_ref()
            .filter(|s| s.label.as_str() == label.as_str())
        {
            if let Some(err) = &status.error {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    format!("ваш ~/.ssh/config не прочитался: {err}"),
                );
            }
            ui.add_enabled_ui(!busy, |ui| match status.include {
                IncludeStatus::Ok => {
                    ui.label("связка включена: строка Include — первая в ~/.ssh/config");
                }
                IncludeStatus::Missing => {
                    if ui.button("Включить SSH-связку").clicked() {
                        action = Some(ListAction::AskSshInclude {
                            target: label.clone(),
                            repair: false,
                        });
                    }
                }
                IncludeStatus::Shadowed => {
                    ui.colored_label(
                        ui.visuals().error_fg_color,
                        "строка Include съехала ниже чужого блока Host/Match — \
                         наши имена будут перехвачены",
                    );
                    if ui.button("Поднять строку первой").clicked() {
                        action = Some(ListAction::AskSshInclude {
                            target: label.clone(),
                            repair: true,
                        });
                    }
                }
            });
            if let Some(name) = &status.collision {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    format!(
                        "имя «{name}» уже занято в вашем ~/.ssh/config — \
                         переименуйте хоста, иначе сработает чужая запись"
                    ),
                );
            }
            // Резолюция по `ssh -G` — проверка по результату (К-7), только у
            // открытого хранилища.
            for r in &status.resolutions {
                if r.ok {
                    ui.label(format!("{}: ssh -G подтверждает связку", r.host));
                } else if let Some(detail) = &r.detail {
                    ui.colored_label(ui.visuals().error_fg_color, format!("{}: {detail}", r.host));
                } else {
                    ui.colored_label(
                        ui.visuals().error_fg_color,
                        format!(
                            "{}: ssh -G не подтверждает связку — нет нашего identityfile \
                             или identitiesonly yes",
                            r.host
                        ),
                    );
                }
            }
        }

        // Подтверждение: человек видит точную строку до записи в его config.
        let confirming = ssh
            .confirm
            .as_ref()
            .is_some_and(|c| c.target.as_str() == label.as_str());
        if confirming {
            if let Some(c) = ssh.confirm.as_ref() {
                ui.label(if c.repair {
                    "Строка будет поднята первой:"
                } else {
                    "В ваш ~/.ssh/config будет вставлена строка:"
                });
                ui.monospace(&c.line);
            }
            ui.add_enabled_ui(!busy, |ui| {
                if ui.button("Подтвердить").clicked() {
                    action = Some(ListAction::ConfirmSshInclude);
                }
                if ui.button("Отмена").clicked() {
                    *ssh.confirm = None;
                }
            });
        }
    }

    ui.add_enabled_ui(!busy, |ui| {
        let drafting = ssh
            .draft
            .as_ref()
            .is_some_and(|d| d.target.as_str() == label.as_str());
        if drafting {
            if let Some(d) = ssh.draft.as_mut() {
                ui.horizontal(|ui| {
                    ui.label("Имя хоста:");
                    ui.text_edit_singleline(&mut d.host);
                });
                ui.horizontal(|ui| {
                    ui.label("Адрес:");
                    ui.text_edit_singleline(&mut d.hostname);
                });
                ui.horizontal(|ui| {
                    ui.label("Логин:");
                    ui.text_edit_singleline(&mut d.user);
                });
                ui.horizontal(|ui| {
                    ui.label("Порт (необязательно):");
                    ui.text_edit_singleline(&mut d.port);
                });
                ui.horizontal(|ui| {
                    ui.label("Файл ключа:");
                    ui.text_edit_singleline(&mut d.key_file);
                });
            }
            // Черновик здесь НЕ забираем: его снимает `app.rs`, и только если
            // операция ушла в работу — как у переименования.
            if ui.button("Сохранить хост").clicked()
                && let Some(d) = ssh.draft.as_ref()
            {
                action = Some(ListAction::AddSshHost {
                    target: d.target.clone(),
                    host: d.host.clone(),
                    hostname: d.hostname.clone(),
                    user: d.user.clone(),
                    port: d.port.clone(),
                    key_file: d.key_file.clone(),
                });
            }
            if ui.button("Отмена").clicked() {
                *ssh.draft = None;
            }
        } else if ui.button("Добавить хост").clicked() {
            *ssh.draft = Some(SshHostDraft {
                target: label.clone(),
                host: String::new(),
                hostname: String::new(),
                user: String::new(),
                port: String::new(),
                key_file: String::new(),
            });
        }
    });
    action
}
