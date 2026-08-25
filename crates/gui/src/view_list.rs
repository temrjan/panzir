//! Экран 1 — список хранилищ, управление записями и плашка окружения.
//!
//! Экран ничего не знает про асинхронность: он рисует данные и возвращает
//! намерение человека. Превращает намерение в операцию [`crate::app::App`].

use eframe::egui;
use panzir_core::registry::VaultEntry;
use panzir_core::vault::{Label, VaultKind, VaultState};
use secrecy::zeroize::Zeroize as _;

use crate::app::{EnvLine, kind_text, state_text};

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

    if input.entries.is_empty() {
        ui.label("Хранилищ пока нет");
    } else {
        for entry in input.entries {
            if let Some(a) = show_entry(
                ui,
                entry,
                input.busy,
                input.rename,
                input.expanded,
                input.unlock,
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
            .indent(label.as_str(), |ui| show_card(ui, entry, busy, unlock))
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
) -> Option<ListAction> {
    match entry.kind() {
        VaultKind::File(path) => ui.label(format!("Файл: {}", path.display())),
        VaultKind::Device { uuid } => ui.label(format!("Носитель, UUID тома: {uuid}")),
    };

    // Точка монтирования — фактическая, из ответа udisks2, сохранённая в
    // записи. Путь симлинка сюда не подставляется: симлинк — наша выдумка,
    // а человеку нужно место, где лежат его файлы.
    if let VaultState::Open { mount_point } = entry.state() {
        ui.label(format!("Смонтировано: {}", mount_point.display()));
    }

    let label = entry.label().clone();
    let mut action = None;

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
