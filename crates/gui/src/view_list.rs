//! Экран 1 — список хранилищ, управление записями и плашка окружения.
//!
//! Экран ничего не знает про асинхронность: он рисует данные и возвращает
//! намерение человека. Превращает намерение в операцию [`crate::app::App`].

use eframe::egui;
use panzir_core::registry::VaultEntry;
use panzir_core::vault::Label;

use crate::app::{EnvLine, kind_text, state_text};

/// Начатое переименование: какую запись меняем и что уже набрано.
pub struct RenameDraft {
    /// Метка, которую меняем.
    pub target: Label,
    /// Текущий ввод.
    pub text: String,
}

/// Что человек попросил сделать.
pub enum ListAction {
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
            if let Some(a) = show_entry(ui, entry, input.busy, input.rename) {
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
) -> Option<ListAction> {
    let mut action = None;
    let label = entry.label().clone();

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
    });

    action
}
