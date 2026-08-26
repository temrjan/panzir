//! Экран 2 — создание нового файлового хранилища.
//!
//! Форма собирает метку, размер и пароль (с повтором против опечатки) и отдаёт
//! наружу [`CreateAction`]. Секрет форма НЕ строит и НЕ затирает: значения читает
//! `app.rs`, там же строит `SecretString` и затирает буфер — единым местом
//! ([`crate::app::App::forget_stale_passphrase`]), как на разблокировке (инвариант 5).

use eframe::egui;
use panzir_core::vault::Label;

/// Минимальный размер контейнера в МиБ: заголовок LUKS2 плюс запас под ФС.
const MIN_SIZE_MIB: u64 = 32;
/// Размер по умолчанию, МиБ (1 ГиБ) — строкой, как его вводит человек.
const DEFAULT_SIZE_MIB: &str = "1024";

/// Черновик формы создания. `passphrase`/`confirm` — секреты: затираются на
/// выходе с экрана (инвариант 5), в самой форме не трогаются.
pub struct CreateDraft {
    /// Метка — она же имя контейнера-файла и симлинка.
    pub label: String,
    /// Размер в МиБ (строка ввода).
    pub size: String,
    /// Пароль.
    pub passphrase: String,
    /// Повтор пароля — ловит опечатку (второе поле, не второй пароль).
    pub confirm: String,
}

impl Default for CreateDraft {
    fn default() -> Self {
        Self {
            label: String::new(),
            size: DEFAULT_SIZE_MIB.to_owned(),
            passphrase: String::new(),
            confirm: String::new(),
        }
    }
}

/// Намерение человека на экране создания. Полей нет — как [`crate::view_list::ListAction::Open`]:
/// значения читает `app.rs` из черновика, там же секрет строится и затирается.
pub enum CreateAction {
    /// Создать хранилище из текущего черновика.
    Submit,
    /// Уйти без создания.
    Cancel,
}

/// Размер из строки ввода в байты. Чистая функция (тестируема без окна).
///
/// Вход — целое число МиБ. Пусто / не число / ниже [`MIN_SIZE_MIB`] → `None`,
/// и форма не даст нажать «Создать».
#[must_use]
pub fn parse_size(input: &str) -> Option<u64> {
    let mib = input.trim().parse::<u64>().ok()?;
    if mib < MIN_SIZE_MIB {
        return None;
    }
    Some(mib * 1024 * 1024)
}

/// Рисует форму, возвращает намерение, если оно было.
///
/// `busy` — идёт операция: «Создать» неактивна (второй операции быть не может),
/// «Отмена» доступна всегда (она операции не запускает).
pub fn show(ui: &mut egui::Ui, draft: &mut CreateDraft, busy: bool) -> Option<CreateAction> {
    let mut action = None;

    ui.heading("Новое хранилище");

    let label_ok = Label::new(&draft.label).is_ok();
    let size_ok = parse_size(&draft.size).is_some();
    let passwords_match = !draft.passphrase.is_empty() && draft.passphrase == draft.confirm;

    ui.horizontal(|ui| {
        ui.label("Метка:");
        ui.text_edit_singleline(&mut draft.label);
    });
    if !draft.label.is_empty() && !label_ok {
        ui.colored_label(
            ui.visuals().error_fg_color,
            "метка: строчные буквы, цифры, дефис; до 16 символов, не с дефиса",
        );
    }

    ui.horizontal(|ui| {
        ui.label("Размер, МиБ:");
        ui.text_edit_singleline(&mut draft.size);
    });
    if !draft.size.is_empty() && !size_ok {
        ui.colored_label(
            ui.visuals().error_fg_color,
            format!("размер: целое число МиБ, не меньше {MIN_SIZE_MIB}"),
        );
    }

    // Поля пароля замаскированы, как на разблокировке (переключателя показа нет —
    // повтор ниже ловит опечатку, инвариант 5).
    ui.horizontal(|ui| {
        ui.label("Пароль:");
        ui.add(egui::TextEdit::singleline(&mut draft.passphrase).password(true));
    });
    ui.horizontal(|ui| {
        ui.label("Повтор:");
        ui.add(egui::TextEdit::singleline(&mut draft.confirm).password(true));
    });
    if !draft.confirm.is_empty() && !passwords_match {
        ui.colored_label(ui.visuals().error_fg_color, "пароли не совпадают");
    }

    let can_create = label_ok && size_ok && passwords_match;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(can_create && !busy, egui::Button::new("Создать"))
            .clicked()
        {
            action = Some(CreateAction::Submit);
        }
        if ui.button("Отмена").clicked() {
            action = Some(CreateAction::Cancel);
        }
    });

    action
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_rejects_junk_empty_and_below_min() {
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("  "), None);
        assert_eq!(parse_size("abc"), None);
        assert_eq!(parse_size("0"), None);
        assert_eq!(parse_size("31"), None); // ниже минимума
    }

    #[test]
    fn parse_size_accepts_mib_as_bytes() {
        assert_eq!(parse_size("32"), Some(32 * 1024 * 1024));
        assert_eq!(parse_size("1024"), Some(1024 * 1024 * 1024)); // 1 ГиБ
        assert_eq!(parse_size(" 64 "), Some(64 * 1024 * 1024));
    }
}
