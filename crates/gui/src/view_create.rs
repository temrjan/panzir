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
    /// Скрыть текущий результат создания.
    Dismiss(crate::app::NoticeScope),
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
    // checked_mul: петабайтный ввод не паникует (dev) и не заворачивается тихо
    // (релиз) — `None` держит «Создать» неактивной тем же путём, что нижняя граница.
    mib.checked_mul(1024 * 1024)
}

/// Рисует форму, возвращает намерение, если оно было.
///
/// `busy` — идёт операция: «Создать» неактивна (второй операции быть не может),
/// «Отмена» доступна всегда (она операции не запускает).
pub fn show(
    ui: &mut egui::Ui,
    draft: &mut CreateDraft,
    busy: bool,
    message: Option<&str>,
    entries: &[panzir_core::registry::VaultEntry],
    notices: &[crate::app::Notice],
) -> Option<CreateAction> {
    use crate::theme::{self, ButtonKind};
    theme::centered(ui, 480.0, |ui| {
        let mut action = None;
        ui.heading("Новое хранилище");
        ui.add_space(8.0);
        // Footer получает место до ScrollArea, но рисуется после полей (Tab).
        let stacked = ui.available_width() < 400.0;
        let footer_height = if stacked { 144.0 } else { 98.0 };
        let fields_height = (ui.available_height() - footer_height - 12.0).max(1.0);
        let mut responses = Vec::new();
        egui::ScrollArea::vertical().id_salt("create-scroll")
            .max_height(fields_height).auto_shrink([false, false]).show(ui, |ui| {
                ui.set_width(ui.available_width());
                if let Some(text) = message { ui.colored_label(theme::DANGER, text); }
                for n in notices.iter().filter(|n| matches!(&n.scope, crate::app::NoticeScope::Create(_))) {
                    if let Some(crate::view_list::ListAction::Dismiss(scope)) = crate::view_list::notice(ui, n) { action = Some(CreateAction::Dismiss(scope)); }
                }
                responses.push(theme::field(ui, ("create", "label"), "Название", &mut draft.label, false, !busy, "Например, work-keys"));
                theme::helper(ui, "Строчные латинские буквы, цифры и дефис; до 16 символов, без дефиса в начале и конце");
                if !draft.label.is_empty() && Label::new(&draft.label).is_err() { ui.colored_label(theme::DANGER, "Название не подходит"); }
                if entries.iter().any(|e| e.label().as_str() == draft.label) { ui.colored_label(theme::DANGER, "Это название уже используется"); }
                ui.add_space(8.0);
                responses.push(theme::field(ui, ("create", "size"), "Размер, МиБ", &mut draft.size, false, !busy, "1024"));
                theme::helper(ui, "Не меньше 32 МиБ. 1024 МиБ = 1 ГиБ");
                if !draft.size.is_empty() && parse_size(&draft.size).is_none() { ui.colored_label(theme::DANGER, "Размер не подходит: требуется целое число МиБ в поддерживаемом диапазоне"); }
                ui.add_space(8.0);
                responses.push(theme::field(ui, ("create", "passphrase"), "Пароль хранилища", &mut draft.passphrase, true, !busy, ""));
                ui.add_space(8.0);
                responses.push(theme::field(ui, ("create", "confirm"), "Повторите пароль", &mut draft.confirm, true, !busy, ""));
                if !draft.confirm.is_empty() && draft.passphrase != draft.confirm { ui.colored_label(theme::DANGER, "Пароли не совпадают"); }
            });
        let valid = Label::new(&draft.label).is_ok()
            && parse_size(&draft.size).is_some()
            && !entries.iter().any(|e| e.label().as_str() == draft.label)
            && !draft.passphrase.is_empty()
            && draft.passphrase == draft.confirm
            && !busy;
        let enter = theme::enter(ui, &responses);
        ui.add_space(12.0);
        theme::helper(
            ui,
            if busy {
                "Создание продолжается"
            } else {
                "После создания хранилище откроется"
            },
        );
        let mut buttons = |ui: &mut egui::Ui| {
            let cancel = if busy {
                "К списку"
            } else {
                "Отмена"
            };
            if theme::button(
                ui,
                "create",
                "cancel",
                cancel,
                cancel,
                true,
                ButtonKind::Neutral,
            )
            .clicked()
            {
                action = Some(CreateAction::Cancel);
            }
            if theme::button(
                ui,
                "create",
                "submit",
                "Создать хранилище",
                "Создать хранилище",
                valid,
                ButtonKind::Primary,
            )
            .clicked()
                || (valid && enter)
            {
                action = Some(CreateAction::Submit);
            }
        };
        if stacked {
            ui.vertical(&mut buttons);
        } else {
            ui.horizontal(&mut buttons);
        }
        action
    })
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

    #[test]
    fn parse_size_rejects_u64_overflow() {
        // МиБ × 2^20 = байты. 2^44 МиБ × 2^20 = 2^64 — на единицу больше u64::MAX.
        // Без checked_mul: dev-сборка паникует прямо в поле ввода, релиз — тихо
        // заворачивается (петабайт → 32 МиБ), нарушая контракт «выше границы → None».
        assert!(parse_size("17592186044415").is_some()); // 2^44 − 1 МиБ — ещё влезает
        assert_eq!(parse_size("17592186044416"), None); // 2^44 МиБ — переполнение
    }
}
