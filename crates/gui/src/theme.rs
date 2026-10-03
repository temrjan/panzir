//! Цвета, типографика и общие элементы принятого редизайна.
use eframe::egui::{self, Color32, FontId, Id, Response, RichText, Stroke, TextStyle, Ui};

pub(crate) const BACKGROUND: Color32 = Color32::from_rgb(13, 18, 18);
pub(crate) const CARD: Color32 = Color32::from_rgb(22, 32, 31);
pub(crate) const FIELD: Color32 = Color32::from_rgb(11, 16, 16);
pub(crate) const TEXT: Color32 = Color32::from_rgb(211, 228, 223);
pub(crate) const MUTED: Color32 = Color32::from_rgb(164, 185, 178);
pub(crate) const BORDER: Color32 = Color32::from_rgb(47, 67, 62);
pub(crate) const FIELD_BORDER: Color32 = Color32::from_rgb(91, 130, 121);
pub(crate) const ACCENT: Color32 = Color32::from_rgb(100, 213, 179);
pub(crate) const DANGER: Color32 = Color32::from_rgb(233, 161, 155);
pub(crate) const DANGER_BG: Color32 = Color32::from_rgb(48, 33, 31);
pub(crate) const DANGER_BORDER: Color32 = Color32::from_rgb(114, 73, 69);

pub(crate) fn apply(ctx: &egui::Context) {
    let mut style = egui::Style {
        visuals: egui::Visuals::dark(),
        ..Default::default()
    };
    style.visuals.panel_fill = BACKGROUND;
    style.visuals.window_fill = CARD;
    style.visuals.extreme_bg_color = FIELD;
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.error_fg_color = DANGER;
    style.visuals.warn_fg_color = DANGER;
    style.visuals.selection.bg_fill = ACCENT.gamma_multiply(0.3);
    style.visuals.selection.stroke = Stroke::new(1.5, ACCENT);
    for widget in [
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        widget.bg_fill = CARD;
        widget.weak_bg_fill = CARD;
        widget.bg_stroke = Stroke::new(1.0, FIELD_BORDER);
        widget.fg_stroke = Stroke::new(1.0, TEXT);
        widget.corner_radius = 7.into();
    }
    style.visuals.widgets.active.bg_stroke = Stroke::new(2.0, ACCENT);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(33, 49, 45);
    style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    style.spacing.item_spacing = egui::vec2(12.0, 12.0);
    style.spacing.button_padding = egui::vec2(16.0, 10.0);
    style.spacing.interact_size = egui::vec2(42.0, 42.0);
    style.text_styles = [
        (TextStyle::Body, FontId::proportional(17.0)),
        (TextStyle::Button, FontId::proportional(16.0)),
        (TextStyle::Small, FontId::proportional(14.0)),
        (TextStyle::Monospace, FontId::monospace(14.0)),
        (TextStyle::Heading, FontId::proportional(28.0)),
    ]
    .into();
    ctx.set_theme(egui::Theme::Dark);
    ctx.set_style_of(egui::Theme::Dark, style);
}

pub(crate) fn id(target: &str, role: &str) -> Id {
    Id::new(("panzir", target, role))
}

pub(crate) fn request_focus(ctx: &egui::Context, target: Id) {
    ctx.data_mut(|d| d.insert_temp(Id::new("panzir-focus-request"), target));
    ctx.request_repaint();
}

fn focus(response: &Response, target: Id) {
    let wanted = response
        .ctx
        .data(|d| d.get_temp::<Id>(Id::new("panzir-focus-request")));
    if wanted == Some(target) && response.enabled() {
        response.request_focus();
        response.scroll_to_me(Some(egui::Align::Center));
        response
            .ctx
            .data_mut(|d| d.remove::<Id>(Id::new("panzir-focus-request")));
    } else if response.gained_focus() && !response.interact_rect.contains_rect(response.rect) {
        // Tab/Shift+Tab use egui's focus traversal, not our explicit request.
        // Scroll once on entry; ordinary frames and wheel input keep their position.
        response.scroll_to_me(Some(egui::Align::Center));
    }
}

/// Три оформления действия; опасность всегда подписана словами.
#[derive(Clone, Copy)]
pub(crate) enum ButtonKind {
    Neutral,
    Primary,
    Danger,
}

pub(crate) fn button(
    ui: &mut Ui,
    target: &str,
    role: &str,
    text: &str,
    name: &str,
    enabled: bool,
    kind: ButtonKind,
) -> Response {
    let target_id = id(target, role);
    let response = ui
        .scope_builder(egui::UiBuilder::new().id(target_id), |ui| {
            let mut button = egui::Button::new(RichText::new(text).size(16.0).color(match kind {
                ButtonKind::Primary => BACKGROUND,
                ButtonKind::Danger => DANGER,
                ButtonKind::Neutral => TEXT,
            }))
            .wrap_mode(egui::TextWrapMode::Extend)
            .min_size(egui::vec2(button_width(ui, text) + 4.0, 42.0));
            button = match kind {
                ButtonKind::Neutral => button,
                ButtonKind::Primary => button.fill(ACCENT).stroke(Stroke::NONE),
                ButtonKind::Danger => button
                    .fill(DANGER_BG)
                    .stroke(Stroke::new(1.0, DANGER_BORDER)),
            };
            ui.add_enabled(enabled, button)
        })
        .inner;
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, name));
    if response.clicked() {
        response.request_focus();
    }
    focus(&response, target_id);
    response
}

pub(crate) fn field(
    ui: &mut Ui,
    key: (&str, &str),
    label: &str,
    value: &mut String,
    password: bool,
    enabled: bool,
    hint: &str,
) -> Response {
    let label_response = ui.label(RichText::new(label).size(16.0));
    let field_id = id(key.0, key.1);
    let response = ui
        .add_enabled(
            enabled,
            egui::TextEdit::singleline(value)
                .id(field_id)
                .password(password)
                .hint_text(hint)
                .desired_width(ui.available_width())
                .min_size(egui::vec2(ui.available_width(), 46.0))
                .margin(egui::vec2(12.0, 15.0)),
        )
        .labelled_by(label_response.id);
    focus(&response, field_id);
    response
}

pub(crate) fn enter(ui: &Ui, responses: &[Response]) -> bool {
    responses.iter().any(|r| r.has_focus() || r.lost_focus())
        && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Enter))
}

pub(crate) fn technical(ui: &mut Ui, text: impl Into<String>) {
    ui.add(
        egui::Label::new(
            RichText::new(text.into())
                .monospace()
                .size(14.0)
                .color(MUTED),
        )
        .wrap()
        .selectable(true),
    );
}

pub(crate) fn helper(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(14.0).color(MUTED));
}

pub(crate) fn card(ui: &Ui) -> egui::Frame {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(10)
        .inner_margin(if ui.available_width() <= 600.0 {
            18
        } else {
            24
        })
}

/// Ограничивает только ширину: высота остаётся доступна для локальной прокрутки.
pub(crate) fn centered<R>(ui: &mut Ui, max_width: f32, contents: impl FnOnce(&mut Ui) -> R) -> R {
    let mut rect = ui.available_rect_before_wrap();
    let padding = if rect.width() <= 600.0 { 18.0 } else { 24.0 };
    rect = rect.shrink2(egui::vec2(padding, padding));
    let width = rect.width().min(max_width);
    rect.min.x += (rect.width() - width) / 2.0;
    rect.max.x = rect.min.x + width;
    ui.scope_builder(egui::UiBuilder::new().max_rect(rect), contents)
        .inner
}

/// Ширина подписи кнопки с принятым внутренним отступом.
pub(crate) fn button_width(ui: &Ui, text: &str) -> f32 {
    ui.fonts_mut(|f| {
        f.layout_no_wrap(text.into(), TextStyle::Button.resolve(ui.style()), TEXT)
            .size()
            .x
    }) + 32.0
}
