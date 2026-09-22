//! A light approximation of Zed's One Dark: same palette and calm spacing, none
//! of the weight. Applied once at startup.

use egui::{Color32, Context, CornerRadius, Stroke};

pub const BG: Color32 = Color32::from_rgb(0x28, 0x2c, 0x34);
pub const PANEL: Color32 = Color32::from_rgb(0x24, 0x28, 0x2f);
pub const SUNKEN: Color32 = Color32::from_rgb(0x1e, 0x22, 0x27);
pub const ELEV: Color32 = Color32::from_rgb(0x33, 0x38, 0x42);
pub const TEXT: Color32 = Color32::from_rgb(0xab, 0xb2, 0xbf);
pub const MUTED: Color32 = Color32::from_rgb(0x6b, 0x71, 0x80);
pub const ACCENT: Color32 = Color32::from_rgb(0x61, 0xaf, 0xef); // blue
pub const GREEN: Color32 = Color32::from_rgb(0x98, 0xc3, 0x79);
pub const RED: Color32 = Color32::from_rgb(0xe0, 0x6c, 0x75);
pub const YELLOW: Color32 = Color32::from_rgb(0xe5, 0xc0, 0x7b);
pub const ORANGE: Color32 = Color32::from_rgb(0xd1, 0x9a, 0x66);
pub const PURPLE: Color32 = Color32::from_rgb(0xc6, 0x78, 0xdd);

pub fn apply(ctx: &Context) {
    let mut v = egui::Visuals::dark();
    let r = CornerRadius::same(4);
    v.panel_fill = PANEL;
    v.window_fill = BG;
    v.extreme_bg_color = SUNKEN;
    v.faint_bg_color = Color32::from_rgb(0x2c, 0x31, 0x39);
    v.override_text_color = Some(TEXT);
    v.hyperlink_color = ACCENT;
    v.selection.bg_fill = Color32::from_rgb(0x3b, 0x44, 0x51);
    v.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    v.window_corner_radius = r;
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = r;
    }
    v.widgets.inactive.bg_fill = ELEV;
    v.widgets.inactive.weak_bg_fill = ELEV;
    v.widgets.hovered.bg_fill = Color32::from_rgb(0x3d, 0x43, 0x4d);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x3d, 0x43, 0x4d);
    v.widgets.active.bg_fill = Color32::from_rgb(0x45, 0x4c, 0x59);
    ctx.set_visuals(v);

    // egui 0.36 replaced Context::style/set_style with per-theme style mutation.
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(9.0, 4.0);
        style.spacing.window_margin = egui::Margin::same(10);
    });
}
