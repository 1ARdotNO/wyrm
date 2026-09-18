//! wyrm-gui — a light native editor for `.otm.yaml` threat models. Launch with a
//! file path (the editor integrations do this); edits live-save back to the file.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod library;
mod theme;

use std::path::PathBuf;

fn main() -> eframe::Result<()> {
    let path = std::env::args().nth(1).map(PathBuf::from);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1040.0, 700.0])
            .with_min_inner_size([760.0, 500.0])
            .with_title("wyrm — threat model editor"),
        ..Default::default()
    };
    eframe::run_native(
        "wyrm",
        options,
        Box::new(move |cc| {
            theme::apply(&cc.egui_ctx);
            Ok(Box::new(app::App::new(path)))
        }),
    )
}
