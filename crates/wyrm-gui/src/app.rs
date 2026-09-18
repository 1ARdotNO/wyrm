//! The editor: a model tree, an inspector, and a live findings panel over one
//! `.otm.yaml`. Every committed edit snapshots the whole model for undo, writes
//! the file, and re-runs the engine so findings track edits in real time.

use crate::library::{MITIGATIONS, TAGS};
use crate::theme;
use egui::{Color32, RichText, Ui};
use otm_core::model::{Asset, AssetRisk, Dataflow, Mitigation, Otm, Parent, Project, TrustRisk};
use otm_core::rules::{Finding, Severity, ThreatLibrary};
use std::path::PathBuf;

const KINDS: &[&str] = &[
    "web-service",
    "process",
    "database",
    "data-store",
    "message-queue",
    "external-entity",
    "identity",
];

#[derive(Clone, Copy, PartialEq)]
enum Sel {
    Zone(usize),
    Comp(usize),
    Flow(usize),
    Asset(usize),
    Mit(usize),
}

/// A deferred edit — collected while drawing (immutable borrow of the model),
/// applied after the frame so the borrow checker stays happy.
enum Act {
    Select(Sel),
    Undo,
    Redo,
    AddTag(usize, String),
    DelTag(usize, String),
    SetFlowSrc(usize, String),
    SetFlowDst(usize, String),
    SetCompType(usize, String),
    SetCompZone(usize, String),
    AddCompAsset(usize, String),
    DelCompAsset(usize, String),
    SetName(Sel, String),
    CommitCia(usize, [u8; 3]),
    CommitRating(usize, u8),
    AddMit(String, usize),
    DelMit(usize),
    NewAsset,
    NewFlow,
}

pub struct App {
    path: Option<PathBuf>,
    otm: Otm,
    lib: ThreatLibrary,
    findings: Vec<Finding>,
    sel: Option<Sel>,
    undo: Vec<Otm>,
    redo: Vec<Otm>,
    edit_name: String,
    edit_cia: [u8; 3],
    status: String,
}

impl App {
    pub fn new(path: Option<PathBuf>) -> Self {
        let (otm, status) = match &path {
            Some(p) if p.exists() => match otm_core::parse_file(p) {
                Ok(o) => (o, format!("{}", p.display())),
                Err(e) => (blank(), format!("parse error: {e}")),
            },
            Some(p) => (blank(), format!("new file · {}", p.display())),
            None => (blank(), "no file — Open or Save As".to_string()),
        };
        let lib = ThreatLibrary::bundled();
        let findings = lib.analyze(&otm);
        Self {
            path,
            otm,
            lib,
            findings,
            sel: None,
            undo: Vec::new(),
            redo: Vec::new(),
            edit_name: String::new(),
            edit_cia: [0; 3],
            status,
        }
    }

    // ---- history & persistence -------------------------------------------

    fn commit(&mut self, a: Act) {
        self.undo.push(self.otm.clone());
        if self.undo.len() > 250 {
            self.undo.remove(0);
        }
        self.redo.clear();
        self.mutate(a);
        self.after_change();
    }

    fn do_undo(&mut self) {
        if let Some(prev) = self.undo.pop() {
            self.redo.push(std::mem::replace(&mut self.otm, prev));
            self.after_change();
        }
    }

    fn do_redo(&mut self) {
        if let Some(next) = self.redo.pop() {
            self.undo.push(std::mem::replace(&mut self.otm, next));
            self.after_change();
        }
    }

    fn after_change(&mut self) {
        self.clamp_selection();
        self.save();
        self.findings = self.lib.analyze(&self.otm);
        self.sync_buffers();
    }

    fn save(&mut self) {
        let Some(path) = self.path.clone() else {
            self.status = "no file — use Save As".into();
            return;
        };
        match otm_core::to_yaml(&self.otm) {
            Ok(body) => {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::write(&path, body) {
                    Ok(()) => self.status = format!("saved ✓ · {}", path.display()),
                    Err(e) => self.status = format!("write error: {e}"),
                }
            }
            Err(e) => self.status = format!("serialize error: {e}"),
        }
    }

    fn sync_buffers(&mut self) {
        match self.sel {
            Some(Sel::Zone(i)) => {
                if let Some(z) = self.otm.trust_zones.get(i) {
                    self.edit_name = z.name.clone();
                    self.edit_cia[0] = z.risk.as_ref().and_then(|r| r.trust_rating).unwrap_or(50);
                }
            }
            Some(Sel::Comp(i)) => {
                self.edit_name = self
                    .otm
                    .components
                    .get(i)
                    .map(|c| c.name.clone())
                    .unwrap_or_default();
            }
            Some(Sel::Flow(i)) => {
                self.edit_name = self
                    .otm
                    .dataflows
                    .get(i)
                    .map(|d| d.name.clone())
                    .unwrap_or_default();
            }
            Some(Sel::Asset(i)) => {
                if let Some(a) = self.otm.assets.get(i) {
                    self.edit_name = a.name.clone();
                    let r = a.risk.clone().unwrap_or_default();
                    self.edit_cia = [r.confidentiality, r.integrity, r.availability];
                }
            }
            Some(Sel::Mit(i)) => {
                self.edit_name = self
                    .otm
                    .mitigations
                    .get(i)
                    .map(|m| m.name.clone())
                    .unwrap_or_default();
            }
            None => {}
        }
    }

    fn clamp_selection(&mut self) {
        let ok = match self.sel {
            Some(Sel::Zone(i)) => i < self.otm.trust_zones.len(),
            Some(Sel::Comp(i)) => i < self.otm.components.len(),
            Some(Sel::Flow(i)) => i < self.otm.dataflows.len(),
            Some(Sel::Asset(i)) => i < self.otm.assets.len(),
            Some(Sel::Mit(i)) => i < self.otm.mitigations.len(),
            None => true,
        };
        if !ok {
            self.sel = None;
        }
    }

    fn apply(&mut self, a: Act) {
        match a {
            Act::Select(s) => {
                self.sel = Some(s);
                self.sync_buffers();
            }
            Act::Undo => self.do_undo(),
            Act::Redo => self.do_redo(),
            other => self.commit(other),
        }
    }

    fn mutate(&mut self, a: Act) {
        match a {
            Act::AddTag(i, t) => {
                if let Some(d) = self.otm.dataflows.get_mut(i) {
                    if !d.tags.contains(&t) {
                        d.tags.push(t);
                    }
                }
            }
            Act::DelTag(i, t) => {
                if let Some(d) = self.otm.dataflows.get_mut(i) {
                    d.tags.retain(|x| x != &t);
                }
            }
            Act::SetFlowSrc(i, s) => {
                if let Some(d) = self.otm.dataflows.get_mut(i) {
                    d.source = s;
                }
            }
            Act::SetFlowDst(i, s) => {
                if let Some(d) = self.otm.dataflows.get_mut(i) {
                    d.destination = s;
                }
            }
            Act::SetCompType(i, k) => {
                if let Some(c) = self.otm.components.get_mut(i) {
                    c.kind = k;
                }
            }
            Act::SetCompZone(i, z) => {
                if let Some(c) = self.otm.components.get_mut(i) {
                    c.parent = Some(Parent {
                        trust_zone: Some(z),
                        component: None,
                    });
                }
            }
            Act::AddCompAsset(i, a) => {
                if let Some(c) = self.otm.components.get_mut(i) {
                    if !c.assets.processed.contains(&a) && !c.assets.stored.contains(&a) {
                        c.assets.processed.push(a);
                    }
                }
            }
            Act::DelCompAsset(i, a) => {
                if let Some(c) = self.otm.components.get_mut(i) {
                    c.assets.processed.retain(|x| x != &a);
                    c.assets.stored.retain(|x| x != &a);
                }
            }
            Act::SetName(sel, name) => match sel {
                Sel::Zone(i) => {
                    if let Some(z) = self.otm.trust_zones.get_mut(i) {
                        z.name = name;
                    }
                }
                Sel::Comp(i) => {
                    if let Some(c) = self.otm.components.get_mut(i) {
                        c.name = name;
                    }
                }
                Sel::Flow(i) => {
                    if let Some(d) = self.otm.dataflows.get_mut(i) {
                        d.name = name;
                    }
                }
                Sel::Asset(i) => {
                    if let Some(x) = self.otm.assets.get_mut(i) {
                        x.name = name;
                    }
                }
                Sel::Mit(i) => {
                    if let Some(m) = self.otm.mitigations.get_mut(i) {
                        m.name = name;
                    }
                }
            },
            Act::CommitCia(i, [c, ig, av]) => {
                if let Some(x) = self.otm.assets.get_mut(i) {
                    x.risk = Some(AssetRisk {
                        confidentiality: c,
                        integrity: ig,
                        availability: av,
                    });
                }
            }
            Act::CommitRating(i, v) => {
                if let Some(z) = self.otm.trust_zones.get_mut(i) {
                    z.risk = Some(TrustRisk {
                        trust_rating: Some(v),
                    });
                }
            }
            Act::AddMit(element_id, tmpl) => {
                let t = &MITIGATIONS[tmpl];
                let id = format!("{}-{}", t.id, sanitize(&element_id));
                if let Some(m) = self.otm.mitigations.iter_mut().find(|m| m.id == id) {
                    if !m.applies_to.contains(&element_id) {
                        m.applies_to.push(element_id);
                    }
                } else {
                    self.otm.mitigations.push(Mitigation {
                        id,
                        name: t.name.to_string(),
                        description: Some(t.desc.to_string()),
                        risk_reduction: Some(t.risk),
                        applies_to: vec![element_id],
                        addresses: t.addresses.iter().map(|s| s.to_string()).collect(),
                    });
                }
            }
            Act::DelMit(i) => {
                if i < self.otm.mitigations.len() {
                    self.otm.mitigations.remove(i);
                }
            }
            Act::NewAsset => {
                let id = fresh_id("asset", self.otm.assets.iter().map(|a| a.id.as_str()));
                self.otm.assets.push(Asset {
                    id,
                    name: "New asset".into(),
                    risk: Some(AssetRisk::default()),
                });
                self.sel = Some(Sel::Asset(self.otm.assets.len() - 1));
            }
            Act::NewFlow => {
                let comps: Vec<String> = self.otm.components.iter().map(|c| c.id.clone()).collect();
                let src = comps.first().cloned().unwrap_or_else(|| "external".into());
                let dst = comps.get(1).cloned().unwrap_or_else(|| src.clone());
                let id = fresh_id("df", self.otm.dataflows.iter().map(|d| d.id.as_str()));
                self.otm.dataflows.push(Dataflow {
                    id,
                    name: "New dataflow".into(),
                    source: src,
                    destination: dst,
                    assets: Vec::new(),
                    attributes: Default::default(),
                    tags: Vec::new(),
                });
                self.sel = Some(Sel::Flow(self.otm.dataflows.len() - 1));
            }
            Act::Select(_) | Act::Undo | Act::Redo => {}
        }
    }

    // ---- drawing ----------------------------------------------------------

    fn top_bar(&self, ui: &mut Ui, acts: &mut Vec<Act>) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("🐉 wyrm").color(theme::ACCENT).strong());
            ui.separator();
            if ui
                .add_enabled(!self.undo.is_empty(), egui::Button::new("↶ Undo"))
                .clicked()
            {
                acts.push(Act::Undo);
            }
            if ui
                .add_enabled(!self.redo.is_empty(), egui::Button::new("↷ Redo"))
                .clicked()
            {
                acts.push(Act::Redo);
            }
            ui.separator();
            if ui.button("＋ Asset").clicked() {
                acts.push(Act::NewAsset);
            }
            if ui.button("＋ Dataflow").clicked() {
                acts.push(Act::NewFlow);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(&self.status).color(theme::MUTED).small());
            });
        });
    }

    fn left_panel(&self, ui: &mut Ui, acts: &mut Vec<Act>) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            section(ui, "Trust zones");
            for (i, z) in self.otm.trust_zones.iter().enumerate() {
                if row(ui, self.sel == Some(Sel::Zone(i)), theme::PURPLE, &z.name).clicked() {
                    acts.push(Act::Select(Sel::Zone(i)));
                }
            }
            section(ui, "Components");
            for (i, c) in self.otm.components.iter().enumerate() {
                let label = format!("{}  ·  {}", c.name, c.kind);
                if row(ui, self.sel == Some(Sel::Comp(i)), theme::ACCENT, &label).clicked() {
                    acts.push(Act::Select(Sel::Comp(i)));
                }
            }
            section(ui, "Dataflows");
            for (i, d) in self.otm.dataflows.iter().enumerate() {
                if row(ui, self.sel == Some(Sel::Flow(i)), theme::GREEN, &d.name).clicked() {
                    acts.push(Act::Select(Sel::Flow(i)));
                }
            }
            section(ui, "Assets");
            for (i, a) in self.otm.assets.iter().enumerate() {
                if row(ui, self.sel == Some(Sel::Asset(i)), theme::YELLOW, &a.name).clicked() {
                    acts.push(Act::Select(Sel::Asset(i)));
                }
            }
            section(ui, "Mitigations");
            for (i, m) in self.otm.mitigations.iter().enumerate() {
                if row(ui, self.sel == Some(Sel::Mit(i)), theme::ORANGE, &m.name).clicked() {
                    acts.push(Act::Select(Sel::Mit(i)));
                }
            }
        });
    }

    fn findings_panel(&self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Findings").strong());
            ui.label(RichText::new(format!("({})", self.findings.len())).color(theme::MUTED));
        });
        egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(ui, |ui| {
                if self.findings.is_empty() {
                    ui.label(RichText::new("No findings 🎉").color(theme::GREEN));
                }
                for f in &self.findings {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(sev_label(f.severity))
                                .color(sev_color(f.severity))
                                .strong(),
                        );
                        ui.label(RichText::new(&f.rule_id).color(theme::MUTED).monospace());
                        ui.label(&f.title);
                        ui.label(
                            RichText::new(format!("· {}", f.element_name)).color(theme::MUTED),
                        );
                        if let Some(base) = f.base_severity {
                            ui.label(
                                RichText::new(format!("↓ from {}", sev_label(base)))
                                    .color(theme::YELLOW)
                                    .small(),
                            );
                        }
                    });
                }
            });
    }

    fn inspector(&mut self, ui: &mut Ui, acts: &mut Vec<Act>) {
        let Some(sel) = self.sel else {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("Select an element to edit").color(theme::MUTED));
            });
            return;
        };
        match sel {
            Sel::Zone(i) => self.inspect_zone(ui, acts, i),
            Sel::Comp(i) => self.inspect_comp(ui, acts, i),
            Sel::Flow(i) => self.inspect_flow(ui, acts, i),
            Sel::Asset(i) => self.inspect_asset(ui, acts, i),
            Sel::Mit(i) => self.inspect_mit(ui, acts, i),
        }
    }

    fn name_field(&mut self, ui: &mut Ui, acts: &mut Vec<Act>, sel: Sel) {
        ui.horizontal(|ui| {
            ui.label("Name");
            let r = ui.text_edit_singleline(&mut self.edit_name);
            // Commit on blur, but only if the text actually changed — otherwise a
            // stray focus/click would push an empty undo step.
            if r.lost_focus() && self.edit_name != self.name_of(sel) {
                acts.push(Act::SetName(sel, self.edit_name.clone()));
            }
        });
    }

    fn name_of(&self, sel: Sel) -> String {
        match sel {
            Sel::Zone(i) => self.otm.trust_zones.get(i).map(|z| z.name.clone()),
            Sel::Comp(i) => self.otm.components.get(i).map(|c| c.name.clone()),
            Sel::Flow(i) => self.otm.dataflows.get(i).map(|d| d.name.clone()),
            Sel::Asset(i) => self.otm.assets.get(i).map(|a| a.name.clone()),
            Sel::Mit(i) => self.otm.mitigations.get(i).map(|m| m.name.clone()),
        }
        .unwrap_or_default()
    }

    fn inspect_zone(&mut self, ui: &mut Ui, acts: &mut Vec<Act>, i: usize) {
        header(ui, theme::PURPLE, "Trust zone");
        self.name_field(ui, acts, Sel::Zone(i));
        ui.add_space(6.0);
        ui.label(
            RichText::new("Trust rating (0 = internet, 100 = trusted)")
                .color(theme::MUTED)
                .small(),
        );
        let resp = ui.add(egui::Slider::new(&mut self.edit_cia[0], 0..=100));
        if resp.drag_stopped() || (resp.changed() && !resp.dragged()) {
            acts.push(Act::CommitRating(i, self.edit_cia[0]));
        }
    }

    fn inspect_comp(&mut self, ui: &mut Ui, acts: &mut Vec<Act>, i: usize) {
        let comp = self.otm.components[i].clone();
        header(ui, theme::ACCENT, "Component");
        self.name_field(ui, acts, Sel::Comp(i));
        ui.horizontal(|ui| {
            ui.label("Type");
            egui::ComboBox::from_id_salt("ctype")
                .selected_text(&comp.kind)
                .show_ui(ui, |ui| {
                    for k in KINDS {
                        if ui.selectable_label(comp.kind == *k, *k).clicked() {
                            acts.push(Act::SetCompType(i, (*k).to_string()));
                        }
                    }
                });
        });
        let cur_zone = comp
            .parent
            .as_ref()
            .and_then(|p| p.trust_zone.clone())
            .unwrap_or_default();
        ui.horizontal(|ui| {
            ui.label("Zone");
            egui::ComboBox::from_id_salt("czone")
                .selected_text(if cur_zone.is_empty() {
                    "—"
                } else {
                    &cur_zone
                })
                .show_ui(ui, |ui| {
                    for z in &self.otm.trust_zones {
                        if ui.selectable_label(cur_zone == z.id, &z.name).clicked() {
                            acts.push(Act::SetCompZone(i, z.id.clone()));
                        }
                    }
                });
        });
        ui.add_space(8.0);
        ui.label(RichText::new("Assets handled").color(theme::MUTED).small());
        let held: Vec<String> = comp
            .assets
            .processed
            .iter()
            .chain(comp.assets.stored.iter())
            .cloned()
            .collect();
        chips(ui, &held, theme::YELLOW, |a| {
            acts.push(Act::DelCompAsset(i, a))
        });
        let avail: Vec<(String, String)> = self
            .otm
            .assets
            .iter()
            .filter(|a| !held.contains(&a.id))
            .map(|a| (a.id.clone(), a.name.clone()))
            .collect();
        add_menu(ui, "＋ asset", &avail, |id| {
            acts.push(Act::AddCompAsset(i, id))
        });
        self.mitigation_box(ui, acts, comp.id.clone());
    }

    fn inspect_flow(&mut self, ui: &mut Ui, acts: &mut Vec<Act>, i: usize) {
        let flow = self.otm.dataflows[i].clone();
        header(ui, theme::GREEN, "Dataflow");
        self.name_field(ui, acts, Sel::Flow(i));
        let comps: Vec<(String, String)> = self
            .otm
            .components
            .iter()
            .map(|c| (c.id.clone(), c.name.clone()))
            .collect();
        ui.horizontal(|ui| {
            ui.label("Source");
            endpoint_combo(ui, "src", &flow.source, &comps, |id| {
                acts.push(Act::SetFlowSrc(i, id))
            });
            ui.label("→");
            ui.label("Dest");
            endpoint_combo(ui, "dst", &flow.destination, &comps, |id| {
                acts.push(Act::SetFlowDst(i, id))
            });
        });
        ui.add_space(8.0);
        ui.label(RichText::new("Tags").color(theme::MUTED).small());
        chips(ui, &flow.tags, theme::ACCENT, |t| {
            acts.push(Act::DelTag(i, t))
        });
        let avail: Vec<(String, String)> = TAGS
            .iter()
            .filter(|(id, _)| !flow.tags.iter().any(|t| t == id))
            .map(|(id, label)| (id.to_string(), label.to_string()))
            .collect();
        add_menu(ui, "＋ tag", &avail, |id| acts.push(Act::AddTag(i, id)));
        self.mitigation_box(ui, acts, flow.id.clone());
    }

    fn inspect_asset(&mut self, ui: &mut Ui, acts: &mut Vec<Act>, i: usize) {
        header(ui, theme::YELLOW, "Asset");
        self.name_field(ui, acts, Sel::Asset(i));
        ui.add_space(6.0);
        let mut changed = false;
        for (idx, label) in ["Confidentiality", "Integrity", "Availability"]
            .iter()
            .enumerate()
        {
            ui.horizontal(|ui| {
                ui.label(RichText::new(*label).color(theme::MUTED));
                let r = ui.add(egui::Slider::new(&mut self.edit_cia[idx], 0..=100));
                if r.drag_stopped() || (r.changed() && !r.dragged()) {
                    changed = true;
                }
            });
        }
        if changed {
            acts.push(Act::CommitCia(i, self.edit_cia));
        }
    }

    fn inspect_mit(&mut self, ui: &mut Ui, acts: &mut Vec<Act>, i: usize) {
        let m = self.otm.mitigations[i].clone();
        header(ui, theme::ORANGE, "Mitigation");
        self.name_field(ui, acts, Sel::Mit(i));
        if let Some(rr) = m.risk_reduction {
            ui.label(format!("Risk reduction: {rr}"));
        }
        if !m.addresses.is_empty() {
            ui.label(
                RichText::new(format!("Addresses: {}", m.addresses.join(", "))).color(theme::MUTED),
            );
        }
        ui.label(RichText::new("Applies to").color(theme::MUTED).small());
        for t in &m.applies_to {
            ui.label(RichText::new(t).monospace());
        }
        ui.add_space(8.0);
        if ui.button("🗑 Delete mitigation").clicked() {
            acts.push(Act::DelMit(i));
        }
    }

    /// The "add a control from the library" box, linked to `element_id`.
    fn mitigation_box(&self, ui: &mut Ui, acts: &mut Vec<Act>, element_id: String) {
        ui.add_space(10.0);
        ui.separator();
        ui.label(
            RichText::new("Add mitigation from library")
                .color(theme::MUTED)
                .small(),
        );
        ui.horizontal_wrapped(|ui| {
            for (idx, t) in MITIGATIONS.iter().enumerate() {
                if ui
                    .button(RichText::new(t.name).color(theme::ORANGE))
                    .on_hover_text(format!(
                        "{}  (−{} on {})",
                        t.desc,
                        t.risk,
                        t.addresses.join(",")
                    ))
                    .clicked()
                {
                    acts.push(Act::AddMit(element_id.clone(), idx));
                }
            }
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut acts: Vec<Act> = Vec::new();
        ctx.input(|inp| {
            let cmd = inp.modifiers.command;
            if cmd && inp.key_pressed(egui::Key::Z) {
                acts.push(if inp.modifiers.shift {
                    Act::Redo
                } else {
                    Act::Undo
                });
            }
            if cmd && inp.key_pressed(egui::Key::Y) {
                acts.push(Act::Redo);
            }
        });

        egui::TopBottomPanel::top("bar").show(ctx, |ui| self.top_bar(ui, &mut acts));
        egui::SidePanel::left("tree")
            .resizable(true)
            .default_width(260.0)
            .show(ctx, |ui| self.left_panel(ui, &mut acts));
        egui::TopBottomPanel::bottom("findings")
            .resizable(true)
            .default_height(170.0)
            .show(ctx, |ui| self.findings_panel(ui));
        egui::CentralPanel::default().show(ctx, |ui| self.inspector(ui, &mut acts));

        for a in acts {
            self.apply(a);
        }
    }
}

// ---- small widgets -------------------------------------------------------

fn section(ui: &mut Ui, title: &str) {
    ui.add_space(6.0);
    ui.label(
        RichText::new(title.to_uppercase())
            .color(theme::MUTED)
            .small()
            .strong(),
    );
}

fn row(ui: &mut Ui, selected: bool, dot: Color32, label: &str) -> egui::Response {
    let text = RichText::new(format!("● {label}")).color(if selected { theme::TEXT } else { dot });
    ui.selectable_label(selected, text)
}

fn header(ui: &mut Ui, color: Color32, kind: &str) {
    ui.label(RichText::new(kind).color(color).heading());
    ui.add_space(4.0);
}

fn chips(ui: &mut Ui, items: &[String], color: Color32, mut on_del: impl FnMut(String)) {
    ui.horizontal_wrapped(|ui| {
        if items.is_empty() {
            ui.label(RichText::new("none").color(theme::MUTED).small());
        }
        for it in items {
            ui.horizontal(|ui| {
                ui.label(RichText::new(it).color(color));
                if ui.small_button("✕").clicked() {
                    on_del(it.clone());
                }
            });
        }
    });
}

fn add_menu(
    ui: &mut Ui,
    label: &str,
    options: &[(String, String)],
    mut on_pick: impl FnMut(String),
) {
    ui.menu_button(label, |ui| {
        if options.is_empty() {
            ui.label(RichText::new("nothing to add").color(theme::MUTED));
        }
        for (id, name) in options {
            if ui.button(name).clicked() {
                on_pick(id.clone());
                ui.close_menu();
            }
        }
    });
}

fn endpoint_combo(
    ui: &mut Ui,
    salt: &str,
    current: &str,
    comps: &[(String, String)],
    mut on_pick: impl FnMut(String),
) {
    let shown = comps
        .iter()
        .find(|(id, _)| id == current)
        .map(|(_, n)| n.as_str())
        .unwrap_or(current);
    egui::ComboBox::from_id_salt(salt)
        .selected_text(shown)
        .show_ui(ui, |ui| {
            for (id, name) in comps {
                if ui.selectable_label(current == id, name).clicked() {
                    on_pick(id.clone());
                }
            }
        });
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
    }
}

fn sev_color(s: Severity) -> Color32 {
    match s {
        Severity::Critical => theme::RED,
        Severity::High => theme::ORANGE,
        Severity::Medium => theme::YELLOW,
        Severity::Low => theme::MUTED,
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn fresh_id<'a>(prefix: &str, existing: impl Iterator<Item = &'a str>) -> String {
    let taken: Vec<&str> = existing.collect();
    (1..)
        .map(|n| format!("{prefix}-{n}"))
        .find(|id| !taken.contains(&id.as_str()))
        .unwrap()
}

fn blank() -> Otm {
    Otm {
        otm_version: "0.2.0".into(),
        project: Project {
            id: "untitled".into(),
            name: "untitled".into(),
            owner: None,
            description: None,
        },
        trust_zones: Vec::new(),
        components: Vec::new(),
        dataflows: Vec::new(),
        assets: Vec::new(),
        threats: Vec::new(),
        mitigations: Vec::new(),
    }
}
