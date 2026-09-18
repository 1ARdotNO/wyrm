//! The editor: a filterable model tree, an inspector, a visual graph, and a live
//! findings panel over one `.otm.yaml`. Every committed edit snapshots the whole
//! model for undo, writes the file, and re-runs the engine so findings track edits.

use crate::library::{MITIGATIONS, TAGS};
use crate::theme;
use egui::text::LayoutJob;
use egui::{
    Align2, Color32, CornerRadius, FontId, Pos2, Rect, RichText, Sense, Shape, Stroke, StrokeKind,
    Ui,
};
use otm_core::model::{
    Asset, AssetRisk, Component, Dataflow, Mitigation, Otm, Parent, Project, TrustRisk, TrustZone,
};
use otm_core::rules::{Finding, Severity, ThreatLibrary};
use std::collections::HashMap;
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

const SECURE_TAGS: &[&str] = &["tls", "mtls", "https", "wss", "ssh", "encrypted"];

#[derive(Clone, Copy, PartialEq)]
enum Sel {
    Zone(usize),
    Comp(usize),
    Flow(usize),
    Asset(usize),
    Mit(usize),
}

#[derive(Clone, Copy, PartialEq)]
enum View {
    Inspector,
    Graph,
}

/// A deferred edit — collected while drawing (immutable borrow of the model),
/// applied after the frame so the borrow checker stays happy.
enum Act {
    Select(Sel),
    /// Select and scroll the tree to the element (used by graph / findings clicks).
    Reveal(Sel),
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
    MitSetRisk(usize, u8),
    MitAddTarget(usize, String),
    MitDelTarget(usize, String),
    MitAddAddr(usize, String),
    MitDelAddr(usize, String),
    DelZone(usize),
    DelComp(usize),
    DelFlow(usize),
    DelAsset(usize),
    NewZone,
    NewComp,
    NewAsset,
    NewFlow,
    NewMit,
}

pub struct App {
    path: Option<PathBuf>,
    otm: Otm,
    lib: ThreatLibrary,
    findings: Vec<Finding>,
    sel: Option<Sel>,
    view: View,
    filter: String,
    scroll_to: bool,
    undo: Vec<Otm>,
    redo: Vec<Otm>,
    edit_name: String,
    edit_cia: [u8; 3],
    status: String,
    /// Last mtime we wrote or loaded — used to detect external file changes.
    file_mtime: Option<std::time::SystemTime>,
}

impl App {
    pub fn new(path: Option<PathBuf>) -> Self {
        let (otm, status) = match &path {
            Some(p) if p.exists() => match otm_core::parse_file(p) {
                Ok(o) => (o, format!("{}", p.display())),
                Err(e) => (blank(), format!("parse error: {e}")),
            },
            Some(p) => (blank(), format!("new file · {}", p.display())),
            None => (blank(), "no file — pass a path".to_string()),
        };
        let lib = ThreatLibrary::bundled();
        let findings = lib.analyze(&otm);
        let file_mtime = path.as_ref().and_then(|p| mtime(p));
        Self {
            path,
            otm,
            lib,
            findings,
            sel: None,
            view: View::Inspector,
            filter: String::new(),
            scroll_to: false,
            undo: Vec::new(),
            redo: Vec::new(),
            edit_name: String::new(),
            edit_cia: [0; 3],
            status,
            file_mtime,
        }
    }

    /// Reload when the file changes on disk (editor / AI / CLI), preserving the
    /// user's selection by element id. Skips our own writes and mid-write parses.
    fn poll_external(&mut self) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let Some(cur) = mtime(&path) else { return };
        if Some(cur) == self.file_mtime {
            return;
        }
        // On a mid-write parse failure, leave mtime unchanged and retry next poll.
        if let Ok(o) = otm_core::parse_file(&path) {
            // Preserve selection by id, not index (external writes may reorder).
            let keep = self.sel.and_then(|s| self.sel_id(s).map(|id| (s, id)));
            self.otm = o;
            self.sel = keep.and_then(|(s, id)| self.find_sel(s, &id));
            self.file_mtime = Some(cur);
            self.findings = self.lib.analyze(&self.otm);
            self.sync_buffers();
            self.status = format!("reloaded (external change) · {}", path.display());
        }
    }

    fn sel_id(&self, sel: Sel) -> Option<String> {
        match sel {
            Sel::Zone(i) => self.otm.trust_zones.get(i).map(|z| z.id.clone()),
            Sel::Comp(i) => self.otm.components.get(i).map(|c| c.id.clone()),
            Sel::Flow(i) => self.otm.dataflows.get(i).map(|d| d.id.clone()),
            Sel::Asset(i) => self.otm.assets.get(i).map(|a| a.id.clone()),
            Sel::Mit(i) => self.otm.mitigations.get(i).map(|m| m.id.clone()),
        }
    }

    fn find_sel(&self, like: Sel, id: &str) -> Option<Sel> {
        match like {
            Sel::Zone(_) => self
                .otm
                .trust_zones
                .iter()
                .position(|z| z.id == id)
                .map(Sel::Zone),
            Sel::Comp(_) => self
                .otm
                .components
                .iter()
                .position(|c| c.id == id)
                .map(Sel::Comp),
            Sel::Flow(_) => self
                .otm
                .dataflows
                .iter()
                .position(|d| d.id == id)
                .map(Sel::Flow),
            Sel::Asset(_) => self
                .otm
                .assets
                .iter()
                .position(|a| a.id == id)
                .map(Sel::Asset),
            Sel::Mit(_) => self
                .otm
                .mitigations
                .iter()
                .position(|m| m.id == id)
                .map(Sel::Mit),
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
            self.status = "no file — nothing saved".into();
            return;
        };
        match otm_core::to_yaml(&self.otm) {
            Ok(body) => {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::write(&path, body) {
                    Ok(()) => {
                        // Record our own write so the watcher doesn't reload it.
                        self.file_mtime = mtime(&path);
                        self.status = format!("saved ✓ · {}", path.display());
                    }
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
            Act::Reveal(s) => {
                self.sel = Some(s);
                self.scroll_to = true;
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
                    self.sel = None;
                }
            }
            Act::MitSetRisk(i, v) => {
                if let Some(m) = self.otm.mitigations.get_mut(i) {
                    m.risk_reduction = Some(v);
                }
            }
            Act::MitAddTarget(i, id) => {
                if let Some(m) = self.otm.mitigations.get_mut(i) {
                    if !m.applies_to.contains(&id) {
                        m.applies_to.push(id);
                    }
                }
            }
            Act::MitDelTarget(i, id) => {
                if let Some(m) = self.otm.mitigations.get_mut(i) {
                    m.applies_to.retain(|x| x != &id);
                }
            }
            Act::MitAddAddr(i, id) => {
                if let Some(m) = self.otm.mitigations.get_mut(i) {
                    if !m.addresses.contains(&id) {
                        m.addresses.push(id);
                    }
                }
            }
            Act::MitDelAddr(i, id) => {
                if let Some(m) = self.otm.mitigations.get_mut(i) {
                    m.addresses.retain(|x| x != &id);
                }
            }
            Act::DelZone(i) => {
                if i < self.otm.trust_zones.len() {
                    self.otm.trust_zones.remove(i);
                    self.sel = None;
                }
            }
            Act::DelComp(i) => {
                if i < self.otm.components.len() {
                    self.otm.components.remove(i);
                    self.sel = None;
                }
            }
            Act::DelFlow(i) => {
                if i < self.otm.dataflows.len() {
                    self.otm.dataflows.remove(i);
                    self.sel = None;
                }
            }
            Act::DelAsset(i) => {
                if i < self.otm.assets.len() {
                    self.otm.assets.remove(i);
                    self.sel = None;
                }
            }
            Act::NewZone => {
                let id = fresh_id("zone", self.otm.trust_zones.iter().map(|z| z.id.as_str()));
                self.otm.trust_zones.push(TrustZone {
                    id,
                    name: "New zone".into(),
                    risk: Some(TrustRisk {
                        trust_rating: Some(50),
                    }),
                });
                self.sel = Some(Sel::Zone(self.otm.trust_zones.len() - 1));
            }
            Act::NewComp => {
                let id = fresh_id(
                    "component",
                    self.otm.components.iter().map(|c| c.id.as_str()),
                );
                let zone = self.otm.trust_zones.first().map(|z| z.id.clone());
                self.otm.components.push(Component {
                    id,
                    name: "New component".into(),
                    kind: "process".into(),
                    parent: zone.map(|z| Parent {
                        trust_zone: Some(z),
                        component: None,
                    }),
                    assets: Default::default(),
                    attributes: Default::default(),
                });
                self.sel = Some(Sel::Comp(self.otm.components.len() - 1));
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
            Act::NewMit => {
                let id = fresh_id(
                    "mitigation",
                    self.otm.mitigations.iter().map(|m| m.id.as_str()),
                );
                self.otm.mitigations.push(Mitigation {
                    id,
                    name: "New mitigation".into(),
                    description: None,
                    risk_reduction: Some(50),
                    applies_to: Vec::new(),
                    addresses: Vec::new(),
                });
                self.sel = Some(Sel::Mit(self.otm.mitigations.len() - 1));
            }
            Act::Select(_) | Act::Reveal(_) | Act::Undo | Act::Redo => {}
        }
    }

    // ---- drawing ----------------------------------------------------------

    fn top_bar(&mut self, ui: &mut Ui, acts: &mut Vec<Act>) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("wyrm").color(theme::ACCENT).strong());
            ui.separator();
            if ui
                .add_enabled(!self.undo.is_empty(), egui::Button::new("Undo"))
                .clicked()
            {
                acts.push(Act::Undo);
            }
            if ui
                .add_enabled(!self.redo.is_empty(), egui::Button::new("Redo"))
                .clicked()
            {
                acts.push(Act::Redo);
            }
            ui.separator();
            ui.selectable_value(&mut self.view, View::Inspector, "Inspector");
            ui.selectable_value(&mut self.view, View::Graph, "Graph");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(&self.status).color(theme::MUTED).small());
            });
        });
    }

    fn left_panel(&mut self, ui: &mut Ui, acts: &mut Vec<Act>) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Filter").small().color(theme::MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("type to filter…")
                    .desired_width(f32::INFINITY),
            );
        });
        let filter = self.filter.to_lowercase();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                self.tree_section(
                    ui,
                    acts,
                    "zones",
                    "TRUST ZONES",
                    Act::NewZone,
                    |ui, acts| {
                        for (i, z) in self.otm.trust_zones.iter().enumerate() {
                            if !passes(&z.name, &filter) {
                                continue;
                            }
                            let sel = self.sel == Some(Sel::Zone(i));
                            let r =
                                tree_item(ui, sel, theme::PURPLE, single_job(&z.name, theme::TEXT));
                            if r.clicked() {
                                acts.push(Act::Select(Sel::Zone(i)));
                            }
                            if sel && self.scroll_to {
                                r.scroll_to_me(Some(egui::Align::Center));
                            }
                        }
                    },
                );
                self.tree_section(ui, acts, "comps", "COMPONENTS", Act::NewComp, |ui, acts| {
                    for (i, c) in self.otm.components.iter().enumerate() {
                        if !(passes(&c.name, &filter) || passes(&c.kind, &filter)) {
                            continue;
                        }
                        let sel = self.sel == Some(Sel::Comp(i));
                        let r = tree_item(ui, sel, type_color(&c.kind), comp_job(&c.name, &c.kind));
                        if r.clicked() {
                            acts.push(Act::Select(Sel::Comp(i)));
                        }
                        if sel && self.scroll_to {
                            r.scroll_to_me(Some(egui::Align::Center));
                        }
                    }
                });
                self.tree_section(ui, acts, "flows", "DATAFLOWS", Act::NewFlow, |ui, acts| {
                    for (i, d) in self.otm.dataflows.iter().enumerate() {
                        if !passes(&d.name, &filter) {
                            continue;
                        }
                        let sel = self.sel == Some(Sel::Flow(i));
                        let color = if d.tags.iter().any(|t| SECURE_TAGS.contains(&t.as_str())) {
                            theme::GREEN
                        } else {
                            theme::MUTED
                        };
                        let r = tree_item(ui, sel, color, single_job(&d.name, theme::TEXT));
                        if r.clicked() {
                            acts.push(Act::Select(Sel::Flow(i)));
                        }
                        if sel && self.scroll_to {
                            r.scroll_to_me(Some(egui::Align::Center));
                        }
                    }
                });
                self.tree_section(ui, acts, "assets", "ASSETS", Act::NewAsset, |ui, acts| {
                    for (i, a) in self.otm.assets.iter().enumerate() {
                        if !passes(&a.name, &filter) {
                            continue;
                        }
                        let sel = self.sel == Some(Sel::Asset(i));
                        let r = tree_item(ui, sel, theme::YELLOW, single_job(&a.name, theme::TEXT));
                        if r.clicked() {
                            acts.push(Act::Select(Sel::Asset(i)));
                        }
                        if sel && self.scroll_to {
                            r.scroll_to_me(Some(egui::Align::Center));
                        }
                    }
                });
                self.tree_section(ui, acts, "mits", "MITIGATIONS", Act::NewMit, |ui, acts| {
                    for (i, m) in self.otm.mitigations.iter().enumerate() {
                        if !passes(&m.name, &filter) {
                            continue;
                        }
                        let sel = self.sel == Some(Sel::Mit(i));
                        let r = tree_item(ui, sel, theme::ORANGE, single_job(&m.name, theme::TEXT));
                        if r.clicked() {
                            acts.push(Act::Select(Sel::Mit(i)));
                        }
                        if sel && self.scroll_to {
                            r.scroll_to_me(Some(egui::Align::Center));
                        }
                    }
                });
            });
        self.scroll_to = false;
    }

    /// A collapsible tree section with an inline "+ add" button on the header.
    fn tree_section(
        &self,
        ui: &mut Ui,
        acts: &mut Vec<Act>,
        id: &str,
        title: &str,
        add: Act,
        body: impl FnOnce(&mut Ui, &mut Vec<Act>),
    ) {
        let hid = ui.make_persistent_id(id);
        let state =
            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), hid, true);
        let header = state.show_header(ui, |ui| {
            ui.label(RichText::new(title).small().strong().color(theme::MUTED));
            if ui.small_button("+").on_hover_text("Add new").clicked() {
                acts.push(add);
            }
        });
        header.body(|ui| body(ui, acts));
    }

    fn findings_panel(&self, ui: &mut Ui, acts: &mut Vec<Act>) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Findings").strong());
            let (crit, high) = self.finding_counts();
            ui.label(RichText::new(format!("{} total", self.findings.len())).color(theme::MUTED));
            if crit > 0 {
                ui.label(RichText::new(format!("· {crit} critical")).color(theme::RED));
            }
            if high > 0 {
                ui.label(RichText::new(format!("· {high} high")).color(theme::ORANGE));
            }
        });
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if self.findings.is_empty() {
                    ui.label(RichText::new("No findings").color(theme::GREEN));
                }
                for f in &self.findings {
                    let r = ui.horizontal_wrapped(|ui| {
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
                                RichText::new(format!("(was {})", sev_label(base)))
                                    .color(theme::YELLOW)
                                    .small(),
                            );
                        }
                    });
                    // Click a finding → jump to its element in the tree.
                    let resp = r
                        .response
                        .interact(Sense::click())
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text("click to reveal in tree");
                    if resp.clicked() {
                        if let Some(sel) = self.locate(&f.element_id) {
                            acts.push(Act::Reveal(sel));
                        }
                    }
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
        delete_btn(ui, acts, Act::DelZone(i), "Delete trust zone");
    }

    fn inspect_comp(&mut self, ui: &mut Ui, acts: &mut Vec<Act>, i: usize) {
        let comp = self.otm.components[i].clone();
        header(ui, type_color(&comp.kind), "Component");
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
        add_menu(ui, "+ asset", &avail, |id| {
            acts.push(Act::AddCompAsset(i, id))
        });
        self.mitigation_box(ui, acts, comp.id.clone());
        delete_btn(ui, acts, Act::DelComp(i), "Delete component");
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
        add_menu(ui, "+ tag", &avail, |id| acts.push(Act::AddTag(i, id)));
        self.mitigation_box(ui, acts, flow.id.clone());
        delete_btn(ui, acts, Act::DelFlow(i), "Delete dataflow");
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
        delete_btn(ui, acts, Act::DelAsset(i), "Delete asset");
    }

    fn inspect_mit(&mut self, ui: &mut Ui, acts: &mut Vec<Act>, i: usize) {
        let m = self.otm.mitigations[i].clone();
        header(ui, theme::ORANGE, "Mitigation");
        self.name_field(ui, acts, Sel::Mit(i));

        // Risk reduction (0 documentary, 100 resolves the finding).
        let mut rr = m.risk_reduction.unwrap_or(50);
        ui.horizontal(|ui| {
            ui.label("Risk reduction");
            let r = ui.add(egui::Slider::new(&mut rr, 0..=100));
            if r.drag_stopped() || (r.changed() && !r.dragged()) {
                acts.push(Act::MitSetRisk(i, rr));
            }
        });

        // Applies to — the components/dataflows this control protects.
        ui.add_space(8.0);
        ui.label(
            RichText::new("Applies to (components / dataflows)")
                .color(theme::MUTED)
                .small(),
        );
        chips(ui, &m.applies_to, theme::ACCENT, |t| {
            acts.push(Act::MitDelTarget(i, t))
        });
        let mut targets: Vec<(String, String)> = self
            .otm
            .components
            .iter()
            .map(|c| (c.id.clone(), format!("{} (component)", c.name)))
            .chain(
                self.otm
                    .dataflows
                    .iter()
                    .map(|d| (d.id.clone(), format!("{} (dataflow)", d.name))),
            )
            .filter(|(id, _)| !m.applies_to.contains(id))
            .collect();
        targets.sort_by(|a, b| a.1.cmp(&b.1));
        add_menu(ui, "+ target", &targets, |id| {
            acts.push(Act::MitAddTarget(i, id))
        });

        // Addresses — which rules it neutralises (empty = every finding on targets).
        ui.add_space(8.0);
        ui.label(
            RichText::new("Addresses rules (empty = all findings on targets)")
                .color(theme::MUTED)
                .small(),
        );
        chips(ui, &m.addresses, theme::YELLOW, |a| {
            acts.push(Act::MitDelAddr(i, a))
        });
        let rules: Vec<(String, String)> = self
            .lib
            .rules
            .iter()
            .filter(|r| !m.addresses.contains(&r.id))
            .map(|r| (r.id.clone(), format!("{} — {}", r.id, r.name)))
            .collect();
        add_menu(ui, "+ rule", &rules, |id| acts.push(Act::MitAddAddr(i, id)));

        delete_btn(ui, acts, Act::DelMit(i), "Delete mitigation");
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

    /// A Mermaid-like graph: components in columns by trust zone, dataflows as
    /// arrows. Click a node to select and reveal it in the tree.
    fn graph_view(&mut self, ui: &mut Ui, acts: &mut Vec<Act>) {
        let filter = self.filter.to_lowercase();

        // Columns ordered internet → trusted; unzoned/unknown in a trailing column.
        let mut zones: Vec<(String, String, u8)> = self
            .otm
            .trust_zones
            .iter()
            .map(|z| {
                (
                    z.id.clone(),
                    z.name.clone(),
                    z.risk.as_ref().and_then(|r| r.trust_rating).unwrap_or(50),
                )
            })
            .collect();
        zones.sort_by_key(|(_, _, r)| *r);
        let mut col_of: HashMap<String, usize> = HashMap::new();
        for (ci, (id, _, _)) in zones.iter().enumerate() {
            col_of.insert(id.clone(), ci);
        }
        let ungrouped = zones.len();
        let ncols = zones.len() + 1;

        const NW: f32 = 186.0;
        const NH: f32 = 30.0;
        const COLW: f32 = 214.0;
        const VGAP: f32 = 12.0;
        const TOP: f32 = 44.0;
        const LEFT: f32 = 14.0;

        // Worst finding severity per element id, so the diagram shows risk.
        let worst = self.worst_by_element();

        let mut col_y = vec![TOP; ncols];
        let mut nodes: Vec<(usize, Rect, String, String, Option<Severity>)> = Vec::new();
        let mut centers: HashMap<String, Pos2> = HashMap::new();
        for (i, c) in self.otm.components.iter().enumerate() {
            if !(passes(&c.name, &filter) || passes(&c.kind, &filter)) {
                continue;
            }
            let col = c
                .parent
                .as_ref()
                .and_then(|p| p.trust_zone.as_ref())
                .and_then(|z| col_of.get(z))
                .copied()
                .unwrap_or(ungrouped);
            let x = LEFT + col as f32 * COLW;
            let y = col_y[col];
            let rect = Rect::from_min_size(egui::pos2(x, y), egui::vec2(NW, NH));
            col_y[col] += NH + VGAP;
            centers.insert(c.id.clone(), rect.center());
            nodes.push((
                i,
                rect,
                c.kind.clone(),
                c.name.clone(),
                worst.get(&c.id).copied(),
            ));
        }
        // Edges within the visible set — colored by finding severity if any.
        let edges: Vec<(Pos2, Pos2, Color32)> = self
            .otm
            .dataflows
            .iter()
            .filter_map(|d| {
                let a = centers.get(&d.source)?;
                let b = centers.get(&d.destination)?;
                let color = if let Some(sev) = worst.get(&d.id) {
                    sev_color(*sev)
                } else if d.tags.iter().any(|t| SECURE_TAGS.contains(&t.as_str())) {
                    theme::GREEN
                } else {
                    theme::MUTED
                };
                Some((*a, *b, color))
            })
            .collect();
        let labels: Vec<(f32, String)> = zones
            .iter()
            .enumerate()
            .map(|(ci, (_, name, _))| (LEFT + ci as f32 * COLW + NW / 2.0, name.clone()))
            .chain((col_y[ungrouped] > TOP).then(|| {
                (
                    LEFT + ungrouped as f32 * COLW + NW / 2.0,
                    "(no zone)".into(),
                )
            }))
            .collect();

        let canvas = egui::vec2(
            ncols as f32 * COLW + LEFT,
            col_y.iter().cloned().fold(TOP, f32::max) + 20.0,
        );

        if nodes.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("No components to show").color(theme::MUTED));
            });
            return;
        }

        egui::ScrollArea::both().show(ui, |ui| {
            let (bg, _) = ui.allocate_exact_size(canvas, Sense::hover());
            let o = bg.min.to_vec2();
            let p = ui.painter_at(bg);
            // column headers
            for (x, name) in &labels {
                p.text(
                    egui::pos2(*x, 18.0) + o,
                    Align2::CENTER_CENTER,
                    name,
                    FontId::proportional(12.0),
                    theme::MUTED,
                );
            }
            // edges under nodes
            for (a, b, color) in &edges {
                arrow(&p, *a + o, *b + o, *color);
            }
            // nodes
            for (idx, rect, kind, name, sev) in &nodes {
                let r = rect.translate(o);
                let resp = ui.interact(r, ui.make_persistent_id(("node", idx)), Sense::click());
                let selected = self.sel == Some(Sel::Comp(*idx));
                p.rect_filled(r, CornerRadius::same(6), theme::ELEV);
                // type color bar on the left edge
                let bar = Rect::from_min_max(r.min, egui::pos2(r.min.x + 4.0, r.max.y));
                p.rect_filled(bar, CornerRadius::same(2), type_color(kind));
                // a finding? outline in the severity color + a corner dot.
                if let Some(sev) = sev {
                    p.rect_stroke(
                        r,
                        CornerRadius::same(6),
                        Stroke::new(1.5_f32, sev_color(*sev)),
                        StrokeKind::Inside,
                    );
                    p.circle_filled(
                        egui::pos2(r.max.x - 6.0, r.min.y + 6.0),
                        4.0,
                        sev_color(*sev),
                    );
                }
                if selected {
                    p.rect_stroke(
                        r,
                        CornerRadius::same(6),
                        Stroke::new(2.0_f32, theme::ACCENT),
                        StrokeKind::Inside,
                    );
                }
                p.text(
                    egui::pos2(r.min.x + 10.0, r.center().y),
                    Align2::LEFT_CENTER,
                    truncate(name, 22),
                    FontId::proportional(12.5),
                    theme::TEXT,
                );
                if resp.clicked() {
                    acts.push(Act::Reveal(Sel::Comp(*idx)));
                }
                let tip = match sev {
                    Some(s) => format!("{name}  ·  {kind}\n{} finding", sev_label(*s)),
                    None => format!("{name}  ·  {kind}"),
                };
                resp.on_hover_text(tip);
            }
        });
    }

    fn finding_counts(&self) -> (usize, usize) {
        let crit = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        (crit, high)
    }

    /// Worst finding severity per element id (for graph risk indicators).
    fn worst_by_element(&self) -> HashMap<String, Severity> {
        let mut m: HashMap<String, Severity> = HashMap::new();
        for f in &self.findings {
            m.entry(f.element_id.clone())
                .and_modify(|s| {
                    if f.severity > *s {
                        *s = f.severity;
                    }
                })
                .or_insert(f.severity);
        }
        m
    }

    fn locate(&self, element_id: &str) -> Option<Sel> {
        if let Some(i) = self.otm.components.iter().position(|c| c.id == element_id) {
            return Some(Sel::Comp(i));
        }
        if let Some(i) = self.otm.dataflows.iter().position(|d| d.id == element_id) {
            return Some(Sel::Flow(i));
        }
        None
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll the file for external edits (editor / AI / CLI) and keep repainting
        // so we notice them even while idle.
        self.poll_external();
        ctx.request_repaint_after(std::time::Duration::from_millis(800));

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
            .default_width(270.0)
            .show(ctx, |ui| self.left_panel(ui, &mut acts));
        egui::TopBottomPanel::bottom("findings")
            .resizable(true)
            .default_height(180.0)
            .show(ctx, |ui| self.findings_panel(ui, &mut acts));
        egui::CentralPanel::default().show(ctx, |ui| match self.view {
            View::Inspector => self.inspector(ui, &mut acts),
            View::Graph => self.graph_view(ui, &mut acts),
        });

        for a in acts {
            self.apply(a);
        }
    }
}

// ---- small widgets -------------------------------------------------------

fn tree_item(ui: &mut Ui, selected: bool, dot: Color32, job: LayoutJob) -> egui::Response {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), 4.5, dot);
        ui.selectable_label(selected, job)
    })
    .inner
}

fn single_job(name: &str, color: Color32) -> LayoutJob {
    let mut job = LayoutJob::default();
    job.append(
        name,
        0.0,
        egui::TextFormat {
            color,
            ..Default::default()
        },
    );
    job
}

fn comp_job(name: &str, kind: &str) -> LayoutJob {
    let mut job = LayoutJob::default();
    job.append(
        name,
        0.0,
        egui::TextFormat {
            color: theme::TEXT,
            ..Default::default()
        },
    );
    job.append(
        &format!("  {kind}"),
        0.0,
        egui::TextFormat {
            color: type_color(kind),
            ..Default::default()
        },
    );
    job
}

fn type_color(kind: &str) -> Color32 {
    match kind {
        "web-service" => theme::ACCENT,
        "database" => theme::ORANGE,
        "data-store" => theme::YELLOW,
        "message-queue" => theme::PURPLE,
        "external-entity" => theme::RED,
        "identity" => Color32::from_rgb(0x56, 0xb6, 0xc2),
        "process" => Color32::from_rgb(0x8a, 0x91, 0x9e),
        _ => theme::MUTED,
    }
}

fn passes(hay: &str, filter: &str) -> bool {
    filter.is_empty() || hay.to_lowercase().contains(filter)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

fn arrow(p: &egui::Painter, a: Pos2, b: Pos2, color: Color32) {
    let stroke = Stroke::new(1.4_f32, color);
    p.line_segment([a, b], stroke);
    let dir = (b - a).normalized();
    if !dir.x.is_finite() {
        return;
    }
    let n = egui::vec2(-dir.y, dir.x);
    let s = 8.0;
    let tip = b - dir * 2.0;
    p.add(Shape::convex_polygon(
        vec![
            tip,
            tip - dir * s + n * s * 0.5,
            tip - dir * s - n * s * 0.5,
        ],
        color,
        Stroke::NONE,
    ));
}

fn header(ui: &mut Ui, color: Color32, kind: &str) {
    ui.label(RichText::new(kind).color(color).heading());
    ui.add_space(4.0);
}

fn delete_btn(ui: &mut Ui, acts: &mut Vec<Act>, act: Act, label: &str) {
    ui.add_space(12.0);
    ui.separator();
    if ui.button(RichText::new(label).color(theme::RED)).clicked() {
        acts.push(act);
    }
}

fn mtime(path: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

fn chips(ui: &mut Ui, items: &[String], color: Color32, mut on_del: impl FnMut(String)) {
    ui.horizontal_wrapped(|ui| {
        if items.is_empty() {
            ui.label(RichText::new("none").color(theme::MUTED).small());
        }
        for it in items {
            ui.horizontal(|ui| {
                ui.label(RichText::new(it).color(color));
                if ui.small_button("×").clicked() {
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
