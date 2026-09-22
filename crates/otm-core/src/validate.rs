//! Referential-integrity checks: does the graph actually hang together?
//!
//! These are the diagnostics an editor surfaces as you type — dangling
//! references, duplicate ids, orphaned components — distinct from the STRIDE
//! findings produced by [`crate::rules`].

use crate::model::Otm;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    pub severity: Severity,
    /// Stable machine code, e.g. `dataflow.source.unknown`.
    pub code: String,
    pub message: String,
    /// The id of the element this diagnostic is about, when known. Lets an editor
    /// place the squiggle on the right line by locating the id in the source.
    pub element: Option<String>,
}

impl Diagnostic {
    fn error(code: &str, message: String) -> Self {
        Self {
            severity: Severity::Error,
            code: code.to_string(),
            message,
            element: None,
        }
    }
    fn warning(code: &str, message: String) -> Self {
        Self {
            severity: Severity::Warning,
            code: code.to_string(),
            message,
            element: None,
        }
    }
    /// Attach the owning element id for source positioning.
    fn at(mut self, id: &str) -> Self {
        self.element = Some(id.to_string());
        self
    }
}

/// Validate cross-references and cardinality. An empty result means the model is
/// structurally sound (it says nothing about its security posture).
pub fn validate(otm: &Otm) -> Vec<Diagnostic> {
    let mut out = Vec::new();

    let component_ids: BTreeSet<&str> = otm.components.iter().map(|c| c.id.as_str()).collect();
    let trustzone_ids: BTreeSet<&str> = otm.trust_zones.iter().map(|t| t.id.as_str()).collect();
    let asset_ids: BTreeSet<&str> = otm.assets.iter().map(|a| a.id.as_str()).collect();

    check_unique(
        &mut out,
        "component",
        otm.components.iter().map(|c| c.id.as_str()),
    );
    check_unique(
        &mut out,
        "trustZone",
        otm.trust_zones.iter().map(|t| t.id.as_str()),
    );
    check_unique(
        &mut out,
        "dataflow",
        otm.dataflows.iter().map(|d| d.id.as_str()),
    );
    check_unique(&mut out, "asset", otm.assets.iter().map(|a| a.id.as_str()));

    for c in &otm.components {
        let explicit_zone = c.parent.as_ref().and_then(|p| p.trust_zone.as_deref());
        if let Some(tz) = explicit_zone {
            if !trustzone_ids.contains(tz) {
                out.push(
                    Diagnostic::error(
                        "component.trustZone.unknown",
                        format!("component '{}' references unknown trust zone '{tz}'", c.id),
                    )
                    .at(&c.id),
                );
            }
        } else if otm.trust_zone_of(&c.id).is_none() {
            // No resolvable zone — a missing parent, or a parent.component chain
            // that never reaches one. Either way every zone-based rule skips it.
            out.push(
                Diagnostic::warning(
                    "component.trustZone.unresolved",
                    format!(
                        "component '{}' resolves to no trust zone; boundary analysis will skip it",
                        c.id
                    ),
                )
                .at(&c.id),
            );
        }
        for asset in c.assets.all() {
            if !asset_ids.contains(asset.as_str()) {
                out.push(
                    Diagnostic::error(
                        "component.asset.unknown",
                        format!("component '{}' references unknown asset '{asset}'", c.id),
                    )
                    .at(&c.id),
                );
            }
        }
    }

    for df in &otm.dataflows {
        if !component_ids.contains(df.source.as_str()) {
            out.push(
                Diagnostic::error(
                    "dataflow.source.unknown",
                    format!("dataflow '{}' has unknown source '{}'", df.id, df.source),
                )
                .at(&df.id),
            );
        }
        if !component_ids.contains(df.destination.as_str()) {
            out.push(
                Diagnostic::error(
                    "dataflow.destination.unknown",
                    format!(
                        "dataflow '{}' has unknown destination '{}'",
                        df.id, df.destination
                    ),
                )
                .at(&df.id),
            );
        }
        for asset in &df.assets {
            if !asset_ids.contains(asset.as_str()) {
                out.push(
                    Diagnostic::error(
                        "dataflow.asset.unknown",
                        format!("dataflow '{}' references unknown asset '{asset}'", df.id),
                    )
                    .at(&df.id),
                );
            }
        }
    }

    out
}

fn check_unique<'a>(out: &mut Vec<Diagnostic>, kind: &str, ids: impl Iterator<Item = &'a str>) {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            out.push(
                Diagnostic::error("id.duplicate", format!("duplicate {kind} id '{id}'")).at(id),
            );
        }
    }
}

/// True when no [`Severity::Error`] diagnostics are present.
pub fn is_valid(diagnostics: &[Diagnostic]) -> bool {
    !diagnostics.iter().any(|d| d.severity == Severity::Error)
}
