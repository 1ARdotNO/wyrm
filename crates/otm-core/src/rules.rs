//! Data-driven STRIDE rule engine.
//!
//! Rules are declarative data (see `threats/library.yaml`), not code, so the
//! catalogue can grow without recompiling. The predicate vocabulary is adapted
//! from OWASP pytm's threat library — pytm encodes conditions as Python
//! expressions over its DFD elements; here the equivalent conditions are a small
//! typed enum evaluated over the OTM graph.

use crate::model::{Component, Dataflow, Otm};
use serde::{Deserialize, Serialize};

/// STRIDE category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stride {
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Which kind of OTM element a rule iterates over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Target {
    Dataflow,
    Component,
}

/// A single condition. All predicates on a rule are AND-ed together.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Predicate {
    /// Dataflow whose source and destination sit in different trust zones.
    CrossesTrustBoundary,
    /// Dataflow with no evidence of transport encryption.
    NotEncrypted,
    /// Element touches an asset whose confidentiality rating is at least `min`.
    CarriesSensitiveData { min_confidentiality: u8 },
    /// Component whose `type` is one of the listed OTM kinds.
    ComponentKindIn { kinds: Vec<String> },
    /// Component sitting in a trust zone rated at or below `max_trust` (internet-facing).
    LowTrustZone { max_trust: u8 },
}

/// One catalogue entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub stride: Stride,
    pub severity: Severity,
    pub target: Target,
    pub when: Vec<Predicate>,
    pub description: String,
    pub mitigation: String,
}

/// A rule that fired against a specific element.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub stride: Stride,
    pub severity: Severity,
    pub element_id: String,
    pub element_name: String,
    pub description: String,
    pub mitigation: String,
}

/// The default catalogue, embedded at build time so the CLI and WASM builds are
/// self-contained. Override with [`ThreatLibrary::from_yaml`].
const DEFAULT_LIBRARY: &str = include_str!("../../../threats/library.yaml");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLibrary {
    pub rules: Vec<Rule>,
}

impl ThreatLibrary {
    /// Load the catalogue bundled with wyrm.
    pub fn bundled() -> Self {
        serde_yaml_ng::from_str(DEFAULT_LIBRARY).expect("bundled threat library must parse")
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml_ng::Error> {
        serde_yaml_ng::from_str(yaml)
    }

    /// Evaluate every rule against the model, returning findings sorted by
    /// severity (most severe first).
    pub fn analyze(&self, otm: &Otm) -> Vec<Finding> {
        let mut findings = Vec::new();
        for rule in &self.rules {
            match rule.target {
                Target::Dataflow => {
                    for df in &otm.dataflows {
                        if rule.when.iter().all(|p| eval_dataflow(p, df, otm)) {
                            findings.push(finding_for(rule, &df.id, &df.name));
                        }
                    }
                }
                Target::Component => {
                    for c in &otm.components {
                        if rule.when.iter().all(|p| eval_component(p, c, otm)) {
                            findings.push(finding_for(rule, &c.id, &c.name));
                        }
                    }
                }
            }
        }
        // Critical first; stable so catalogue order breaks ties deterministically.
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
        findings
    }
}

fn finding_for(rule: &Rule, element_id: &str, element_name: &str) -> Finding {
    Finding {
        rule_id: rule.id.clone(),
        title: rule.name.clone(),
        stride: rule.stride,
        severity: rule.severity,
        element_id: element_id.to_string(),
        element_name: element_name.to_string(),
        description: rule.description.clone(),
        mitigation: rule.mitigation.clone(),
    }
}

fn eval_dataflow(p: &Predicate, df: &Dataflow, otm: &Otm) -> bool {
    match p {
        Predicate::CrossesTrustBoundary => {
            match (
                otm.trust_zone_of(&df.source),
                otm.trust_zone_of(&df.destination),
            ) {
                (Some(a), Some(b)) => a != b,
                _ => false,
            }
        }
        Predicate::NotEncrypted => !is_encrypted(df),
        Predicate::CarriesSensitiveData {
            min_confidentiality,
        } => df
            .assets
            .iter()
            .any(|id| asset_confidentiality(otm, id) >= *min_confidentiality),
        // Component-only predicates never match a dataflow.
        Predicate::ComponentKindIn { .. } | Predicate::LowTrustZone { .. } => false,
    }
}

fn eval_component(p: &Predicate, c: &Component, otm: &Otm) -> bool {
    match p {
        Predicate::ComponentKindIn { kinds } => kinds.iter().any(|k| k == &c.kind),
        Predicate::CarriesSensitiveData {
            min_confidentiality,
        } => c
            .assets
            .all()
            .any(|id| asset_confidentiality(otm, id) >= *min_confidentiality),
        Predicate::LowTrustZone { max_trust } => c
            .parent
            .as_ref()
            .and_then(|p| p.trust_zone.as_deref())
            .and_then(|tz| trust_rating(otm, tz))
            .is_some_and(|rating| rating <= *max_trust),
        // Dataflow-only predicates never match a component.
        Predicate::CrossesTrustBoundary | Predicate::NotEncrypted => false,
    }
}

/// A flow counts as encrypted if any attribute/tag advertises transport security.
fn is_encrypted(df: &Dataflow) -> bool {
    const SECURE_MARKERS: &[&str] = &["https", "tls", "mtls", "wss", "ssh", "encrypted"];
    if let Some(v) = df
        .attributes
        .get("isEncrypted")
        .or_else(|| df.attributes.get("encrypted"))
    {
        if v.eq_ignore_ascii_case("true") {
            return true;
        }
    }
    if let Some(proto) = df.attributes.get("protocol") {
        if SECURE_MARKERS.iter().any(|m| proto.eq_ignore_ascii_case(m)) {
            return true;
        }
    }
    df.tags
        .iter()
        .any(|t| SECURE_MARKERS.iter().any(|m| t.eq_ignore_ascii_case(m)))
}

fn asset_confidentiality(otm: &Otm, asset_id: &str) -> u8 {
    otm.asset(asset_id)
        .and_then(|a| a.risk.as_ref())
        .map(|r| r.confidentiality)
        .unwrap_or(0)
}

fn trust_rating(otm: &Otm, tz_id: &str) -> Option<u8> {
    otm.trust_zones
        .iter()
        .find(|tz| tz.id == tz_id)?
        .risk
        .as_ref()?
        .trust_rating
}
