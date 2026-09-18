//! Data-driven STRIDE rule engine.
//!
//! Rules are declarative data (see `threats/library.yaml`), not code, so the
//! catalogue can grow without recompiling. The predicate vocabulary is adapted
//! from OWASP pytm's threat library — pytm encodes conditions as Python
//! expressions over its DFD elements; here the equivalent conditions are a small
//! typed enum evaluated over the OTM graph.

use crate::model::{Component, Dataflow, Mitigation, Otm};
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

impl Severity {
    fn rung(self) -> i8 {
        match self {
            Severity::Low => 0,
            Severity::Medium => 1,
            Severity::High => 2,
            Severity::Critical => 3,
        }
    }

    /// Step this severity down by `steps` rungs, saturating at `Low`.
    fn lower(self, steps: i8) -> Severity {
        match (self.rung() - steps).max(0) {
            0 => Severity::Low,
            1 => Severity::Medium,
            2 => Severity::High,
            _ => Severity::Critical,
        }
    }
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
    /// Ids of linked mitigations that lowered this finding's severity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitigated_by: Vec<String>,
    /// The pre-mitigation severity, present only when a control downgraded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_severity: Option<Severity>,
}

/// The default catalogue, embedded at build time so the CLI and WASM builds are
/// self-contained. Override with [`ThreatLibrary::from_yaml`].
const DEFAULT_LIBRARY: &str = include_str!("../threats/library.yaml");

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
        // Apply linked controls before ranking, so severities already reflect
        // any WAF/auth/encryption mitigation the model records.
        let mut findings = apply_mitigations(findings, otm);
        // Critical first; stable so catalogue order breaks ties deterministically.
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
        findings
    }
}

/// Down-rank (or resolve) findings that a linked mitigation covers. A mitigation
/// covers a finding when it targets the finding's element and either addresses
/// its rule or addresses nothing (⇒ all findings on that element). Reductions on
/// the same finding sum, capped at 100 — full coverage resolves it outright.
fn apply_mitigations(findings: Vec<Finding>, otm: &Otm) -> Vec<Finding> {
    if otm.mitigations.is_empty() {
        return findings;
    }
    let covers = |m: &Mitigation, f: &Finding| {
        m.applies_to.iter().any(|t| t == &f.element_id)
            && (m.addresses.is_empty() || m.addresses.iter().any(|r| r == &f.rule_id))
    };
    let mut out = Vec::with_capacity(findings.len());
    for mut f in findings {
        let linked: Vec<&Mitigation> = otm.mitigations.iter().filter(|m| covers(m, &f)).collect();
        if linked.is_empty() {
            out.push(f);
            continue;
        }
        let reduction: u16 = linked
            .iter()
            .map(|m| u16::from(m.risk_reduction.unwrap_or(50)))
            .sum::<u16>()
            .min(100);
        if reduction >= 100 {
            // Fully mitigated — treat as resolved and drop from the report.
            continue;
        }
        let steps = if reduction >= 70 {
            2
        } else if reduction >= 40 {
            1
        } else {
            0
        };
        if steps > 0 {
            f.base_severity = Some(f.severity);
            f.severity = f.severity.lower(steps);
        }
        f.mitigated_by = linked.iter().map(|m| m.id.clone()).collect();
        out.push(f);
    }
    out
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
        mitigated_by: Vec::new(),
        base_severity: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Asset, AssetRisk, Component, ComponentAssets, Mitigation, Parent, Project, TrustRisk,
        TrustZone,
    };

    /// An internet-facing component holding sensitive data ⇒ WYRM-T003 (high).
    fn exposed_model() -> Otm {
        Otm {
            otm_version: "0.2.0".into(),
            project: Project {
                id: "p".into(),
                name: "p".into(),
                owner: None,
                description: None,
            },
            trust_zones: vec![TrustZone {
                id: "edge".into(),
                name: "edge".into(),
                risk: Some(TrustRisk {
                    trust_rating: Some(10),
                }),
            }],
            components: vec![Component {
                id: "api".into(),
                name: "api".into(),
                kind: "web-service".into(),
                parent: Some(Parent {
                    trust_zone: Some("edge".into()),
                    component: None,
                }),
                assets: ComponentAssets {
                    processed: vec!["pii".into()],
                    stored: vec![],
                },
                attributes: Default::default(),
            }],
            dataflows: vec![],
            assets: vec![Asset {
                id: "pii".into(),
                name: "pii".into(),
                risk: Some(AssetRisk {
                    confidentiality: 90,
                    integrity: 0,
                    availability: 0,
                }),
            }],
            threats: vec![],
            mitigations: vec![],
        }
    }

    fn mitigation(reduction: Option<u8>) -> Mitigation {
        Mitigation {
            id: "waf".into(),
            name: "Edge WAF".into(),
            risk_reduction: reduction,
            applies_to: vec!["api".into()],
            ..Default::default()
        }
    }

    #[test]
    fn trust_zone_resolves_through_parent_component_chain() {
        let mut otm = exposed_model();
        // A child whose parent is the "api" component (not a zone directly).
        otm.components.push(Component {
            id: "child".into(),
            name: "child".into(),
            kind: "process".into(),
            parent: Some(Parent {
                trust_zone: None,
                component: Some("api".into()),
            }),
            assets: ComponentAssets::default(),
            attributes: Default::default(),
        });
        // Walks child → api → edge zone.
        assert_eq!(otm.trust_zone_of("child"), Some("edge"));
    }

    #[test]
    fn unlinked_mitigation_does_not_downgrade() {
        let mut otm = exposed_model();
        let mut m = mitigation(Some(100));
        m.applies_to.clear(); // documentary only
        otm.mitigations.push(m);
        let f = &ThreatLibrary::bundled().analyze(&otm)[0];
        assert_eq!(f.severity, Severity::High);
        assert!(f.mitigated_by.is_empty());
    }

    #[test]
    fn partial_mitigation_steps_severity_down() {
        let mut otm = exposed_model();
        otm.mitigations.push(mitigation(Some(50))); // 40–69 ⇒ one rung
        let f = &ThreatLibrary::bundled().analyze(&otm)[0];
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.base_severity, Some(Severity::High));
        assert_eq!(f.mitigated_by, vec!["waf".to_string()]);
    }

    #[test]
    fn full_mitigation_resolves_finding() {
        let mut otm = exposed_model();
        otm.mitigations.push(mitigation(Some(100)));
        assert!(
            !ThreatLibrary::bundled()
                .analyze(&otm)
                .iter()
                .any(|f| f.rule_id == "WYRM-T003"),
            "fully-mitigated finding is resolved"
        );
    }

    #[test]
    fn addresses_scopes_which_rule_is_muted() {
        let mut otm = exposed_model();
        let mut m = mitigation(Some(100));
        m.addresses = vec!["WYRM-T999".into()]; // targets a different rule
        otm.mitigations.push(m);
        let f = &ThreatLibrary::bundled().analyze(&otm)[0];
        assert_eq!(
            f.severity,
            Severity::High,
            "unrelated rule stays full severity"
        );
    }
}
