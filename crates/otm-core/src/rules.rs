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
    /// Component carrying an attribute `tag` — either `"key"` (present) or
    /// `"key=value"` (exact match). Used for annotated IAM facets like
    /// `provisioning=manual` or `privilege=high`.
    HasTag { tag: String },
    /// Component that is the source of at least `min` dataflows — a proxy for how
    /// many resources an identity can reach (access fan-out).
    AccessFanOut { min: usize },
    /// Element records **no** control of the named family (authz, authn, hardened,
    /// ratelimit, resilience, backup, signing, integrity, waf, logging) — checked
    /// against its attributes/tags and any linked mitigation. Absence is only
    /// scored at full severity when the model uses that control convention
    /// elsewhere (see the noise floor in `analyze`); otherwise it floors to Low.
    LacksControl { control: String },
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
                            let mut f = finding_for(rule, &df.id, &df.name);
                            floor_uncertain(&mut f, rule, otm);
                            findings.push(f);
                        }
                    }
                }
                Target::Component => {
                    for c in &otm.components {
                        if rule.when.iter().all(|p| eval_component(p, c, otm)) {
                            let mut f = finding_for(rule, &c.id, &c.name);
                            floor_uncertain(&mut f, rule, otm);
                            findings.push(f);
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

/// Noise floor for control-absence rules: if a rule asserts `lacksControl{X}` for
/// a control the model never uses, we can't distinguish "provably absent" from
/// "never modelled", so cap the finding at Low.
fn floor_uncertain(f: &mut Finding, rule: &Rule, otm: &Otm) {
    let uncertain = rule.when.iter().any(
        |p| matches!(p, Predicate::LacksControl { control } if !model_uses_control(otm, control)),
    );
    if uncertain && f.severity > Severity::Low {
        f.base_severity = Some(f.severity);
        f.severity = Severity::Low;
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
        Predicate::LacksControl { control } => !dataflow_asserts_control(otm, df, control),
        // Component-only predicates never match a dataflow.
        Predicate::ComponentKindIn { .. }
        | Predicate::LowTrustZone { .. }
        | Predicate::HasTag { .. }
        | Predicate::AccessFanOut { .. } => false,
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
        // Resolve via trust_zone_of so components nested under a module/cluster
        // component (parent.component) inherit their container's zone.
        Predicate::LowTrustZone { max_trust } => otm
            .trust_zone_of(&c.id)
            .and_then(|tz| trust_rating(otm, tz))
            .is_some_and(|rating| rating <= *max_trust),
        Predicate::HasTag { tag } => match tag.split_once('=') {
            Some((k, v)) => c.attributes.get(k).map(String::as_str) == Some(v),
            None => c.attributes.contains_key(tag),
        },
        Predicate::AccessFanOut { min } => {
            otm.dataflows.iter().filter(|d| d.source == c.id).count() >= *min
        }
        Predicate::LacksControl { control } => !component_asserts_control(otm, c, control),
        // Dataflow-only predicates never match a component.
        Predicate::CrossesTrustBoundary | Predicate::NotEncrypted => false,
    }
}

/// Alias words that count as asserting a control family — matched as a
/// case-insensitive substring against attributes, tags, and linked mitigations.
fn control_aliases(control: &str) -> &'static [&'static str] {
    match control {
        "authz" => &["authz", "authoriz", "accesscontrol", "rbac", "iap", "iam"],
        "authn" => &["authn", "authenticat", "mfa", "2fa", "oauth", "oidc", "sso"],
        "hardened" => &["harden", "baseline", "cis"],
        "ratelimit" => &["ratelimit", "rate-limit", "throttl"],
        "resilience" => &["resilien", "autoscal", "hpa", "replicas"],
        "backup" => &["backup", "replication", "snapshot"],
        "signing" => &["signing", "signature", "signed", "cosign", "sigstore"],
        "integrity" => &["integrity", "checksum", "signature", "signing"],
        "waf" => &["waf", "armor", "security-policy", "cloudflare"],
        "logging" => &["logging", "audit", "log-sink", "flow-log"],
        _ => &[],
    }
}

fn hits(s: &str, aliases: &[&str]) -> bool {
    let s = s.to_lowercase();
    aliases.iter().any(|a| s.contains(a))
}

/// A mitigation linked to `element_id` whose id/name names the control family.
fn mitigation_asserts(otm: &Otm, element_id: &str, aliases: &[&str]) -> bool {
    otm.mitigations.iter().any(|m| {
        m.applies_to.iter().any(|t| t == element_id)
            && (hits(&m.id, aliases) || hits(&m.name, aliases))
    })
}

fn component_asserts_control(otm: &Otm, c: &Component, control: &str) -> bool {
    let al = control_aliases(control);
    c.attributes.iter().any(|(k, v)| hits(k, al) || hits(v, al))
        || mitigation_asserts(otm, &c.id, al)
}

fn dataflow_asserts_control(otm: &Otm, d: &Dataflow, control: &str) -> bool {
    let al = control_aliases(control);
    d.tags.iter().any(|t| hits(t, al))
        || d.attributes.iter().any(|(k, v)| hits(k, al) || hits(v, al))
        || mitigation_asserts(otm, &d.id, al)
}

/// Does the model use this control convention anywhere? If not, a `lacksControl`
/// finding can't tell "provably absent" from "never modelled" — so it's floored.
fn model_uses_control(otm: &Otm, control: &str) -> bool {
    otm.components
        .iter()
        .any(|c| component_asserts_control(otm, c, control))
        || otm
            .dataflows
            .iter()
            .any(|d| dataflow_asserts_control(otm, d, control))
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
        Asset, AssetRisk, Component, ComponentAssets, Dataflow, Mitigation, Parent, Project,
        TrustRisk, TrustZone,
    };

    fn identity(id: &str, attrs: &[(&str, &str)], assets: Vec<String>) -> Component {
        Component {
            id: id.into(),
            name: id.into(),
            kind: "identity".into(),
            parent: Some(Parent {
                trust_zone: Some("edge".into()),
                component: None,
            }),
            assets: ComponentAssets {
                processed: assets,
                stored: vec![],
            },
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn lacks_control_floors_when_convention_unused_else_full() {
        // exposed_model: `api` is a web-service in the edge zone holding pii, no authz.
        let mut otm = exposed_model();
        let t008 = |o: &Otm| {
            ThreatLibrary::bundled()
                .analyze(o)
                .into_iter()
                .find(|f| f.rule_id == "WYRM-T008" && f.element_id == "api")
        };
        // Nothing in the model annotates authz → floored to Low.
        let f = t008(&otm).expect("T008 fires on api");
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.base_severity, Some(Severity::High));

        // Once any element asserts authz, the convention is in use → full severity.
        otm.components
            .push(identity("gw", &[("authz", "oidc")], vec![]));
        assert_eq!(t008(&otm).unwrap().severity, Severity::High);
    }

    #[test]
    fn iam_rules_flag_standing_and_broad_access() {
        // T006: manually-provisioned human identity touching sensitive data.
        let mut a = exposed_model();
        a.components.push(identity(
            "admin",
            &[("provisioning", "manual")],
            vec!["pii".into()],
        ));
        assert!(
            ThreatLibrary::bundled()
                .analyze(&a)
                .iter()
                .any(|f| f.rule_id == "WYRM-T006")
        );

        // T007: high-privilege identity reaching 5+ resources.
        let mut b = exposed_model();
        b.components
            .push(identity("sa", &[("privilege", "high")], vec![]));
        for i in 0..5 {
            b.dataflows.push(Dataflow {
                id: format!("f{i}"),
                name: format!("f{i}"),
                source: "sa".into(),
                destination: "api".into(),
                assets: vec![],
                attributes: Default::default(),
                tags: vec![],
            });
        }
        assert!(
            ThreatLibrary::bundled()
                .analyze(&b)
                .iter()
                .any(|f| f.rule_id == "WYRM-T007")
        );
    }

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
