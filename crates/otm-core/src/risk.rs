//! OWASP Risk Rating Methodology over findings — a likelihood-aware view on top
//! of each rule's fixed severity. Risk = Likelihood × Impact, each the 0–9 mean
//! of its factors, banded Low(<3)/Medium(<6)/High(≥6) and combined via the OWASP
//! matrix into Note/Low/Medium/High/Critical.
//!
//! The factors are seeded from what the OTM graph already knows — asset CIA drives
//! the technical impact, trust-zone exposure drives opportunity/size/ease, and a
//! logging control drives accountability/detection — then overlaid with org-wide
//! defaults (`.threatmodel/risk.yaml`) and per-element `risk.<factor>` attributes.

use crate::model::Otm;
use crate::rules::Finding;
use serde::{Deserialize, Serialize};

/// The 16 OWASP factors, each 0–9.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Factors {
    // Threat-agent
    pub skill: u8,
    pub motive: u8,
    pub opportunity: u8,
    pub size: u8,
    // Vulnerability
    pub ease_of_discovery: u8,
    pub ease_of_exploit: u8,
    pub awareness: u8,
    pub intrusion_detection: u8,
    // Technical impact
    pub loss_of_confidentiality: u8,
    pub loss_of_integrity: u8,
    pub loss_of_availability: u8,
    pub loss_of_accountability: u8,
    // Business impact
    pub financial_damage: u8,
    pub reputation_damage: u8,
    pub non_compliance: u8,
    pub privacy_violation: u8,
}

impl Factors {
    fn likelihood(&self) -> f32 {
        f32::from(
            self.skill
                + self.motive
                + self.opportunity
                + self.size
                + self.ease_of_discovery
                + self.ease_of_exploit
                + self.awareness
                + self.intrusion_detection,
        ) / 8.0
    }
    fn technical_impact(&self) -> f32 {
        f32::from(
            self.loss_of_confidentiality
                + self.loss_of_integrity
                + self.loss_of_availability
                + self.loss_of_accountability,
        ) / 4.0
    }
    fn business_impact(&self) -> f32 {
        f32::from(
            self.financial_damage
                + self.reputation_damage
                + self.non_compliance
                + self.privacy_violation,
        ) / 4.0
    }
    /// Overall impact — the higher of technical (asset-CIA driven, always present)
    /// and business (org-configured); business escalates but never dilutes.
    fn impact(&self) -> f32 {
        self.technical_impact().max(self.business_impact())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Band {
    Low,
    Medium,
    High,
}

fn band(v: f32) -> Band {
    if v < 3.0 {
        Band::Low
    } else if v < 6.0 {
        Band::Medium
    } else {
        Band::High
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Note,
    Low,
    Medium,
    High,
    Critical,
}

/// The OWASP overall-risk matrix (likelihood × impact).
fn matrix(l: Band, i: Band) -> RiskLevel {
    use Band::{High, Low, Medium};
    use RiskLevel as R;
    match (l, i) {
        (Low, Low) => R::Note,
        (Medium, Low) | (Low, Medium) => R::Low,
        (High, Low) | (Medium, Medium) | (Low, High) => R::Medium,
        (High, Medium) | (Medium, High) => R::High,
        (High, High) => R::Critical,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Risk {
    pub likelihood: f32,
    pub impact: f32,
    pub likelihood_band: Band,
    pub impact_band: Band,
    pub level: RiskLevel,
    pub factors: Factors,
}

impl Risk {
    fn of(f: Factors) -> Self {
        let (l, i) = (f.likelihood(), f.impact());
        Risk {
            likelihood: (l * 10.0).round() / 10.0,
            impact: (i * 10.0).round() / 10.0,
            likelihood_band: band(l),
            impact_band: band(i),
            level: matrix(band(l), band(i)),
            factors: f,
        }
    }
}

/// Org-wide factor defaults and business-impact weights. Loaded from
/// `.threatmodel/risk.yaml`; anything unset falls back to the OTM-derived seed.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskConfig {
    pub skill: Option<u8>,
    pub motive: Option<u8>,
    pub size: Option<u8>,
    pub financial_damage: Option<u8>,
    pub reputation_damage: Option<u8>,
    pub non_compliance: Option<u8>,
    pub privacy_violation: Option<u8>,
}

/// Parse a `.threatmodel/risk.yaml` org config.
pub fn config_from_yaml(yaml: &str) -> Result<RiskConfig, serde_yaml_ng::Error> {
    serde_yaml_ng::from_str(yaml)
}

/// Score every finding and attach its [`Risk`].
pub fn annotate(findings: &mut [Finding], otm: &Otm, cfg: &RiskConfig) {
    for f in findings.iter_mut() {
        f.risk = Some(score(f, otm, cfg));
    }
}

pub fn score(f: &Finding, otm: &Otm, cfg: &RiskConfig) -> Risk {
    let mut fac = seed(f, otm);
    // Org defaults for the factors the graph can't infer.
    if let Some(v) = cfg.skill {
        fac.skill = v;
    }
    if let Some(v) = cfg.motive {
        fac.motive = v;
    }
    if let Some(v) = cfg.size {
        fac.size = v;
    }
    if let Some(v) = cfg.financial_damage {
        fac.financial_damage = v;
    }
    if let Some(v) = cfg.reputation_damage {
        fac.reputation_damage = v;
    }
    if let Some(v) = cfg.non_compliance {
        fac.non_compliance = v;
    }
    if let Some(v) = cfg.privacy_violation {
        fac.privacy_violation = v;
    }
    // Per-element `risk.<factor>=N` attributes win last.
    element_overrides(&mut fac, otm, &f.element_id);
    Risk::of(fac)
}

/// Seed factors from the OTM graph + the finding.
fn seed(f: &Finding, otm: &Otm) -> Factors {
    let (c, i, a) = element_cia(otm, &f.element_id);
    let exposed = element_exposed(otm, &f.element_id);
    let logged = element_logged(otm, &f.element_id);
    Factors {
        // Org knowledge (overridable): "advanced computer user", possible reward.
        skill: 5,
        motive: 5,
        // Exposure drives who can reach it and how easily.
        opportunity: if exposed { 8 } else { 4 },
        size: if exposed { 9 } else { 5 }, // anonymous internet vs internal users
        ease_of_discovery: if exposed { 8 } else { 4 },
        ease_of_exploit: if exposed { 6 } else { 3 },
        awareness: 7, // wyrm rules are well-known threat classes
        // OWASP: higher = less detection. Logged+reviewed ≈ 3, not logged ≈ 8.
        intrusion_detection: if logged { 3 } else { 8 },
        // Technical impact straight from asset CIA.
        loss_of_confidentiality: scale(c),
        loss_of_integrity: scale(i),
        loss_of_availability: scale(a),
        loss_of_accountability: if logged { 2 } else { 7 },
        // Business impact defaults low unless the org configures it — privacy
        // tracks confidentiality of the data at stake.
        financial_damage: 3,
        reputation_damage: 3,
        non_compliance: 3,
        privacy_violation: if c >= 70 { 7 } else { 3 },
    }
}

fn scale(cia_0_100: u8) -> u8 {
    (u16::from(cia_0_100) * 9 / 100) as u8
}

/// Max C/I/A (0–100) across the assets an element touches.
fn element_cia(otm: &Otm, element_id: &str) -> (u8, u8, u8) {
    let asset_ids: Vec<&str> = if let Some(c) = otm.component(element_id) {
        c.assets.all().map(String::as_str).collect()
    } else if let Some(d) = otm.dataflows.iter().find(|d| d.id == element_id) {
        d.assets.iter().map(String::as_str).collect()
    } else {
        Vec::new()
    };
    asset_ids.iter().fold((0, 0, 0), |(c, i, a), id| {
        match otm.asset(id).and_then(|x| x.risk.as_ref()) {
            Some(r) => (
                c.max(r.confidentiality),
                i.max(r.integrity),
                a.max(r.availability),
            ),
            None => (c, i, a),
        }
    })
}

/// Lowest trust rating the element sits in / touches (a component's zone, or the
/// min of a flow's two endpoints). <= 30 counts as internet/low-trust exposure.
fn element_exposed(otm: &Otm, element_id: &str) -> bool {
    let rating = |zone: Option<&str>| {
        zone.and_then(|z| otm.trust_zones.iter().find(|t| t.id == z))
            .and_then(|z| z.risk.as_ref())
            .and_then(|r| r.trust_rating)
    };
    if otm.component(element_id).is_some() {
        rating(otm.trust_zone_of(element_id)).is_some_and(|r| r <= 30)
    } else if let Some(d) = otm.dataflows.iter().find(|d| d.id == element_id) {
        let lo = rating(otm.trust_zone_of(&d.source))
            .into_iter()
            .chain(rating(otm.trust_zone_of(&d.destination)))
            .min();
        lo.is_some_and(|r| r <= 30)
    } else {
        false
    }
}

const LOG_ALIASES: &[&str] = &["logging", "audit", "log-sink", "flow-log"];

fn element_logged(otm: &Otm, element_id: &str) -> bool {
    let tag_hit = |s: &str| {
        let s = s.to_lowercase();
        LOG_ALIASES.iter().any(|a| s.contains(a))
    };
    let attrs_hit = otm
        .component(element_id)
        .map(|c| c.attributes.keys().any(|k| tag_hit(k)))
        .or_else(|| {
            otm.dataflows.iter().find(|d| d.id == element_id).map(|d| {
                d.tags.iter().any(|t| tag_hit(t)) || d.attributes.keys().any(|k| tag_hit(k))
            })
        })
        .unwrap_or(false);
    let mit_hit = otm.mitigations.iter().any(|m| {
        m.applies_to.iter().any(|t| t == element_id) && (tag_hit(&m.id) || tag_hit(&m.name))
    });
    attrs_hit || mit_hit
}

/// Apply `risk.<factor>=N` attributes on the element (0–9, clamped).
fn element_overrides(f: &mut Factors, otm: &Otm, element_id: &str) {
    let attrs = if let Some(c) = otm.component(element_id) {
        Some(&c.attributes)
    } else {
        otm.dataflows
            .iter()
            .find(|d| d.id == element_id)
            .map(|d| &d.attributes)
    };
    let Some(attrs) = attrs else { return };
    for (k, v) in attrs {
        let Some(name) = k.strip_prefix("risk.") else {
            continue;
        };
        let Ok(n) = v.trim().parse::<u8>() else {
            continue;
        };
        let n = n.min(9);
        match name {
            "skill" => f.skill = n,
            "motive" => f.motive = n,
            "opportunity" => f.opportunity = n,
            "size" => f.size = n,
            "easeOfDiscovery" => f.ease_of_discovery = n,
            "easeOfExploit" => f.ease_of_exploit = n,
            "awareness" => f.awareness = n,
            "intrusionDetection" => f.intrusion_detection = n,
            "financialDamage" => f.financial_damage = n,
            "reputationDamage" => f.reputation_damage = n,
            "nonCompliance" => f.non_compliance = n,
            "privacyViolation" => f.privacy_violation = n,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposed_sensitive_finding_scores_higher_than_internal() {
        let otm = crate::parse(
            "otmVersion: 0.2.0\nproject: { id: p, name: P }\ntrustZones:\n  - { id: edge, name: Edge, risk: { trustRating: 10 } }\n  - { id: intr, name: Internal, risk: { trustRating: 80 } }\nassets:\n  - { id: pii, name: PII, risk: { confidentiality: 90, integrity: 40 } }\ncomponents:\n  - { id: api, name: api, type: web-service, parent: { trustZone: edge }, assets: { processed: [pii] } }\n",
        )
        .unwrap();
        let mut findings = crate::ThreatLibrary::bundled().analyze(&otm);
        annotate(&mut findings, &otm, &RiskConfig::default());
        let f = findings.iter().find(|f| f.element_id == "api").unwrap();
        let r = f.risk.as_ref().unwrap();
        // Exposed + high-confidentiality data → High likelihood, High impact.
        assert_eq!(r.likelihood_band, Band::High);
        assert!(matches!(r.level, RiskLevel::High | RiskLevel::Critical));
    }

    #[test]
    fn config_and_attribute_overrides_apply() {
        let otm = crate::parse(
            "otmVersion: 0.2.0\nproject: { id: p, name: P }\ntrustZones:\n  - { id: edge, name: Edge, risk: { trustRating: 10 } }\n  - { id: intr, name: Internal, risk: { trustRating: 80 } }\nassets:\n  - { id: pii, name: PII, risk: { confidentiality: 90 } }\ncomponents:\n  - { id: api, name: api, type: web-service, parent: { trustZone: edge }, assets: { processed: [pii] }, attributes: { \"risk.skill\": \"9\" } }\n",
        )
        .unwrap();
        let f = crate::ThreatLibrary::bundled().analyze(&otm);
        let api = f.iter().find(|x| x.element_id == "api").unwrap();
        let cfg = RiskConfig {
            motive: Some(9),
            ..Default::default()
        };
        let r = score(api, &otm, &cfg);
        assert_eq!(r.factors.skill, 9); // from the attribute
        assert_eq!(r.factors.motive, 9); // from the config
    }
}
