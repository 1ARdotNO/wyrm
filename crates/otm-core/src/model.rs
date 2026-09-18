//! Serde types for the Open Threat Model (OTM) format.
//!
//! Modelled on the OTM 0.2.0 spec (<https://github.com/iriusrisk/OpenThreatModel>).
//! Unknown fields are ignored rather than rejected so that real-world documents
//! carrying tool-specific extensions still parse.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Free-form key/value bag used by OTM `attributes`. Values are kept as strings
/// because OTM permits arbitrary scalars and downstream rules only ever compare.
pub type Attributes = BTreeMap<String, String>;

/// A complete OTM document — the root object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Otm {
    pub otm_version: String,
    pub project: Project,
    #[serde(default)]
    pub trust_zones: Vec<TrustZone>,
    #[serde(default)]
    pub components: Vec<Component>,
    #[serde(default)]
    pub dataflows: Vec<Dataflow>,
    #[serde(default)]
    pub assets: Vec<Asset>,
    #[serde(default)]
    pub threats: Vec<Threat>,
    #[serde(default)]
    pub mitigations: Vec<Mitigation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustZone {
    pub id: String,
    pub name: String,
    /// Higher = more trusted (OTM `risk.trustRating`, 0–100). Absent ⇒ unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<TrustRisk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustRisk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_rating: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    pub id: String,
    pub name: String,
    /// OTM component type, e.g. `web-service`, `database`, `process`, `external-entity`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Placement in the trust hierarchy; drives boundary-crossing analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Parent>,
    #[serde(default, skip_serializing_if = "ComponentAssets::is_empty")]
    pub assets: ComponentAssets,
    #[serde(default, skip_serializing_if = "Attributes::is_empty")]
    pub attributes: Attributes,
}

/// A component's parent is a trust zone (the only variant wyrm's rules use today).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentAssets {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stored: Vec<String>,
}

impl ComponentAssets {
    pub fn is_empty(&self) -> bool {
        self.processed.is_empty() && self.stored.is_empty()
    }
    /// Every asset id touched by this component, stored or processed.
    pub fn all(&self) -> impl Iterator<Item = &String> {
        self.processed.iter().chain(self.stored.iter())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dataflow {
    pub id: String,
    pub name: String,
    pub source: String,
    pub destination: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assets: Vec<String>,
    #[serde(default, skip_serializing_if = "Attributes::is_empty")]
    pub attributes: Attributes,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Asset {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<AssetRisk>,
}

/// CIA ratings, 0–100. Missing dimensions default to 0 (unknown/none).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetRisk {
    #[serde(default)]
    pub confidentiality: u8,
    #[serde(default)]
    pub integrity: u8,
    #[serde(default)]
    pub availability: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Threat {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mitigation {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// How much this control lowers risk on its targets, 0–100. Absent ⇒ 50
    /// (one severity step) once it targets something; 100 resolves the finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_reduction: Option<u8>,
    /// Component/dataflow ids this control protects. Empty ⇒ documentary only,
    /// so an unlinked control never silently suppresses a finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applies_to: Vec<String>,
    /// Rule ids this control neutralizes (e.g. `WYRM-T003`). Empty ⇒ every
    /// finding on the targets — keeps a WAF from muting an encryption finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
}

impl Otm {
    /// Resolve the trust zone a component sits in, if declared.
    /// The trust zone a component sits in. Walks up the `parent.component` chain
    /// (OTM allows a component's parent to be another component) until it finds
    /// one anchored to a zone — so nested/grouped components inherit their
    /// container's zone. Cycle-guarded.
    pub fn trust_zone_of<'a>(&'a self, component_id: &str) -> Option<&'a str> {
        let mut seen = std::collections::HashSet::new();
        let mut cur = component_id;
        loop {
            if !seen.insert(cur) {
                return None; // cycle
            }
            let parent = self
                .components
                .iter()
                .find(|c| c.id == cur)?
                .parent
                .as_ref()?;
            if let Some(tz) = parent.trust_zone.as_deref() {
                return Some(tz);
            }
            cur = parent.component.as_deref()?;
        }
    }

    pub fn component<'a>(&'a self, id: &str) -> Option<&'a Component> {
        self.components.iter().find(|c| c.id == id)
    }

    pub fn asset<'a>(&'a self, id: &str) -> Option<&'a Asset> {
        self.assets.iter().find(|a| a.id == id)
    }
}
