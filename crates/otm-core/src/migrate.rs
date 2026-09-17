//! Migrate other threat-model formats into OTM.
//!
//! - [`from_threagile`] parses a Threagile model YAML.
//! - [`from_pytm`] parses pytm's `--json` model export.
//!
//! Both map onto the same OTM shape: trust boundaries → trust zones, technical
//! assets/elements → components, data assets → assets, communication links/flows →
//! dataflows. Ordinal CIA ratings are projected onto OTM's 0–100 scale.

use crate::model::{
    Asset, AssetRisk, Component, ComponentAssets, Dataflow, Otm, Parent, Project, TrustRisk,
    TrustZone,
};
use serde::Deserialize;
use std::collections::BTreeMap;

fn sanitize_id(s: &str) -> String {
    let id: String = s
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    if id.is_empty() {
        "unnamed".to_string()
    } else {
        id
    }
}

// ---------------------------------------------------------------------------
// Threagile
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Threagile {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    data_assets: BTreeMap<String, TgDataAsset>,
    #[serde(default)]
    technical_assets: BTreeMap<String, TgTechAsset>,
    #[serde(default)]
    trust_boundaries: BTreeMap<String, TgBoundary>,
}

#[derive(Deserialize)]
struct TgDataAsset {
    id: String,
    #[serde(default)]
    confidentiality: Option<String>,
    #[serde(default)]
    integrity: Option<String>,
    #[serde(default)]
    availability: Option<String>,
}

#[derive(Deserialize)]
struct TgTechAsset {
    id: String,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    technology: Option<String>,
    #[serde(default)]
    data_assets_processed: Vec<String>,
    #[serde(default)]
    data_assets_stored: Vec<String>,
    #[serde(default)]
    communication_links: BTreeMap<String, TgCommLink>,
}

#[derive(Deserialize)]
struct TgCommLink {
    target: String,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    vpn: bool,
    #[serde(default)]
    data_assets_sent: Vec<String>,
    #[serde(default)]
    data_assets_received: Vec<String>,
}

#[derive(Deserialize)]
struct TgBoundary {
    id: String,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    technical_assets_inside: Vec<String>,
}

/// Convert a Threagile model YAML to OTM.
pub fn from_threagile(yaml: &str) -> Result<Otm, crate::Error> {
    let tg: Threagile = serde_yaml_ng::from_str(yaml)?;

    let assets = tg
        .data_assets
        .iter()
        .map(|(name, d)| Asset {
            id: d.id.clone(),
            name: name.clone(),
            risk: Some(AssetRisk {
                confidentiality: tg_conf(d.confidentiality.as_deref()),
                integrity: tg_iea(d.integrity.as_deref()),
                availability: tg_iea(d.availability.as_deref()),
            }),
        })
        .collect();

    let trust_zones: Vec<TrustZone> = tg
        .trust_boundaries
        .iter()
        .map(|(name, b)| TrustZone {
            id: b.id.clone(),
            name: name.clone(),
            risk: Some(TrustRisk {
                trust_rating: Some(tg_boundary_trust(b.kind.as_deref())),
            }),
        })
        .collect();

    // Reverse index: technical-asset id → containing boundary id.
    let mut zone_of: BTreeMap<&str, &str> = BTreeMap::new();
    for b in tg.trust_boundaries.values() {
        for asset_id in &b.technical_assets_inside {
            zone_of.insert(asset_id, &b.id);
        }
    }

    let mut components = Vec::new();
    let mut dataflows = Vec::new();
    for (name, a) in &tg.technical_assets {
        let mut stored = a.data_assets_stored.clone();
        let processed = a.data_assets_processed.clone();
        stored.retain(|_| true);
        components.push(Component {
            id: a.id.clone(),
            name: name.clone(),
            kind: tg_component_type(a.kind.as_deref(), a.technology.as_deref()).to_string(),
            parent: zone_of.get(a.id.as_str()).map(|z| Parent {
                trust_zone: Some(z.to_string()),
                component: None,
            }),
            assets: ComponentAssets { processed, stored },
            attributes: Default::default(),
        });

        for (link_name, link) in &a.communication_links {
            let mut carried = link.data_assets_sent.clone();
            carried.extend(link.data_assets_received.iter().cloned());
            carried.sort();
            carried.dedup();
            let tags = if tg_encrypted(link.protocol.as_deref(), link.vpn) {
                vec!["tls".to_string()]
            } else {
                Vec::new()
            };
            dataflows.push(Dataflow {
                id: sanitize_id(&format!("{}-{}", a.id, link.target)),
                name: link_name.clone(),
                source: a.id.clone(),
                destination: link.target.clone(),
                assets: carried,
                attributes: Default::default(),
                tags,
            });
        }
    }

    components.sort_by(|a, b| a.id.cmp(&b.id));
    dataflows.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(Otm {
        otm_version: "0.2.0".to_string(),
        project: project("threagile", tg.title.as_deref()),
        trust_zones,
        components,
        dataflows,
        assets,
        threats: Vec::new(),
        mitigations: Vec::new(),
    })
}

fn tg_conf(level: Option<&str>) -> u8 {
    match level.unwrap_or("") {
        "public" => 0,
        "internal" => 25,
        "restricted" => 50,
        "confidential" => 75,
        "strictly-confidential" => 100,
        _ => 0,
    }
}

fn tg_iea(level: Option<&str>) -> u8 {
    match level.unwrap_or("") {
        "archive" => 0,
        "operational" => 25,
        "important" => 50,
        "critical" => 75,
        "mission-critical" => 100,
        _ => 0,
    }
}

fn tg_boundary_trust(kind: Option<&str>) -> u8 {
    match kind.unwrap_or("") {
        "network-on-prem" | "network-dedicated-hoster" => 100,
        "network-policy-namespace-isolation" | "execution-environment" => 80,
        "network-cloud-security-group" | "network-virtual-lan" => 60,
        "network-cloud-provider" => 40,
        _ => 50,
    }
}

fn tg_component_type(kind: Option<&str>, technology: Option<&str>) -> &'static str {
    let tech = technology.unwrap_or("");
    match kind.unwrap_or("process") {
        "external-entity" => "external-entity",
        "datastore" => {
            if ["database", "sql", "nosql", "relational-database-tables"]
                .iter()
                .any(|t| tech.contains(t))
            {
                "database"
            } else {
                "data-store"
            }
        }
        _ => {
            if [
                "web-service",
                "web-server",
                "service-registry",
                "api-gateway",
                "load-balancer",
            ]
            .iter()
            .any(|t| tech.contains(t))
            {
                "web-service"
            } else {
                "process"
            }
        }
    }
}

fn tg_encrypted(protocol: Option<&str>, vpn: bool) -> bool {
    const ENCRYPTED: &[&str] = &[
        "https",
        "wss",
        "ssh",
        "ldaps",
        "smb-encrypted",
        "jdbc-encrypted",
        "binary-encrypted",
    ];
    vpn || protocol.is_some_and(|p| ENCRYPTED.contains(&p))
}

// ---------------------------------------------------------------------------
// pytm (--json model export)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Pytm {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    boundaries: Vec<PyNamed>,
    #[serde(default)]
    data: Vec<PyData>,
    #[serde(default)]
    elements: Vec<PyElement>,
    #[serde(default)]
    flows: Vec<PyFlow>,
}

#[derive(Deserialize)]
struct PyNamed {
    name: String,
}

#[derive(Deserialize)]
struct PyData {
    name: String,
    #[serde(default)]
    classification: Option<String>,
}

#[derive(Deserialize)]
struct PyElement {
    name: String,
    #[serde(default, rename = "__class__")]
    class: Option<String>,
    #[serde(default, rename = "inBoundary")]
    in_boundary: Option<String>,
}

#[derive(Deserialize)]
struct PyFlow {
    name: String,
    source: String,
    sink: String,
    #[serde(default)]
    data: Vec<String>,
    #[serde(default, rename = "isEncrypted")]
    is_encrypted: bool,
}

/// Convert a pytm `--json` model export to OTM.
pub fn from_pytm(json: &str) -> Result<Otm, crate::Error> {
    let py: Pytm = serde_json::from_str(json)?;

    let assets = py
        .data
        .iter()
        .map(|d| Asset {
            id: sanitize_id(&d.name),
            name: d.name.clone(),
            risk: Some(AssetRisk {
                confidentiality: py_classification(d.classification.as_deref()),
                integrity: 0,
                availability: 0,
            }),
        })
        .collect();

    let trust_zones = py
        .boundaries
        .iter()
        .map(|b| TrustZone {
            id: sanitize_id(&b.name),
            name: b.name.clone(),
            risk: None,
        })
        .collect();

    let components = py
        .elements
        .iter()
        .map(|e| Component {
            id: sanitize_id(&e.name),
            name: e.name.clone(),
            kind: py_component_type(e.class.as_deref()).to_string(),
            parent: e.in_boundary.as_ref().map(|b| Parent {
                trust_zone: Some(sanitize_id(b)),
                component: None,
            }),
            assets: Default::default(),
            attributes: Default::default(),
        })
        .collect();

    let mut dataflows: Vec<Dataflow> = py
        .flows
        .iter()
        .map(|f| Dataflow {
            id: sanitize_id(&format!("{}-{}", f.source, f.sink)),
            name: f.name.clone(),
            source: sanitize_id(&f.source),
            destination: sanitize_id(&f.sink),
            assets: f.data.iter().map(|d| sanitize_id(d)).collect(),
            attributes: Default::default(),
            tags: if f.is_encrypted {
                vec!["tls".to_string()]
            } else {
                Vec::new()
            },
        })
        .collect();
    dataflows.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(Otm {
        otm_version: "0.2.0".to_string(),
        project: project("pytm", py.name.as_deref()),
        trust_zones,
        components,
        dataflows,
        assets,
        threats: Vec::new(),
        mitigations: Vec::new(),
    })
}

fn py_classification(level: Option<&str>) -> u8 {
    match level.unwrap_or("") {
        "PUBLIC" => 0,
        "RESTRICTED" => 50,
        "SECRET" => 75,
        "TOP_SECRET" => 100,
        _ => 0,
    }
}

fn py_component_type(class: Option<&str>) -> &'static str {
    match class.unwrap_or("") {
        "Actor" | "ExternalEntity" => "external-entity",
        "Datastore" => "database",
        "Server" => "web-service",
        "Lambda" => "process",
        _ => "process",
    }
}

fn project(source: &str, title: Option<&str>) -> Project {
    let name = title.unwrap_or(source).to_string();
    Project {
        id: sanitize_id(&name),
        name,
        owner: None,
        description: Some(format!("Imported from {source} by `wyrm import`.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threagile_maps_to_valid_otm() {
        let yaml = r#"
title: Demo
data_assets:
  Customer Data:
    id: customer-data
    confidentiality: strictly-confidential
    integrity: critical
    availability: operational
technical_assets:
  Web Frontend:
    id: web-frontend
    type: process
    technology: web-service-rest
    data_assets_processed: [customer-data]
    communication_links:
      DB traffic:
        target: db
        protocol: jdbc
        data_assets_sent: [customer-data]
  Database:
    id: db
    type: datastore
    technology: relational-database-tables
    data_assets_stored: [customer-data]
trust_boundaries:
  Cloud:
    id: cloud
    type: network-cloud-provider
    technical_assets_inside: [web-frontend, db]
"#;
        let otm = from_threagile(yaml).unwrap();
        assert!(
            crate::validate::is_valid(&crate::validate(&otm)),
            "{:?}",
            crate::validate(&otm)
        );
        assert_eq!(otm.component("db").unwrap().kind, "database");
        assert_eq!(otm.component("web-frontend").unwrap().kind, "web-service");
        assert_eq!(otm.trust_zone_of("db"), Some("cloud"));
        assert_eq!(
            otm.asset("customer-data")
                .unwrap()
                .risk
                .as_ref()
                .unwrap()
                .confidentiality,
            100
        );
        // jdbc is not encrypted → no tls tag.
        let flow = otm
            .dataflows
            .iter()
            .find(|d| d.source == "web-frontend")
            .unwrap();
        assert!(!flow.tags.iter().any(|t| t == "tls"));
        assert_eq!(
            otm.trust_zones[0].risk.as_ref().unwrap().trust_rating,
            Some(40)
        );
    }

    #[test]
    fn pytm_json_maps_to_valid_otm() {
        let json = r#"{
          "name": "Demo",
          "boundaries": [{ "name": "Internet" }, { "name": "AWS" }],
          "data": [{ "name": "creds", "classification": "SECRET" }],
          "elements": [
            { "name": "User", "__class__": "Actor", "inBoundary": "Internet" },
            { "name": "Web", "__class__": "Server", "inBoundary": "AWS" },
            { "name": "DB", "__class__": "Datastore", "inBoundary": "AWS" }
          ],
          "flows": [
            { "name": "login", "source": "User", "sink": "Web", "data": ["creds"], "isEncrypted": true }
          ]
        }"#;
        let otm = from_pytm(json).unwrap();
        assert!(
            crate::validate::is_valid(&crate::validate(&otm)),
            "{:?}",
            crate::validate(&otm)
        );
        assert_eq!(otm.component("user").unwrap().kind, "external-entity");
        assert_eq!(otm.component("db").unwrap().kind, "database");
        assert_eq!(otm.trust_zone_of("web"), Some("aws"));
        let flow = &otm.dataflows[0];
        assert!(flow.tags.iter().any(|t| t == "tls"));
        assert_eq!(
            otm.asset("creds")
                .unwrap()
                .risk
                .as_ref()
                .unwrap()
                .confidentiality,
            75
        );
    }
}
