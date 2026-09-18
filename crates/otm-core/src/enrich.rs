//! Enrich a generated model with human-supplied context.
//!
//! `wyrm init` infers topology; the risk-bearing context (asset sensitivity,
//! internal dataflows, IAM provisioning, controls) comes from an annotation file
//! keyed by resource address — see `docs/ANNOTATIONS.md`.

use crate::model::{Asset, Dataflow, Mitigation, Otm, Parent};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize, Default)]
struct DataFile {
    #[serde(default)]
    assets: Vec<Asset>,
    /// Fully-specified controls (with `appliesTo`/`riskReduction`/`addresses`).
    #[serde(default)]
    mitigations: Vec<Mitigation>,
    #[serde(default)]
    resources: BTreeMap<String, ResourceData>,
}

#[derive(Deserialize, Default)]
struct ResourceData {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    zone: Option<String>,
    #[serde(default)]
    assets: Vec<String>,
    #[serde(default)]
    stored: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    mitigations: Vec<String>,
    #[serde(default)]
    flows: Vec<String>,
    #[serde(default)]
    provisioning: Option<String>,
    #[serde(default)]
    privilege: Option<String>,
}

/// Apply a `.threatmodel/data.yaml` document to a generated model.
pub fn enrich(otm: &mut Otm, yaml: &str) -> Result<(), crate::Error> {
    let data: DataFile = serde_yaml_ng::from_str(yaml)?;

    for a in data.assets {
        if !otm.assets.iter().any(|x| x.id == a.id) {
            otm.assets.push(a);
        }
    }

    for m in data.mitigations {
        match otm.mitigations.iter_mut().find(|x| x.id == m.id) {
            Some(existing) => *existing = m,
            None => otm.mitigations.push(m),
        }
    }

    for (key, rd) in &data.resources {
        let Some(cid) = component_id(otm, key) else {
            continue;
        };

        if let Some(c) = otm.components.iter_mut().find(|c| c.id == cid) {
            if let Some(k) = &rd.kind {
                c.kind = k.clone();
            }
            if let Some(z) = &rd.zone {
                c.parent = Some(Parent {
                    trust_zone: Some(z.clone()),
                    component: None,
                });
            }
            for a in &rd.assets {
                if !c.assets.processed.contains(a) {
                    c.assets.processed.push(a.clone());
                }
            }
            for a in &rd.stored {
                if !c.assets.stored.contains(a) {
                    c.assets.stored.push(a.clone());
                }
            }
            for t in &rd.tags {
                c.attributes
                    .entry(t.clone())
                    .or_insert_with(|| "true".to_string());
            }
            if let Some(p) = &rd.provisioning {
                c.attributes.insert("provisioning".to_string(), p.clone());
            }
            if let Some(p) = &rd.privilege {
                c.attributes.insert("privilege".to_string(), p.clone());
            }
        }

        // Internal dataflows the annotation declares.
        for target in &rd.flows {
            if let Some(tid) = component_id(otm, target) {
                let fid = format!("df-{cid}-{tid}");
                if !otm.dataflows.iter().any(|d| d.id == fid) {
                    otm.dataflows.push(Dataflow {
                        id: fid,
                        name: format!("{cid} → {tid}"),
                        source: cid.clone(),
                        destination: tid,
                        assets: rd.assets.clone(),
                        attributes: Default::default(),
                        tags: rd.tags.clone(),
                    });
                }
            }
        }

        // A resource's named controls attach to that component so `analyze`
        // downgrades its findings (default one severity step, per Mitigation docs).
        for m in &rd.mitigations {
            let mid = sanitize(m);
            match otm.mitigations.iter_mut().find(|x| x.id == mid) {
                Some(existing) => {
                    if !existing.applies_to.contains(&cid) {
                        existing.applies_to.push(cid.clone());
                    }
                }
                None => otm.mitigations.push(Mitigation {
                    id: mid,
                    name: m.clone(),
                    applies_to: vec![cid.clone()],
                    ..Default::default()
                }),
            }
        }
    }

    otm.components.sort_by(|a, b| a.id.cmp(&b.id));
    otm.dataflows.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(())
}

/// Resolve an annotation key (resource address, id, or a sanitized form) to a
/// component id.
fn component_id(otm: &Otm, key: &str) -> Option<String> {
    let san = sanitize(key);
    otm.components
        .iter()
        .find(|c| c.name == key || c.id == key || c.id == san)
        .map(|c| c.id.clone())
}

fn sanitize(s: &str) -> String {
    s.trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_file_attaches_sensitivity_and_flows() {
        let mut otm = crate::generate::from_compose(
            "services:\n  api: { image: our/api }\n  db: { image: postgres }\n",
            "demo",
        )
        .unwrap();

        let data = r#"
assets:
  - { id: pii, name: Customer PII, risk: { confidentiality: 100 } }
resources:
  api:
    assets: [pii]
    flows: [db]
  db:
    stored: [pii]
    zone: tz-data
"#;
        enrich(&mut otm, data).unwrap();

        assert!(otm.asset("pii").is_some(), "asset defined");
        assert!(
            otm.component("api")
                .unwrap()
                .assets
                .processed
                .contains(&"pii".to_string())
        );
        assert!(
            otm.dataflows
                .iter()
                .any(|d| d.source == "api" && d.destination == "db")
        );
        assert_eq!(otm.trust_zone_of("db"), Some("tz-data"));
    }
}
