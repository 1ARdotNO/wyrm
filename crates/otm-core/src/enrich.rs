//! Enrich a generated model with human-supplied context.
//!
//! `wyrm init` infers topology; the risk-bearing context (asset sensitivity,
//! internal dataflows, IAM provisioning, controls) comes from an annotation file
//! keyed by resource address — see `docs/ANNOTATIONS.md`.

use crate::model::{Asset, Dataflow, Mitigation, Otm, Parent};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Default)]
struct DataFile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    assets: Vec<Asset>,
    /// Fully-specified controls (with `appliesTo`/`riskReduction`/`addresses`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mitigations: Vec<Mitigation>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    resources: BTreeMap<String, ResourceData>,
}

#[derive(Serialize, Deserialize, Default)]
struct ResourceData {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    zone: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    assets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    stored: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mitigations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    flows: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provisioning: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

/// Apply Trivy-style inline `# wyrm: key=value …` comments found in IaC source
/// text (Terraform), keyed to the resource/module they precede. Reuses [`enrich`]
/// so inline and external annotations share one code path and schema.
pub fn enrich_inline(otm: &mut Otm, text: &str) -> Result<(), crate::Error> {
    let resources = inline_annotations(text);
    if resources.is_empty() {
        return Ok(());
    }
    let data = DataFile {
        resources,
        ..Default::default()
    };
    let yaml = serde_yaml_ng::to_string(&data)?;
    enrich(otm, &yaml)
}

/// Scan IaC text for `# wyrm:` comment blocks and key them to the resource or
/// module they sit above (`type.name` / `module.name`).
fn inline_annotations(text: &str) -> BTreeMap<String, ResourceData> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: BTreeMap<String, ResourceData> = BTreeMap::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(key) = resource_key(line) else {
            continue;
        };
        let mut acc = ResourceData::default();
        let mut found = false;
        // Walk up the contiguous comment block above this resource.
        for j in (0..i).rev() {
            let prev = lines[j].trim();
            let Some(body) = prev.strip_prefix('#').or_else(|| prev.strip_prefix("//")) else {
                break; // a non-comment line ends the block
            };
            if let Some(rd) = parse_wyrm(body) {
                merge_rd(&mut acc, rd);
                found = true;
            }
        }
        if found {
            out.insert(key, acc);
        }
    }
    out
}

/// Parse one `wyrm: k=v k2=a,b` comment body into a [`ResourceData`].
fn parse_wyrm(comment: &str) -> Option<ResourceData> {
    let rest = comment.trim().strip_prefix("wyrm:")?.trim();
    let mut rd = ResourceData::default();
    for tok in rest.split_whitespace() {
        let Some((k, v)) = tok.split_once('=') else {
            continue;
        };
        let list = || {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        };
        match k {
            "assets" => rd.assets = list(),
            "stored" => rd.stored = list(),
            "tags" => rd.tags = list(),
            "flows" => rd.flows = list(),
            "mitigations" => rd.mitigations = list(),
            "type" => rd.kind = Some(v.to_string()),
            "zone" => rd.zone = Some(v.to_string()),
            "provisioning" => rd.provisioning = Some(v.to_string()),
            "privilege" => rd.privilege = Some(v.to_string()),
            _ => {}
        }
    }
    Some(rd)
}

fn merge_rd(a: &mut ResourceData, b: ResourceData) {
    a.assets.extend(b.assets);
    a.stored.extend(b.stored);
    a.tags.extend(b.tags);
    a.flows.extend(b.flows);
    a.mitigations.extend(b.mitigations);
    a.kind = b.kind.or(a.kind.take());
    a.zone = b.zone.or(a.zone.take());
    a.provisioning = b.provisioning.or(a.provisioning.take());
    a.privilege = b.privilege.or(a.privilege.take());
}

/// The `type.name` (or `module.name`) a `resource`/`module` line declares.
fn resource_key(line: &str) -> Option<String> {
    let t = line.trim_start();
    let quoted: Vec<&str> = t.split('"').skip(1).step_by(2).collect();
    if t.starts_with("resource ") && quoted.len() >= 2 {
        Some(format!("{}.{}", quoted[0], quoted[1]))
    } else if t.starts_with("module ") && !quoted.is_empty() {
        Some(format!("module.{}", quoted[0]))
    } else {
        None
    }
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

    #[cfg(feature = "terraform")]
    #[test]
    fn inline_comments_annotate_the_component() {
        // A Trivy-style annotation above a resource, keyed to `type.name`.
        let tf = r#"
# wyrm: assets=pii tags=tls
resource "google_storage_bucket" "data" {
}
"#;
        let mut otm = crate::generate::from_terraform(tf, "demo").unwrap();
        enrich_inline(&mut otm, tf).unwrap();
        let bucket = otm
            .components
            .iter()
            .find(|c| c.name == "google_storage_bucket.data")
            .expect("bucket component");
        assert!(bucket.assets.processed.contains(&"pii".to_string()));
        assert!(bucket.attributes.contains_key("tls"));
    }

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
