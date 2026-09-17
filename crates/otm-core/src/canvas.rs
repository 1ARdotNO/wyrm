//! Convert between [JSON Canvas](https://jsoncanvas.org) and OTM.
//!
//! This is the bridge for visual authoring (e.g. an Obsidian canvas): group nodes
//! are trust zones, text/file nodes are components (placed in the zone whose box
//! contains them), and edges are dataflows. [`to_otm`] reads a canvas; [`from_otm`]
//! lays an OTM model out as a canvas.

use crate::model::{Component, Dataflow, Otm, Parent, Project, TrustZone};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Default)]
struct Canvas {
    #[serde(default)]
    nodes: Vec<Node>,
    #[serde(default)]
    edges: Vec<Edge>,
}

#[derive(Serialize, Deserialize)]
struct Node {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    x: i64,
    y: i64,
    width: i64,
    height: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    color: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Edge {
    id: String,
    #[serde(rename = "fromNode")]
    from_node: String,
    #[serde(rename = "toNode")]
    to_node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

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

/// Parse a JSON Canvas document into an OTM model.
pub fn to_otm(json: &str) -> Result<Otm, crate::Error> {
    let canvas: Canvas = serde_json::from_str(json)?;

    // Map every canvas node id → its OTM id (derived from the node's label/text).
    let mut otm_id: BTreeMap<&str, String> = BTreeMap::new();
    let mut zones = Vec::new();
    let mut group_boxes: Vec<(String, i64, i64, i64, i64)> = Vec::new();

    for n in &canvas.nodes {
        if n.kind == "group" {
            let name = n.label.clone().unwrap_or_else(|| "Zone".to_string());
            let id = sanitize_id(&name);
            otm_id.insert(n.id.as_str(), id.clone());
            group_boxes.push((id.clone(), n.x, n.y, n.width, n.height));
            zones.push(TrustZone {
                id,
                name,
                risk: None,
            });
        }
    }

    let mut components = Vec::new();
    for n in &canvas.nodes {
        if n.kind == "group" {
            continue;
        }
        let name = node_name(n);
        let id = sanitize_id(&name);
        otm_id.insert(n.id.as_str(), id.clone());
        // The zone whose box contains this node's centre.
        let (cx, cy) = (n.x + n.width / 2, n.y + n.height / 2);
        let zone = group_boxes
            .iter()
            .find(|(_, gx, gy, gw, gh)| cx >= *gx && cx <= gx + gw && cy >= *gy && cy <= gy + gh)
            .map(|(zid, ..)| zid.clone());
        components.push(Component {
            id,
            name: name.clone(),
            kind: infer_kind(&name).to_string(),
            parent: zone.map(|z| Parent {
                trust_zone: Some(z),
                component: None,
            }),
            assets: Default::default(),
            attributes: Default::default(),
        });
    }

    let mut dataflows = Vec::new();
    for (i, e) in canvas.edges.iter().enumerate() {
        let (Some(source), Some(destination)) = (
            otm_id.get(e.from_node.as_str()),
            otm_id.get(e.to_node.as_str()),
        ) else {
            continue;
        };
        dataflows.push(Dataflow {
            id: sanitize_id(&format!("df-{source}-{destination}-{i}")),
            name: e
                .label
                .clone()
                .unwrap_or_else(|| format!("{source} → {destination}")),
            source: source.clone(),
            destination: destination.clone(),
            assets: Vec::new(),
            attributes: Default::default(),
            tags: Vec::new(),
        });
    }

    components.sort_by(|a, b| a.id.cmp(&b.id));
    dataflows.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(Otm {
        otm_version: "0.2.0".to_string(),
        project: Project {
            id: "canvas".to_string(),
            name: "Canvas import".to_string(),
            owner: None,
            description: Some("Imported from a JSON Canvas by `wyrm import`.".to_string()),
        },
        trust_zones: zones,
        components,
        dataflows,
        assets: Vec::new(),
        threats: Vec::new(),
        mitigations: Vec::new(),
    })
}

/// Render an OTM model as a JSON Canvas document (one column per trust zone).
pub fn from_otm(otm: &Otm) -> Result<String, crate::Error> {
    const COL_W: i64 = 320;
    const NODE_W: i64 = 240;
    const NODE_H: i64 = 60;
    const ROW_H: i64 = 90;
    const PAD: i64 = 40;

    let mut nodes = Vec::new();
    let mut col_of: BTreeMap<&str, usize> = BTreeMap::new();
    let ungrouped_col = otm.trust_zones.len();

    // Count components per zone to size the group boxes.
    let mut counts = vec![0i64; otm.trust_zones.len() + 1];
    for c in &otm.components {
        let col = c
            .parent
            .as_ref()
            .and_then(|p| p.trust_zone.as_deref())
            .and_then(|tz| otm.trust_zones.iter().position(|z| z.id == tz))
            .unwrap_or(ungrouped_col);
        counts[col] += 1;
    }

    // Group nodes (trust zones).
    for (col, z) in otm.trust_zones.iter().enumerate() {
        col_of.insert(z.id.as_str(), col);
        let height = PAD * 2 + counts[col].max(1) * ROW_H;
        nodes.push(Node {
            id: z.id.clone(),
            kind: "group".to_string(),
            x: col as i64 * COL_W,
            y: 0,
            width: COL_W - PAD,
            height,
            text: None,
            label: Some(z.name.clone()),
            file: None,
            color: None,
        });
    }

    // Component nodes, stacked within their zone's column.
    let mut placed = vec![0i64; otm.trust_zones.len() + 1];
    for c in &otm.components {
        let col = c
            .parent
            .as_ref()
            .and_then(|p| p.trust_zone.as_deref())
            .and_then(|tz| col_of.get(tz).copied())
            .unwrap_or(ungrouped_col);
        let row = placed[col];
        placed[col] += 1;
        nodes.push(Node {
            id: c.id.clone(),
            kind: "text".to_string(),
            x: col as i64 * COL_W + PAD / 2,
            y: PAD + row * ROW_H,
            width: NODE_W,
            height: NODE_H,
            text: Some(format!("{}\n({})", c.name, c.kind)),
            label: None,
            file: None,
            color: None,
        });
    }

    let edges = otm
        .dataflows
        .iter()
        .map(|d| Edge {
            id: d.id.clone(),
            from_node: d.source.clone(),
            to_node: d.destination.clone(),
            label: Some(d.name.clone()),
        })
        .collect();

    let canvas = Canvas { nodes, edges };
    serde_json::to_string_pretty(&canvas).map_err(crate::Error::from)
}

fn node_name(n: &Node) -> String {
    if let Some(t) = &n.text {
        return t.lines().next().unwrap_or(t).trim().to_string();
    }
    if let Some(f) = &n.file {
        return f
            .rsplit('/')
            .next()
            .unwrap_or(f)
            .trim_end_matches(".md")
            .to_string();
    }
    "node".to_string()
}

fn infer_kind(name: &str) -> &'static str {
    let n = name.to_lowercase();
    if ["database", "postgres", "mysql", "mongo", " db", "db "]
        .iter()
        .any(|k| n.contains(k))
    {
        "database"
    } else if ["cache", "redis", "memcache"].iter().any(|k| n.contains(k)) {
        "data-store"
    } else if ["queue", "kafka", "rabbit"].iter().any(|k| n.contains(k)) {
        "message-queue"
    } else if ["browser", "user", "client", "external"]
        .iter()
        .any(|k| n.contains(k))
    {
        "external-entity"
    } else {
        "process"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canvas_round_trips_through_otm() {
        let canvas = r#"{
          "nodes": [
            { "id": "z1", "type": "group", "label": "Internet", "x": 0, "y": 0, "width": 280, "height": 300 },
            { "id": "z2", "type": "group", "label": "Private", "x": 320, "y": 0, "width": 280, "height": 300 },
            { "id": "n1", "type": "text", "text": "User Browser", "x": 20, "y": 40, "width": 200, "height": 50 },
            { "id": "n2", "type": "text", "text": "API", "x": 340, "y": 40, "width": 200, "height": 50 },
            { "id": "n3", "type": "text", "text": "Orders DB", "x": 340, "y": 140, "width": 200, "height": 50 }
          ],
          "edges": [
            { "id": "e1", "fromNode": "n1", "toNode": "n2", "label": "request" },
            { "id": "e2", "fromNode": "n2", "toNode": "n3", "label": "query" }
          ]
        }"#;

        let otm = to_otm(canvas).unwrap();
        assert!(
            crate::validate::is_valid(&crate::validate(&otm)),
            "{:?}",
            crate::validate(&otm)
        );
        assert_eq!(otm.trust_zones.len(), 2);
        // Node placed by geometry into the right zone.
        assert_eq!(otm.trust_zone_of("user-browser"), Some("internet"));
        assert_eq!(otm.trust_zone_of("api"), Some("private"));
        assert_eq!(otm.component("orders-db").unwrap().kind, "database");
        assert!(
            otm.dataflows
                .iter()
                .any(|d| d.source == "user-browser" && d.destination == "api")
        );

        // OTM → canvas → OTM preserves the graph.
        let back = from_otm(&otm).unwrap();
        let otm2 = to_otm(&back).unwrap();
        assert_eq!(otm2.components.len(), otm.components.len());
        assert_eq!(otm2.dataflows.len(), otm.dataflows.len());
        assert_eq!(otm2.trust_zone_of("api"), Some("private"));
    }
}
