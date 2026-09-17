//! Render an OTM model as a Mermaid flowchart.
//!
//! Mermaid is the pragmatic diagram target: Zed and Obsidian both render it
//! natively, so `wyrm diagram` produces a picture with zero drawing surface of
//! its own. Trust zones become subgraphs; dataflows become edges.

use crate::model::Otm;
use std::fmt::Write as _;

/// Produce a `flowchart LR` describing the model. Deterministic: same input,
/// same bytes out (important for diffs and snapshot tests).
pub fn render(otm: &Otm) -> String {
    let mut s = String::from("flowchart LR\n");

    // Components grouped by trust zone; ungrouped ones go in a synthetic bucket.
    for tz in &otm.trust_zones {
        let _ = writeln!(
            s,
            "  subgraph {}[\"{}\"]",
            sanitize(&tz.id),
            escape(&tz.name)
        );
        for c in otm.components.iter().filter(|c| in_zone(c, &tz.id)) {
            let _ = writeln!(s, "    {}[\"{}\"]", sanitize(&c.id), escape(&c.name));
        }
        s.push_str("  end\n");
    }
    for c in otm.components.iter().filter(|c| c.parent.is_none()) {
        let _ = writeln!(s, "  {}[\"{}\"]", sanitize(&c.id), escape(&c.name));
    }

    for df in &otm.dataflows {
        let _ = writeln!(
            s,
            "  {} -->|\"{}\"| {}",
            sanitize(&df.source),
            escape(&df.name),
            sanitize(&df.destination)
        );
    }

    s
}

fn in_zone(c: &crate::model::Component, tz_id: &str) -> bool {
    c.parent.as_ref().and_then(|p| p.trust_zone.as_deref()) == Some(tz_id)
}

/// Node ids must be Mermaid-safe identifiers.
fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Escape a label for a Mermaid quoted string.
fn escape(label: &str) -> String {
    label.replace('"', "&quot;")
}
