//! SARIF 2.1.0 export of findings — the standard static-analysis format that
//! GitHub code scanning (and most SAST tooling) ingests. Shared by the CLI and GUI.

use crate::rules::{Finding, Rule, Severity, Stride};
use serde_json::{Value, json};

/// A finding plus where it lives, for a SARIF `physicalLocation`.
pub struct Located<'a> {
    pub finding: &'a Finding,
    pub uri: String,
    pub line: u32,
}

/// Build a SARIF 2.1.0 document from located findings and the rule catalogue.
/// Only rules referenced by a finding are emitted in the tool driver.
pub fn to_sarif(items: &[Located], rules: &[Rule]) -> String {
    let used: std::collections::BTreeSet<&str> =
        items.iter().map(|i| i.finding.rule_id.as_str()).collect();

    let rule_objs: Vec<Value> = rules
        .iter()
        .filter(|r| used.contains(r.id.as_str()))
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "shortDescription": { "text": r.name },
                "fullDescription": { "text": r.description.trim() },
                "helpUri": format!("https://1ardotno.github.io/wyrm/rules.html#{}", r.id),
                "defaultConfiguration": { "level": level(r.severity) },
                "properties": {
                    "tags": [format!("stride/{}", stride(r.stride))],
                    "security-severity": security_severity(r.severity),
                },
            })
        })
        .collect();

    let results: Vec<Value> = items
        .iter()
        .map(|it| {
            let f = it.finding;
            json!({
                "ruleId": f.rule_id,
                "level": level(f.severity),
                "message": { "text": format!("{} — {}\n↳ {}", f.title, f.element_name, f.mitigation) },
                "locations": [{ "physicalLocation": {
                    "artifactLocation": { "uri": it.uri },
                    "region": { "startLine": it.line.max(1) },
                }}],
                "properties": {
                    "element": f.element_name,
                    "stride": stride(f.stride),
                    "severity": sev(f.severity),
                },
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "wyrm",
                "informationUri": "https://github.com/1ARdotNO/wyrm",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rule_objs,
            }},
            "results": results,
        }],
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

/// Findings as a portable YAML list, for further processing off-tool.
pub fn findings_yaml(findings: &[Finding]) -> String {
    serde_yaml_ng::to_string(findings).unwrap_or_default()
}

/// The 1-based line of an element's declaration in an OTM source, best-effort.
pub fn locate_line(source: &str, element_id: &str) -> u32 {
    let needle = format!("id: {element_id}");
    source
        .lines()
        .position(|l| {
            l.contains(&needle) || l.trim_start().starts_with(&format!("- id: {element_id}"))
        })
        .map(|i| i as u32 + 1)
        .unwrap_or(1)
}

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// GitHub reads `security-severity` (0–10) to bucket alerts.
fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.0",
        Severity::High => "7.0",
        Severity::Medium => "4.0",
        Severity::Low => "1.0",
    }
}

fn sev(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

fn stride(s: Stride) -> &'static str {
    match s {
        Stride::Spoofing => "Spoofing",
        Stride::Tampering => "Tampering",
        Stride::Repudiation => "Repudiation",
        Stride::InformationDisclosure => "InformationDisclosure",
        Stride::DenialOfService => "DenialOfService",
        Stride::ElevationOfPrivilege => "ElevationOfPrivilege",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sarif_has_rules_and_results() {
        let otm = crate::parse(
            "otmVersion: 0.2.0\nproject: { id: p, name: P }\ntrustZones:\n  - { id: edge, name: Edge, risk: { trustRating: 10 } }\n  - { id: intr, name: Internal, risk: { trustRating: 80 } }\nassets:\n  - { id: pii, name: PII, risk: { confidentiality: 90 } }\ncomponents:\n  - { id: api, name: api, type: web-service, parent: { trustZone: edge }, assets: { processed: [pii] } }\n",
        )
        .unwrap();
        let findings = crate::ThreatLibrary::bundled().analyze(&otm);
        assert!(!findings.is_empty());
        let items: Vec<Located> = findings
            .iter()
            .map(|f| Located {
                finding: f,
                uri: "m.otm.yaml".into(),
                line: 1,
            })
            .collect();
        let sarif = to_sarif(&items, &crate::ThreatLibrary::bundled().rules);
        let v: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(
            v["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len()
                >= 1
        );
        assert!(v["runs"][0]["results"].as_array().unwrap().len() >= 1);
    }
}
