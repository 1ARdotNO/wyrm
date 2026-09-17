//! End-to-end checks over the bundled example model and threat library.

use otm_core::rules::{Severity, Stride};

const EXAMPLE: &str = include_str!("../../../.threatmodel/example.otm.yaml");

fn model() -> otm_core::Otm {
    otm_core::parse(EXAMPLE).expect("example model parses")
}

#[test]
fn example_is_structurally_valid() {
    let diags = otm_core::validate(&model());
    assert!(
        otm_core::validate::is_valid(&diags),
        "unexpected validation errors: {diags:?}"
    );
}

#[test]
fn bundled_library_loads() {
    let lib = otm_core::ThreatLibrary::bundled();
    assert!(!lib.rules.is_empty(), "bundled library should carry rules");
}

#[test]
fn cleartext_credential_flow_is_flagged_critical() {
    let findings = otm_core::ThreatLibrary::bundled().analyze(&model());
    let t001 = findings
        .iter()
        .find(|f| f.rule_id == "WYRM-T001")
        .expect("WYRM-T001 should fire on the cleartext login flow");
    assert_eq!(t001.element_id, "df-login");
    assert_eq!(t001.severity, Severity::Critical);
    assert_eq!(t001.stride, Stride::InformationDisclosure);
}

#[test]
fn encrypted_internal_flow_is_not_flagged_for_encryption() {
    let findings = otm_core::ThreatLibrary::bundled().analyze(&model());
    // df-lookup is tagged `tls` and stays inside no boundary crossing it cares about.
    assert!(
        !findings.iter().any(|f| f.element_id == "df-lookup"
            && matches!(f.rule_id.as_str(), "WYRM-T001" | "WYRM-T002")),
        "encrypted flow must not trip the cleartext/encryption rules"
    );
}

#[test]
fn findings_are_sorted_most_severe_first() {
    let findings = otm_core::ThreatLibrary::bundled().analyze(&model());
    assert!(
        findings.windows(2).all(|w| w[0].severity >= w[1].severity),
        "findings should be ordered by descending severity"
    );
}

#[test]
fn dangling_dataflow_source_is_an_error() {
    let broken = r#"
otmVersion: 0.2.0
project: { id: p, name: P }
components:
  - { id: a, name: A, type: process }
dataflows:
  - { id: f, name: F, source: a, destination: ghost }
"#;
    let otm = otm_core::parse(broken).unwrap();
    let diags = otm_core::validate(&otm);
    assert!(
        diags
            .iter()
            .any(|d| d.code == "dataflow.destination.unknown")
    );
    assert!(!otm_core::validate::is_valid(&diags));
}
