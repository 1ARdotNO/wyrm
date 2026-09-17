//! Turn an OTM document's text into LSP diagnostics.
//!
//! Pure and side-effect-free so it can be unit-tested without a running server.
//! Structural problems ([`otm_core::validate`]) and STRIDE findings
//! ([`otm_core::rules`]) both become squiggles, positioned by locating the
//! offending element's id in the source text.

use lsp_types::{Diagnostic, DiagnosticSeverity, NumberOrString, Position, Range};
use otm_core::rules::Severity as RuleSeverity;
use otm_core::validate::Severity as ValSeverity;

/// Compute all diagnostics for a model's source text.
pub fn compute(text: &str) -> Vec<Diagnostic> {
    let otm = match otm_core::parse(text) {
        Ok(otm) => otm,
        // A parse failure is the only diagnostic worth showing until it's fixed.
        Err(err) => return vec![parse_error(&err)],
    };

    let mut out = Vec::new();

    for d in otm_core::validate(&otm) {
        let severity = match d.severity {
            ValSeverity::Error => DiagnosticSeverity::ERROR,
            ValSeverity::Warning => DiagnosticSeverity::WARNING,
        };
        let range = d
            .element
            .as_deref()
            .map(|id| locate(text, id))
            .unwrap_or_default();
        out.push(diag(range, severity, &d.code, "wyrm", d.message));
    }

    for f in otm_core::ThreatLibrary::bundled().analyze(&otm) {
        let range = locate(text, &f.element_id);
        let message = format!("{} — {}\n↳ {}", f.rule_id, f.title, f.mitigation);
        out.push(diag(
            range,
            stride_severity(f.severity),
            &f.rule_id,
            "wyrm-stride",
            message,
        ));
    }

    out
}

fn diag(
    range: Range,
    severity: DiagnosticSeverity,
    code: &str,
    source: &str,
    message: String,
) -> Diagnostic {
    Diagnostic {
        range,
        severity: Some(severity),
        code: Some(NumberOrString::String(code.to_string())),
        source: Some(source.to_string()),
        message,
        ..Default::default()
    }
}

/// STRIDE severity → editor severity. Critical/High are hard errors; Medium warns;
/// Low is informational.
fn stride_severity(s: RuleSeverity) -> DiagnosticSeverity {
    match s {
        RuleSeverity::Critical | RuleSeverity::High => DiagnosticSeverity::ERROR,
        RuleSeverity::Medium => DiagnosticSeverity::WARNING,
        RuleSeverity::Low => DiagnosticSeverity::INFORMATION,
    }
}

/// Find the first occurrence of `id` in the text and return its range. Falls back
/// to the top of the document when the id can't be located.
///
/// Character offsets are counted in `char`s; for the ASCII ids OTM uses this
/// matches the UTF-16 units LSP expects.
fn locate(text: &str, id: &str) -> Range {
    for (line_no, line) in text.lines().enumerate() {
        if let Some(byte_col) = line.find(id) {
            let start = line[..byte_col].chars().count() as u32;
            let end = start + id.chars().count() as u32;
            let l = line_no as u32;
            return Range::new(Position::new(l, start), Position::new(l, end));
        }
    }
    Range::default()
}

fn parse_error(err: &otm_core::Error) -> Diagnostic {
    let pos = match err {
        otm_core::Error::Yaml(y) => y.location().map(|loc| {
            Position::new(
                loc.line().saturating_sub(1) as u32,
                loc.column().saturating_sub(1) as u32,
            )
        }),
        _ => None,
    }
    .unwrap_or_default();
    diag(
        Range::new(pos, pos),
        DiagnosticSeverity::ERROR,
        "parse",
        "wyrm",
        format!("could not parse threat model: {err}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../.threatmodel/example.otm.yaml");

    #[test]
    fn example_yields_stride_diagnostic_positioned_on_the_flow() {
        let diags = compute(EXAMPLE);
        let t001 = diags
            .iter()
            .find(|d| d.code == Some(NumberOrString::String("WYRM-T001".into())))
            .expect("WYRM-T001 should surface as a diagnostic");
        assert_eq!(t001.severity, Some(DiagnosticSeverity::ERROR));
        // Positioned on the df-login line, not pinned to the top of the file.
        assert!(
            t001.range.start.line > 0,
            "diagnostic should be located on the flow"
        );
    }

    #[test]
    fn malformed_yaml_reports_a_single_parse_error() {
        let diags = compute("otmVersion: 0.2.0\nproject: [this is not an object");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, Some(NumberOrString::String("parse".into())));
    }

    #[test]
    fn dangling_reference_becomes_an_error_diagnostic() {
        let text = "otmVersion: 0.2.0\nproject: { id: p, name: P }\ncomponents:\n  - { id: a, name: A, type: process }\ndataflows:\n  - { id: f, name: F, source: a, destination: ghost }\n";
        let diags = compute(text);
        assert!(diags.iter().any(|d| d.code
            == Some(NumberOrString::String(
                "dataflow.destination.unknown".into()
            ))));
    }
}
