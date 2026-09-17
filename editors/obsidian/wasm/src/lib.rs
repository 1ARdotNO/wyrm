//! WebAssembly bindings for `otm-core`.
//!
//! Exposes the same parse → validate → analyze → render pipeline the CLI and LSP
//! use, so the Obsidian plugin runs the identical engine. Functions take the model
//! text and return JSON strings (findings/diagnostics) or the Mermaid source.

use wasm_bindgen::prelude::*;

/// Run the STRIDE rule engine; returns findings as a JSON array string.
#[wasm_bindgen]
pub fn analyze(model: &str) -> Result<String, JsError> {
    let otm = otm_core::parse(model).map_err(to_js)?;
    let findings = otm_core::ThreatLibrary::bundled().analyze(&otm);
    serde_json::to_string(&findings).map_err(to_js)
}

/// Structural validation; returns diagnostics as a JSON array string.
#[wasm_bindgen]
pub fn validate(model: &str) -> Result<String, JsError> {
    let otm = otm_core::parse(model).map_err(to_js)?;
    let diagnostics = otm_core::validate(&otm);
    serde_json::to_string(&diagnostics).map_err(to_js)
}

/// Render a Mermaid data-flow diagram from the model.
#[wasm_bindgen(js_name = toMermaid)]
pub fn to_mermaid(model: &str) -> Result<String, JsError> {
    let otm = otm_core::parse(model).map_err(to_js)?;
    Ok(otm_core::render::mermaid(&otm))
}

fn to_js<E: std::fmt::Display>(err: E) -> JsError {
    JsError::new(&err.to_string())
}
