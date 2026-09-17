//! `otm-core` — the shared engine behind wyrm.
//!
//! Parse an [Open Threat Model](https://github.com/iriusrisk/OpenThreatModel)
//! document, [`validate`] its structure, run the STRIDE [`rules`] engine, and
//! [`render`] a diagram. Every wyrm client (the CLI, the Zed LSP, the Obsidian
//! plugin via WASM) is a thin shell over this crate — the analysis lives here
//! exactly once.

pub mod model;
pub mod render;
pub mod rules;
pub mod validate;

pub use model::Otm;
pub use rules::{Finding, Severity, Stride, ThreatLibrary};
pub use validate::{Diagnostic, validate};

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Parse an OTM document from a string, accepting either YAML or JSON.
///
/// OTM permits both; YAML is a superset of JSON, so we try YAML first and only
/// fall back to the JSON parser for its sharper error messages on `.json` input.
pub fn parse(text: &str) -> Result<Otm, Error> {
    match serde_yaml_ng::from_str::<Otm>(text) {
        Ok(otm) => Ok(otm),
        Err(yaml_err) => {
            let trimmed = text.trim_start();
            if trimmed.starts_with('{') {
                serde_json::from_str::<Otm>(text).map_err(Error::from)
            } else {
                Err(Error::Yaml(yaml_err))
            }
        }
    }
}

/// Parse an OTM document from a file path.
pub fn parse_file(path: impl AsRef<Path>) -> Result<Otm, Error> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse(&text)
}
