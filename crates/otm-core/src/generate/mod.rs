//! Generate a baseline OTM model from infrastructure files.
//!
//! Each importer (compose, kubernetes, …) turns one infra source into a baseline
//! [`Otm`]. They share the boundary model below: an internet zone (low trust), an
//! internal zone, and a data tier, with a synthetic external client so ingress
//! flows cross a real boundary. What infra can't express — asset sensitivity — is
//! left for a human (or an LLM pass) to annotate. See `docs/DETECTION.md`.

pub mod compose;
pub mod kubernetes;

pub use compose::from_compose;
pub use kubernetes::from_manifests;

use crate::model::{Component, Parent, TrustRisk, TrustZone};

pub(crate) const TZ_INTERNET: &str = "tz-internet";
pub(crate) const TZ_INTERNAL: &str = "tz-internal";
pub(crate) const TZ_DATA: &str = "tz-data";
pub(crate) const EXTERNAL: &str = "external";

pub(crate) fn zone(id: &str, name: &str, trust: u8) -> TrustZone {
    TrustZone {
        id: id.to_string(),
        name: name.to_string(),
        risk: Some(TrustRisk {
            trust_rating: Some(trust),
        }),
    }
}

/// The synthetic external client that internet-facing flows originate from.
pub(crate) fn external_actor() -> Component {
    Component {
        id: EXTERNAL.to_string(),
        name: "External client".to_string(),
        kind: "external-entity".to_string(),
        parent: Some(Parent {
            trust_zone: Some(TZ_INTERNET.to_string()),
            component: None,
        }),
        assets: Default::default(),
        attributes: Default::default(),
    }
}

pub(crate) fn is_datastore(kind: &str) -> bool {
    matches!(kind, "database" | "data-store" | "message-queue")
}

/// Turn an arbitrary name into a stable OTM id.
pub(crate) fn sanitize_id(s: &str) -> String {
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
