//! Classify each component into a deployment environment (prod / staging / …),
//! so a model can be sliced and risk-weighted per env — statically, with no plan
//! or cloud access.
//!
//! Conventions differ, so classification is config-driven with three signals:
//!   1. **path marker** — a directory whose *next* segment names the env
//!      (`environments/prod/…` → `prod`); the common layout, on by default.
//!   2. **scope map** — explicit `dir-prefix → env`, for repos where the env is a
//!      variable rather than a folder.
//!   3. **literal label** — a resource `labels`/`tags` value, stamped at import.
//!
//! Where the env is genuinely dynamic (one root module deploys to many envs via a
//! `var.environment`), none of these can name it — the component is left
//! unclassified rather than guessed.

use crate::model::Otm;
use serde::Deserialize;
use std::collections::BTreeMap;

/// How wyrm derives an environment. Loaded from `.threatmodel/environments.yaml`;
/// an absent file uses the defaults (the common `environments/<env>` layout).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EnvConfig {
    /// Directory segments whose *following* segment names the env. Tried in order.
    pub path_markers: Vec<String>,
    /// Explicit `scope-prefix → environment`, for var-based repos. The longest
    /// matching prefix wins, so specific dirs override broad ones.
    pub scopes: BTreeMap<String, String>,
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            path_markers: ["environments", "envs", "env"].map(String::from).to_vec(),
            scopes: BTreeMap::new(),
        }
    }
}

/// Parse a `.threatmodel/environments.yaml` config.
pub fn config_from_yaml(yaml: &str) -> Result<EnvConfig, serde_yaml_ng::Error> {
    serde_yaml_ng::from_str(yaml)
}

/// Stamp `attributes.environment` on every component we can classify from its
/// module `scope`. A value already present (e.g. a literal label captured at
/// import) is authoritative and left untouched.
pub fn classify_environments(otm: &mut Otm, cfg: &EnvConfig) {
    for c in otm.components.iter_mut() {
        if c.attributes.contains_key("environment") {
            continue;
        }
        let Some(scope) = c.attributes.get("scope").cloned() else {
            continue;
        };
        if let Some(env) = env_of(&scope, cfg) {
            c.attributes.insert("environment".into(), env);
        }
    }
}

/// Derive an env from a module scope (directory): the explicit scope map first
/// (longest prefix), then the path-marker convention.
fn env_of(scope: &str, cfg: &EnvConfig) -> Option<String> {
    if let Some((_, env)) = cfg
        .scopes
        .iter()
        .filter(|(k, _)| scope == k.as_str() || scope.starts_with(&format!("{k}/")))
        .max_by_key(|(k, _)| k.len())
    {
        return Some(env.clone());
    }
    let segs: Vec<&str> = scope.split('/').filter(|s| !s.is_empty()).collect();
    for (i, seg) in segs.iter().enumerate() {
        if cfg.path_markers.iter().any(|m| m == seg) {
            if let Some(next) = segs.get(i + 1) {
                return Some((*next).to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Component;

    fn comp(id: &str, scope: Option<&str>, env: Option<&str>) -> Component {
        let mut c = Component {
            id: id.into(),
            name: id.into(),
            kind: "process".into(),
            parent: None,
            assets: Default::default(),
            attributes: Default::default(),
        };
        if let Some(s) = scope {
            c.attributes.insert("scope".into(), s.into());
        }
        if let Some(e) = env {
            c.attributes.insert("environment".into(), e.into());
        }
        c
    }

    #[test]
    fn path_marker_takes_segment_after_marker() {
        let cfg = EnvConfig::default();
        assert_eq!(
            env_of("gcloud/environments/team-a", &cfg).as_deref(),
            Some("team-a")
        );
        assert_eq!(env_of("gcloud/modules/gke", &cfg), None);
    }

    #[test]
    fn scope_map_wins_and_prefers_longest_prefix() {
        let mut cfg = EnvConfig::default();
        cfg.scopes.insert("uapi".into(), "shared".into());
        cfg.scopes.insert("uapi/prod".into(), "production".into());
        assert_eq!(env_of("uapi/staging", &cfg).as_deref(), Some("shared"));
        assert_eq!(env_of("uapi/prod/db", &cfg).as_deref(), Some("production"));
    }

    #[test]
    fn classify_sets_env_and_respects_existing_literal() {
        let mut otm = crate::parse("otmVersion: 0.2.0\nproject: { id: p, name: P }\n").unwrap();
        otm.components
            .push(comp("a", Some("gcloud/environments/staging"), None));
        otm.components.push(comp(
            "b",
            Some("gcloud/environments/staging"),
            Some("prod-literal"),
        ));
        otm.components.push(comp("c", None, None)); // no scope → skipped
        classify_environments(&mut otm, &EnvConfig::default());
        let env = |id: &str| {
            otm.components
                .iter()
                .find(|c| c.id == id)
                .and_then(|c| c.attributes.get("environment"))
                .cloned()
        };
        assert_eq!(env("a").as_deref(), Some("staging"));
        assert_eq!(env("b").as_deref(), Some("prod-literal")); // literal not overwritten
        assert_eq!(env("c"), None);
    }
}
