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

use crate::model::{Otm, Parent};
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
    /// Reconcile differing env names across sources (`production → prod`), so a
    /// Terraform env and an ArgoCD env join even when spelled differently.
    pub aliases: BTreeMap<String, String>,
    /// Explicit `environment → cluster trust-zone id`, overriding the auto match
    /// when linking workloads to the cluster they run on.
    pub cluster_mapping: BTreeMap<String, String>,
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            path_markers: ["environments", "envs", "env"].map(String::from).to_vec(),
            scopes: BTreeMap::new(),
            aliases: BTreeMap::new(),
            cluster_mapping: BTreeMap::new(),
        }
    }
}

impl EnvConfig {
    /// Canonical env name after alias reconciliation.
    fn canon(&self, env: &str) -> String {
        self.aliases
            .get(env)
            .map(String::as_str)
            .unwrap_or(env)
            .to_string()
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

/// Re-home Kubernetes workloads into the cluster trust zone of their environment,
/// across combined sources. Clusters are matched to workloads by env name (with
/// alias reconciliation); an explicit `clusterMapping` overrides. Only components
/// stamped `source=kubernetes` move, so Terraform resources of the same env stay
/// where they are. Falls back to the sole cluster when there's exactly one.
pub fn link_by_environment(otm: &mut Otm, cfg: &EnvConfig) {
    // env → cluster zone id: explicit mapping first, then auto from the cluster.
    let mut env_zone: BTreeMap<String, String> = cfg
        .cluster_mapping
        .iter()
        .map(|(env, zone)| (cfg.canon(env), zone.clone()))
        .collect();
    let cluster_zones: Vec<String> = otm
        .trust_zones
        .iter()
        .map(|z| z.id.clone())
        .filter(|id| id.starts_with("tz-cluster-"))
        .collect();
    for zone in &cluster_zones {
        let name = zone.trim_start_matches("tz-cluster-");
        if let Some(env) = otm
            .components
            .iter()
            .find(|c| c.id.contains(name) && c.attributes.contains_key("environment"))
            .and_then(|c| c.attributes.get("environment"))
        {
            env_zone
                .entry(cfg.canon(env))
                .or_insert_with(|| zone.clone());
        }
    }
    // One cluster, no per-env signal → every workload runs there.
    let single = (cluster_zones.len() == 1).then(|| cluster_zones[0].clone());

    for c in otm.components.iter_mut() {
        if c.attributes.get("source").map(String::as_str) != Some("kubernetes") {
            continue;
        }
        let target = c
            .attributes
            .get("environment")
            .and_then(|e| env_zone.get(&cfg.canon(e)).cloned())
            .or_else(|| single.clone());
        if let Some(zone) = target {
            c.parent = Some(Parent {
                trust_zone: Some(zone),
                component: None,
            });
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

    fn model_with_cluster() -> Otm {
        // A TF cluster (+ its zone) tagged prod, a k8s workload tagged prod, and a
        // Terraform bucket also tagged prod that must NOT move into the cluster.
        let mut otm = crate::parse(
            "otmVersion: 0.2.0\nproject: { id: p, name: P }\ntrustZones:\n  - { id: tz-internal, name: Internal }\n  - { id: tz-cluster-main, name: Cluster }\n",
        )
        .unwrap();
        let mut cluster = comp("google-container-cluster-main", None, Some("production"));
        cluster
            .attributes
            .insert("source".into(), "terraform".into());
        let mut workload = comp("frontend", None, Some("prod"));
        workload
            .attributes
            .insert("source".into(), "kubernetes".into());
        workload.parent = Some(Parent {
            trust_zone: Some("tz-internal".into()),
            component: None,
        });
        let mut bucket = comp("gcs-bucket", None, Some("prod"));
        bucket
            .attributes
            .insert("source".into(), "terraform".into());
        bucket.parent = Some(Parent {
            trust_zone: Some("tz-internal".into()),
            component: None,
        });
        otm.components.extend([cluster, workload, bucket]);
        otm
    }

    fn zone_of<'a>(otm: &'a Otm, id: &str) -> Option<&'a str> {
        otm.components
            .iter()
            .find(|c| c.id == id)?
            .parent
            .as_ref()?
            .trust_zone
            .as_deref()
    }

    #[test]
    fn link_moves_only_k8s_workloads_into_the_env_cluster() {
        let mut otm = model_with_cluster();
        // `prod` (workload) aliases to `production` (cluster's env) so they join.
        let mut cfg = EnvConfig::default();
        cfg.aliases.insert("prod".into(), "production".into());
        link_by_environment(&mut otm, &cfg);
        assert_eq!(zone_of(&otm, "frontend"), Some("tz-cluster-main")); // k8s moved
        assert_eq!(zone_of(&otm, "gcs-bucket"), Some("tz-internal")); // TF stayed
    }

    #[test]
    fn explicit_cluster_mapping_overrides_env_match() {
        let mut otm = model_with_cluster();
        let mut cfg = EnvConfig::default();
        cfg.cluster_mapping
            .insert("prod".into(), "tz-cluster-main".into());
        link_by_environment(&mut otm, &cfg);
        assert_eq!(zone_of(&otm, "frontend"), Some("tz-cluster-main"));
    }
}
