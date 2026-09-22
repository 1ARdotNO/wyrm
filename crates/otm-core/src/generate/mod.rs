//! Generate a baseline OTM model from infrastructure files.
//!
//! Each importer (compose, kubernetes, …) turns one infra source into a baseline
//! [`Otm`]. They share the boundary model below: an internet zone (low trust), an
//! internal zone, and a data tier, with a synthetic external client so ingress
//! flows cross a real boundary. What infra can't express — asset sensitivity — is
//! left for a human (or an LLM pass) to annotate. See `docs/DETECTION.md`.

pub mod compose;
pub mod kubernetes;
#[cfg(feature = "terraform")]
pub mod terraform;

pub use compose::from_compose;
pub use kubernetes::from_manifests;
#[cfg(feature = "terraform")]
pub use terraform::{
    from_terraform, from_terraform_docs, from_terraform_scoped, from_tfplan_json, looks_like_tfplan,
};

use crate::model::{Component, Dataflow, Otm, Parent, TrustRisk, TrustZone};
use std::collections::{BTreeMap, BTreeSet};

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

/// Reconcile a freshly generated model with an existing (human-edited) one.
///
/// Regenerated **topology** wins — components, dataflows, and zones reflect the
/// current infrastructure. Human **annotations** are preserved: top-level
/// `assets`/`threats`/`mitigations`, per-element asset attachments, dataflow tags
/// (e.g. a `tls` a reviewer added), extra attributes, and any elements the human
/// added that the generator doesn't produce. This is what lets `wyrm init` re-run
/// on every commit without clobbering a reviewer's mitigations.
pub fn merge(generated: Otm, existing: Otm) -> Otm {
    let mut out = generated;

    let ex_components: BTreeMap<String, Component> = existing
        .components
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();
    let ex_flows: BTreeMap<String, Dataflow> = existing
        .dataflows
        .into_iter()
        .map(|d| (d.id.clone(), d))
        .collect();

    // Overlay human annotations onto the regenerated components.
    for c in &mut out.components {
        if let Some(ex) = ex_components.get(&c.id) {
            if !ex.assets.is_empty() {
                c.assets = ex.assets.clone();
            }
            for (k, v) in &ex.attributes {
                c.attributes.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    }
    // Keep components the human added that the generator no longer emits.
    let gen_ids: BTreeSet<String> = out.components.iter().map(|c| c.id.clone()).collect();
    for (id, c) in &ex_components {
        if !gen_ids.contains(id) {
            out.components.push(c.clone());
        }
    }

    // Overlay tags/assets onto regenerated dataflows (union tags — a reviewer's
    // `tls`/mitigation tag must survive).
    for d in &mut out.dataflows {
        if let Some(ex) = ex_flows.get(&d.id) {
            for t in &ex.tags {
                if !d.tags.contains(t) {
                    d.tags.push(t.clone());
                }
            }
            if !ex.assets.is_empty() {
                d.assets = ex.assets.clone();
            }
            for (k, v) in &ex.attributes {
                d.attributes.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    }
    let gen_flow_ids: BTreeSet<String> = out.dataflows.iter().map(|d| d.id.clone()).collect();
    for (id, d) in &ex_flows {
        if !gen_flow_ids.contains(id) {
            out.dataflows.push(d.clone());
        }
    }

    // Sensitivity and controls are entirely human-owned.
    out.assets = existing.assets;
    out.threats = existing.threats;
    out.mitigations = existing.mitigations;
    if existing.project.owner.is_some() {
        out.project.owner = existing.project.owner;
    }

    out.components.sort_by(|a, b| a.id.cmp(&b.id));
    out.dataflows.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// Drop generated elements whose id or name contains any of the (case-insensitive)
/// `patterns` — a way to strip autodetection noise (e.g. IAM/identity). Removes the
/// matching components, any dataflows touching them, and trust zones left empty.
pub fn exclude(otm: &mut Otm, patterns: &[String]) {
    if patterns.is_empty() {
        return;
    }
    let pats: Vec<String> = patterns.iter().map(|p| p.to_lowercase()).collect();
    let hit = |s: &str| {
        let s = s.to_lowercase();
        pats.iter().any(|p| s.contains(p.as_str()))
    };

    let removed: BTreeSet<String> = otm
        .components
        .iter()
        .filter(|c| hit(&c.id) || hit(&c.name))
        .map(|c| c.id.clone())
        .collect();
    otm.components.retain(|c| !removed.contains(&c.id));
    otm.dataflows.retain(|d| {
        !removed.contains(&d.source) && !removed.contains(&d.destination) && !hit(&d.name)
    });

    // Drop trust zones no surviving component lives in.
    let used: BTreeSet<&str> = otm
        .components
        .iter()
        .filter_map(|c| c.parent.as_ref().and_then(|p| p.trust_zone.as_deref()))
        .collect();
    otm.trust_zones.retain(|z| used.contains(z.id.as_str()));
}

#[cfg(all(test, feature = "terraform"))]
mod cross_link_tests {
    use super::*;

    #[test]
    fn k8s_workloads_land_in_the_tf_cluster_zone() {
        let tf =
            from_terraform("resource \"google_container_cluster\" \"main\" {}\n", "sys").unwrap();
        let mut k8s = from_manifests(
            "apiVersion: v1\nkind: Service\nmetadata: { name: api }\nspec: { type: ClusterIP, ports: [{ port: 8080 }] }\n",
            "sys",
        )
        .unwrap();
        place_in_cluster(&tf, &mut k8s);
        let api = k8s.components.iter().find(|c| c.id == "api").unwrap();
        assert_eq!(
            api.parent.as_ref().unwrap().trust_zone.as_deref(),
            Some("tz-cluster-main")
        );
        // Combining unions both, deduping the shared Internal/Data zones.
        let merged = combine(tf, k8s);
        assert!(merged.components.iter().any(|c| c.id == "api"));
        assert!(merged.trust_zones.iter().any(|z| z.id == "tz-cluster-main"));
    }
}

/// Union two generated models into one, deduping by id (keeping `a` on conflict).
/// Used to fold a Kubernetes model into a Terraform one for a single repo.
pub fn combine(mut a: Otm, b: Otm) -> Otm {
    fn seen<'a>(it: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
        it.map(str::to_string).collect()
    }
    let have = seen(a.components.iter().map(|c| c.id.as_str()));
    a.components
        .extend(b.components.into_iter().filter(|c| !have.contains(&c.id)));
    let have = seen(a.trust_zones.iter().map(|z| z.id.as_str()));
    a.trust_zones
        .extend(b.trust_zones.into_iter().filter(|z| !have.contains(&z.id)));
    let have = seen(a.dataflows.iter().map(|d| d.id.as_str()));
    a.dataflows
        .extend(b.dataflows.into_iter().filter(|d| !have.contains(&d.id)));
    let have = seen(a.assets.iter().map(|x| x.id.as_str()));
    a.assets
        .extend(b.assets.into_iter().filter(|x| !have.contains(&x.id)));
    let have = seen(a.mitigations.iter().map(|m| m.id.as_str()));
    a.mitigations
        .extend(b.mitigations.into_iter().filter(|m| !have.contains(&m.id)));
    a
}

/// Re-parent a Kubernetes model's internal workloads into the Terraform model's
/// cluster zone, so the k8s components live in the cluster they run on. Applied
/// only when the TF model defines exactly one cluster zone (unambiguous);
/// multi-cluster mapping belongs in `.threatmodel/data.yaml`.
pub fn place_in_cluster(tf: &Otm, k8s: &mut Otm) {
    let clusters: Vec<&str> = tf
        .trust_zones
        .iter()
        .map(|z| z.id.as_str())
        .filter(|id| id.starts_with("tz-cluster-"))
        .collect();
    let [cluster_zone] = clusters.as_slice() else {
        return;
    };
    for c in &mut k8s.components {
        let internal = c.parent.as_ref().and_then(|p| p.trust_zone.as_deref()) == Some(TZ_INTERNAL);
        if internal {
            c.parent = Some(Parent {
                trust_zone: Some((*cluster_zone).to_string()),
                component: None,
            });
        }
    }
}

/// Expand a user-facing exclusion token: named categories → their patterns, or the
/// token itself as a literal substring.
pub fn expand_exclude(token: &str) -> Vec<String> {
    match token.to_lowercase().as_str() {
        "iam" | "identity" | "access" => [
            "iam",
            "_ksa_principal",
            "_principal",
            "service_account",
            "serviceaccount",
            "org_policy",
            "org-policy",
            "custom_role",
            "custom-role",
            "deny_policy",
            "_project_data",
            "_lien",
            "_binding",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        other => vec![other.to_string()],
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Asset, Mitigation};

    const COMPOSE: &str = "services:\n  web:\n    image: nginx\n    ports: [\"80:80\"]\n    depends_on: [api]\n  api:\n    build: .\n";

    #[test]
    fn merge_preserves_human_annotations_and_refreshes_topology() {
        // A reviewed model: tls on the ingress flow, a mitigation, an asset, a hand component.
        let mut existing = from_compose(COMPOSE, "demo").unwrap();
        for d in &mut existing.dataflows {
            if d.destination == "web" {
                d.tags.push("tls".to_string());
            }
        }
        existing.mitigations.push(Mitigation {
            id: "m1".into(),
            name: "Edge WAF".into(),
            description: None,
            risk_reduction: Some(80),
            ..Default::default()
        });
        existing.assets.push(Asset {
            id: "pii".into(),
            name: "PII".into(),
            risk: None,
        });
        existing.components.push(Component {
            id: "handmade".into(),
            name: "Hand".into(),
            kind: "process".into(),
            parent: Some(Parent {
                trust_zone: Some(TZ_INTERNAL.into()),
                component: None,
            }),
            assets: Default::default(),
            attributes: Default::default(),
        });

        // Regenerate fresh topology and reconcile.
        let merged = merge(from_compose(COMPOSE, "demo").unwrap(), existing);

        assert!(
            merged
                .dataflows
                .iter()
                .any(|d| d.destination == "web" && d.tags.iter().any(|t| t == "tls")),
            "reviewer's tls tag must survive regeneration"
        );
        assert!(
            merged.mitigations.iter().any(|m| m.id == "m1"),
            "mitigation preserved"
        );
        assert!(
            merged.assets.iter().any(|a| a.id == "pii"),
            "asset preserved"
        );
        assert!(
            merged.components.iter().any(|c| c.id == "handmade"),
            "hand-added component preserved"
        );
        assert!(
            merged.components.iter().any(|c| c.id == "api"),
            "topology refreshed"
        );
        assert!(crate::validate::is_valid(&crate::validate(&merged)));
    }

    #[test]
    fn exclude_strips_components_and_dangling_flows() {
        let compose = "services:\n  web: { image: nginx, ports: [\"80:80\"], depends_on: [iam-sync] }\n  iam-sync: { image: busybox }\n  db: { image: postgres }\n";
        let mut otm = from_compose(compose, "demo").unwrap();
        exclude(&mut otm, &expand_exclude("iam"));
        assert!(
            !otm.components.iter().any(|c| c.id == "iam-sync"),
            "iam component removed"
        );
        assert!(
            !otm.dataflows.iter().any(|d| d.destination == "iam-sync"),
            "dangling flow removed"
        );
        assert!(
            otm.components.iter().any(|c| c.id == "web"),
            "real component kept"
        );
        assert!(
            otm.components.iter().any(|c| c.id == "db"),
            "real component kept"
        );
        assert!(crate::validate::is_valid(&crate::validate(&otm)));
    }
}
