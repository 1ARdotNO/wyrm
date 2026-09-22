//! Baseline model from Terraform (HCL).
//!
//! Terraform describes *resources*, not flows, so this importer is an exposure
//! inventory: each notable resource becomes a component (load balancers/APIs/
//! gateways that are internet-facing get an ingress dataflow; datastores land in
//! a data tier), and edge controls (WAF/Cloud Armor/DDoS) become mitigations.
//! Internal service-to-service flows aren't inferable from HCL without resolving
//! references, so they're left for review. See `docs/DETECTION.md`.

use super::*;
use crate::model::{Component, Dataflow, Mitigation, Otm, Parent, Project, TrustZone};
use hcl::{Body, Expression, Structure};
use std::collections::{BTreeMap, BTreeSet};

/// Build a baseline [`Otm`] from a single Terraform document.
pub fn from_terraform(text: &str, project_name: &str) -> Result<Otm, crate::Error> {
    let body: Body = hcl::from_str(text).map_err(|e| crate::Error::Hcl(e.to_string()))?;
    let mut b = Builder::default();
    add_blocks(&mut b, &body);
    Ok(b.build(project_name))
}

/// Build a baseline from many Terraform documents, **skipping any that don't
/// parse** (template files with placeholders, or HCL features the parser doesn't
/// support). Returns the model and the number of skipped documents — real repos
/// shouldn't fail wholesale because one file is unparseable.
pub fn from_terraform_docs<'a>(
    docs: impl IntoIterator<Item = &'a str>,
    project_name: &str,
) -> (Otm, usize) {
    let mut b = Builder::default();
    let mut skipped = 0;
    for text in docs {
        match hcl::from_str::<Body>(text) {
            Ok(body) => add_blocks(&mut b, &body),
            Err(_) => skipped += 1,
        }
    }
    (b.build(project_name), skipped)
}

/// Like [`from_terraform_docs`], but each document carries a *scope* — its module
/// directory. Any resource/module whose bare id appears in **more than one scope**
/// is path-qualified (`envs-prod-aws_s3_bucket-logs`) so multi-module / multi-env
/// layouts don't collide on a shared name. Ids seen in a single scope stay clean.
pub fn from_terraform_scoped(docs: &[(String, String)], project_name: &str) -> (Otm, usize) {
    // Pass 1: which bare ids show up under two or more distinct scopes?
    let mut scopes_of: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for (scope, text) in docs {
        if let Ok(body) = hcl::from_str::<Body>(text) {
            for key in resource_keys(&body) {
                scopes_of.entry(key).or_default().insert(scope.as_str());
            }
        }
    }
    let qualify: BTreeSet<String> = scopes_of
        .into_iter()
        .filter(|(_, s)| s.len() > 1)
        .map(|(k, _)| k)
        .collect();

    // Pass 2: build, qualifying only the colliding ids.
    let mut b = Builder {
        qualify,
        ..Default::default()
    };
    let mut skipped = 0;
    for (scope, text) in docs {
        match hcl::from_str::<Body>(text) {
            Ok(body) => {
                scope.clone_into(&mut b.scope);
                add_blocks(&mut b, &body);
            }
            Err(_) => skipped += 1,
        }
    }
    (b.build(project_name), skipped)
}

/// The bare ids a document declares (resources and module calls), for collision
/// detection — mirrors the id scheme in [`Builder::resource`]/[`Builder::module`].
fn resource_keys(body: &Body) -> Vec<String> {
    let mut keys = Vec::new();
    for structure in body.iter() {
        let Structure::Block(bl) = structure else {
            continue;
        };
        match bl.identifier.as_str() {
            "resource" => {
                let rtype = bl.labels.first().map(label_str).unwrap_or_default();
                let rname = bl.labels.get(1).map(label_str).unwrap_or_default();
                if !rtype.is_empty() && !rname.is_empty() {
                    keys.push(sanitize_id(&format!("{rtype}-{rname}")));
                }
            }
            "module" => {
                if let Some(name) = bl.labels.first().map(label_str).filter(|n| !n.is_empty()) {
                    keys.push(sanitize_id(&format!("module-{name}")));
                }
            }
            _ => {}
        }
    }
    keys
}

fn add_blocks(b: &mut Builder, body: &Body) {
    for structure in body.iter() {
        let Structure::Block(bl) = structure else {
            continue;
        };
        match bl.identifier.as_str() {
            "resource" => {
                let rtype = bl.labels.first().map(label_str).unwrap_or_default();
                let rname = bl.labels.get(1).map(label_str).unwrap_or_default();
                if !rtype.is_empty() && !rname.is_empty() {
                    b.resource(rtype, rname, Attrs::Hcl(bl.body()));
                }
            }
            // Module calls are where most real infra lives — model each as a
            // component (type inferred from its name + source).
            "module" => {
                if let Some(name) = bl.labels.first().map(label_str).filter(|n| !n.is_empty()) {
                    let source = attr_str(bl.body(), "source").unwrap_or_default();
                    b.module(name, source);
                }
            }
            _ => {}
        }
    }
}

#[derive(Default)]
struct Builder {
    components: BTreeMap<String, Component>,
    dataflows: Vec<Dataflow>,
    mitigations: Vec<Mitigation>,
    /// Trust zones derived from networks (VPC/subnet) and cluster internals.
    zones: BTreeMap<String, TrustZone>,
    has_edge: bool,
    has_db: bool,
    /// An IAP-gated backend was found anywhere in the config.
    iap: bool,
    /// A Cloud Armor security policy is attached to a backend anywhere in the config.
    armor: bool,
    /// (edge component id, ingress flow id) for HTTPS edges — IAP/WAF front these.
    https_edges: Vec<(String, String)>,
    /// Module scope (directory) of the document currently being read.
    scope: String,
    /// Bare resource/module ids that collide across scopes and so must be
    /// path-qualified. Empty on the single-document / single-module path.
    qualify: BTreeSet<String>,
}

impl Builder {
    /// A module call becomes a component; its type is inferred from name + source.
    fn module(&mut self, name: &str, source: &str) {
        let (id, display) = self.scoped(
            &sanitize_id(&format!("module-{name}")),
            &format!("module.{name}"),
        );
        let kind = module_type(name, source);
        let store = is_datastore(kind);
        self.has_db |= store;
        self.put(
            &id,
            &display,
            kind,
            if store { TZ_DATA } else { TZ_INTERNAL },
        );
        self.tag_provenance(&id, None);
    }

    fn resource(&mut self, rtype: &str, rname: &str, attrs: Attrs) {
        let (id, display) = self.scoped(
            &sanitize_id(&format!("{rtype}-{rname}")),
            &format!("{rtype}.{rname}"),
        );
        self.add_resource(rtype, &id, &display, rname, attrs);
    }

    /// Path-qualify an id/display when its bare id collides across module scopes,
    /// so multi-module / multi-env layouts don't clobber one another. Non-colliding
    /// ids (the common case) are left clean.
    fn scoped(&self, base: &str, display: &str) -> (String, String) {
        if !self.qualify.contains(base) {
            return (base.to_string(), display.to_string());
        }
        let label = if self.scope.is_empty() {
            "root"
        } else {
            self.scope.as_str()
        };
        (
            sanitize_id(&format!("{label}-{base}")),
            format!("{label}/{display}"),
        )
    }

    /// Add every managed resource in a plan/state-JSON module, keyed by its full
    /// (module-scoped) address so nested resources never collide.
    fn resource_from_plan(&mut self, r: &StateResource, module: &str) {
        let id = sanitize_id(&r.address);
        self.add_resource(&r.rtype, &id, &r.address, &r.name, Attrs::Json(&r.values));
        // Tag the component with its module so clients can group by it.
        if !module.is_empty() {
            if let Some(c) = self.components.get_mut(&id) {
                c.attributes
                    .insert("module".to_string(), module.to_string());
            }
        }
    }

    /// Shared resource handling for both HCL and plan-JSON. `id`/`display` carry
    /// the (module-scoped) address; `label` names the resource in mitigations.
    fn add_resource(&mut self, rtype: &str, id: &str, display: &str, label: &str, attrs: Attrs) {
        // Networks (VPC/subnet) and cluster internals become trust zones — the
        // segments a threat model reasons over. VPC/subnet are pure zones; a
        // cluster also defines an internal zone but keeps its control-plane node.
        if let Some((zid, zname, rating)) = derived_zone(rtype, label) {
            self.zones
                .entry(zid.clone())
                .or_insert_with(|| zone(&zid, &zname, rating));
            if !is_cluster(rtype) {
                return;
            }
        }

        // IAP on a backend service = a Google-managed auth wall on the HTTPS path.
        if iap_enabled(rtype, attrs) {
            self.iap = true;
        }
        // A backend service with `security_policy` set has Cloud Armor in front.
        if cloud_armor_attached(rtype, attrs) {
            self.armor = true;
        }

        // Edge controls attach nowhere specific here — record them as mitigations.
        if let Some(control) = mitigation_for(rtype) {
            self.mitigations.push(Mitigation {
                id: id.to_string(),
                name: format!("{control} ({label})"),
                description: None,
                risk_reduction: None,
                ..Default::default()
            });
            return;
        }

        match classify(rtype) {
            Some(Kind::Datastore(k)) => {
                self.has_db = true;
                self.put(id, display, k, TZ_DATA);
                // Record at-rest posture so the datastore rules can read it.
                if let Some(c) = self.components.get_mut(id) {
                    if datastore_public(rtype, attrs) {
                        c.attributes
                            .insert("public".to_string(), "true".to_string());
                    }
                    if datastore_encrypted(rtype, attrs) {
                        c.attributes
                            .insert("encryption".to_string(), "at-rest".to_string());
                    }
                }
            }
            Some(Kind::Compute) => self.put(id, display, "process", TZ_INTERNAL),
            Some(Kind::Edge) => {
                self.put(id, display, "web-service", TZ_INTERNAL);
                if is_internet_facing(rtype, attrs) {
                    let enc = edge_encryption(rtype, attrs);
                    let fid = self.ingress(id, display, enc);
                    if enc == Some("tls") {
                        self.https_edges.push((id.to_string(), fid));
                    }
                }
            }
            None => {}
        }
        self.tag_provenance(id, Some(attrs));
    }

    /// Record where a component came from — its module `scope` (directory) and a
    /// literal `environment` label if the resource carries one — so downstream
    /// env classification can slice the model without a plan.
    fn tag_provenance(&mut self, id: &str, attrs: Option<Attrs>) {
        let scope = self.scope.clone();
        let Some(c) = self.components.get_mut(id) else {
            return;
        };
        if !scope.is_empty() {
            c.attributes.entry("scope".to_string()).or_insert(scope);
        }
        if let Some(env) = attrs.and_then(literal_env) {
            c.attributes.entry("environment".to_string()).or_insert(env);
        }
    }

    fn put(&mut self, id: &str, name: &str, kind: &str, zone_id: &str) {
        self.components.insert(
            id.to_string(),
            Component {
                id: id.to_string(),
                name: name.to_string(),
                kind: kind.to_string(),
                parent: Some(Parent {
                    trust_zone: Some(zone_id.to_string()),
                    component: None,
                }),
                assets: Default::default(),
                attributes: Default::default(),
            },
        );
    }

    fn ingress(&mut self, id: &str, name: &str, encryption: Option<&str>) -> String {
        self.has_edge = true;
        // IPSec tunnels and HTTPS/SSL-proxy LBs are encrypted by construction; tag
        // them so they don't read as cleartext ingress (WYRM-T002 false positive).
        let tags = encryption.map(|t| vec![t.to_string()]).unwrap_or_default();
        let fid = format!("df-ingress-{id}");
        self.dataflows.push(Dataflow {
            id: fid.clone(),
            name: format!("external request to {name}"),
            source: EXTERNAL.to_string(),
            destination: id.to_string(),
            assets: Vec::new(),
            attributes: Default::default(),
            tags,
        });
        fid
    }

    fn build(mut self, project_name: &str) -> Otm {
        let mut components: Vec<Component> = self.components.into_values().collect();
        if self.has_edge {
            components.push(external_actor());
        }

        let mut trust_zones = Vec::new();
        if self.has_edge {
            trust_zones.push(zone(TZ_INTERNET, "Internet", 10));
        }
        trust_zones.push(zone(TZ_INTERNAL, "Internal Network", 70));
        if self.has_db {
            trust_zones.push(zone(TZ_DATA, "Data Tier", 85));
        }
        // Networks/subnets/cluster internals discovered in the config.
        trust_zones.extend(std::mem::take(&mut self.zones).into_values());

        // IAP fronts the HTTPS ingress path: a managed auth+authz wall. Link it to
        // the HTTPS edges so it downgrades their spoofing/edge-exposure findings.
        // It does NOT cover transport (T002) or app-layer bugs — hence not 100.
        if self.iap && !self.https_edges.is_empty() {
            let mut targets: Vec<String> = Vec::new();
            for (cid, fid) in &self.https_edges {
                targets.push(cid.clone());
                targets.push(fid.clone());
            }
            self.mitigations.push(Mitigation {
                id: "iap-auth-gate".to_string(),
                name: "Identity-Aware Proxy (Google-managed auth gate)".to_string(),
                description: Some(
                    "IAP blocks the backend until the caller is authenticated and holds roles/iap.httpsResourceAccessor. Verify the IAM binding is not allUsers/allAuthenticatedUsers.".to_string(),
                ),
                risk_reduction: Some(80),
                applies_to: targets,
                addresses: vec!["WYRM-T003".to_string(), "WYRM-T005".to_string()],
            });
        }

        // Cloud Armor (attached via a backend's `security_policy`) filters the
        // HTTPS edges. A WAF downgrades edge exposure, it doesn't wall it off —
        // so a partial reduction, and only on the exposure rule (T003).
        if self.armor && !self.https_edges.is_empty() {
            let mut targets: Vec<String> = Vec::new();
            for (cid, fid) in &self.https_edges {
                targets.push(cid.clone());
                targets.push(fid.clone());
            }
            self.mitigations.push(Mitigation {
                id: "cloud-armor".to_string(),
                name: "Cloud Armor (WAF on the ingress)".to_string(),
                description: Some(
                    "A Cloud Armor security policy filters this HTTPS backend. Confirm the policy enforces (not preview) and has meaningful deny rules.".to_string(),
                ),
                risk_reduction: Some(50),
                applies_to: targets,
                addresses: vec!["WYRM-T003".to_string()],
            });
        }

        let mut seen = BTreeSet::new();
        self.dataflows.retain(|d| seen.insert(d.id.clone()));
        self.mitigations.sort_by(|a, b| a.id.cmp(&b.id));
        self.mitigations.dedup_by(|a, b| a.id == b.id);

        components.sort_by(|a, b| a.id.cmp(&b.id));
        self.dataflows.sort_by(|a, b| a.id.cmp(&b.id));

        Otm {
            otm_version: "0.2.0".to_string(),
            project: Project {
                id: sanitize_id(project_name),
                name: project_name.to_string(),
                owner: None,
                description: Some("Baseline generated by `wyrm init` from Terraform — an exposure inventory; add internal dataflows and asset sensitivity.".to_string()),
            },
            trust_zones,
            components,
            dataflows: self.dataflows,
            assets: Vec::new(),
            threats: Vec::new(),
            mitigations: self.mitigations,
        }
    }
}

enum Kind {
    Edge,
    Datastore(&'static str),
    Compute,
}

fn classify(rtype: &str) -> Option<Kind> {
    // Datastores → data tier.
    const DATABASES: &[&str] = &[
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_dynamodb_table",
        "google_sql_database_instance",
        "google_bigtable_instance",
        "google_spanner_instance",
        "google_spanner_database",
        "google_firestore_database",
        "google_bigquery_dataset",
        "google_redis_cluster",
        "azurerm_postgresql_server",
        "azurerm_postgresql_flexible_server",
        "azurerm_mysql_server",
        "azurerm_mysql_flexible_server",
        "azurerm_mssql_server",
        "azurerm_sql_server",
        "azurerm_cosmosdb_account",
    ];
    const STORES: &[&str] = &[
        "aws_elasticache_cluster",
        "aws_elasticache_replication_group",
        "aws_s3_bucket",
        "google_redis_instance",
        "google_storage_bucket",
        "google_secret_manager_secret",
        "google_kms_key_ring",
        "google_kms_crypto_key",
        "google_storage_hmac_key",
        "kubernetes_secret",
        "azurerm_redis_cache",
        "azurerm_storage_account",
        "azurerm_key_vault",
    ];
    const QUEUES: &[&str] = &[
        "aws_sqs_queue",
        "aws_mq_broker",
        "google_pubsub_topic",
        "azurerm_servicebus_namespace",
    ];
    const EDGE: &[&str] = &[
        "aws_lb",
        "aws_alb",
        "aws_elb",
        "aws_apigatewayv2_api",
        "aws_api_gateway_rest_api",
        "google_compute_global_forwarding_rule",
        "google_compute_forwarding_rule",
        "google_container_cluster",
        "aws_eks_cluster",
        "azurerm_kubernetes_cluster",
        "azurerm_lb",
        "azurerm_application_gateway",
        // VPN edges — internet-facing but the tunnel is encrypted (see edge_encryption).
        "google_compute_vpn_gateway",
        "google_compute_ha_vpn_gateway",
        "google_compute_vpn_tunnel",
        "aws_vpn_gateway",
        "azurerm_virtual_network_gateway",
    ];
    const COMPUTE: &[&str] = &[
        "aws_instance",
        "aws_ecs_service",
        "aws_lambda_function",
        "google_compute_instance",
        "google_cloud_run_service",
        "google_cloud_run_v2_service",
        "google_cloudfunctions_function",
        "google_cloudfunctions2_function",
        "google_container_node_pool",
        "aws_eks_node_group",
        "helm_release",
        "kubernetes_deployment",
        "kubernetes_stateful_set",
        "azurerm_linux_virtual_machine",
        "azurerm_windows_virtual_machine",
        "azurerm_virtual_machine",
    ];

    if DATABASES.contains(&rtype) {
        Some(Kind::Datastore("database"))
    } else if STORES.contains(&rtype) {
        Some(Kind::Datastore("data-store"))
    } else if QUEUES.contains(&rtype) {
        Some(Kind::Datastore("message-queue"))
    } else if EDGE.contains(&rtype) {
        Some(Kind::Edge)
    } else if COMPUTE.contains(&rtype) {
        Some(Kind::Compute)
    } else {
        None
    }
}

/// Infer a component type for a module call from its name + source path.
fn module_type(name: &str, source: &str) -> &'static str {
    let s = format!("{name} {source}").to_lowercase();
    let has = |kws: &[&str]| kws.iter().any(|k| s.contains(k));
    if has(&[
        "postgres",
        "mysql",
        "spanner",
        "cloudsql",
        "cloud-sql",
        "bigtable",
        "firestore",
        "database",
        "dynamodb",
        "rds",
        "-db",
        "db-",
    ]) {
        "database"
    } else if has(&[
        "redis",
        "memcache",
        "memorystore",
        "cache",
        "bucket",
        "storage",
        "gcs",
        "s3",
        "secret",
        "kms",
        "vault",
        "backup",
    ]) {
        "data-store"
    } else if has(&[
        "pubsub",
        "pub-sub",
        "kafka",
        "queue",
        "topic",
        "sqs",
        "servicebus",
        "eventhub",
    ]) {
        "message-queue"
    } else if has(&[
        "gke",
        "cluster",
        "kubernetes",
        "k8s",
        "cloudrun",
        "cloud-run",
        "appengine",
        "apigee",
        "gateway",
        "ingress",
        "loadbalancer",
        "load-balancer",
    ]) {
        "web-service"
    } else {
        "process"
    }
}

fn mitigation_for(rtype: &str) -> Option<&'static str> {
    match rtype {
        "aws_wafv2_web_acl" => Some("AWS WAF"),
        "aws_shield_protection" => Some("AWS Shield (DDoS)"),
        "google_compute_security_policy" => Some("Cloud Armor"),
        "google_compute_region_security_policy" => Some("Cloud Armor (regional)"),
        "azurerm_web_application_firewall_policy" => Some("Azure WAF"),
        "azurerm_network_ddos_protection_plan" => Some("Azure DDoS Protection"),
        "sigsci_site" => Some("Signal Sciences WAF"),
        _ => None,
    }
}

/// Provider defaults favour exposure — treat "attribute absent" as internet-facing.
/// A literal environment name from a resource's `labels`/`tags`, if present.
/// Interpolated/variable values (`var.environment`, `${…}`) aren't statically
/// knowable, so they're skipped — the env stays unclassified rather than guessed.
fn literal_env(a: Attrs) -> Option<String> {
    for (block, key) in [
        ("labels", "environment"),
        ("labels", "env"),
        ("tags", "Environment"),
        ("tags", "environment"),
    ] {
        if let Some(v) = a.nested(block).and_then(|n| n.get_str(key)) {
            if !v.is_empty() && !v.contains("var.") && !v.contains("${") {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn is_internet_facing(rtype: &str, a: Attrs) -> bool {
    match rtype {
        "aws_lb" | "aws_alb" | "aws_elb" => a.get_bool("internal") != Some(true),
        "aws_apigatewayv2_api" => a.get_bool("disable_execute_api_endpoint") != Some(true),
        "aws_api_gateway_rest_api" => true,
        "google_compute_global_forwarding_rule" | "google_compute_forwarding_rule" => a
            .get_str("load_balancing_scheme")
            .is_none_or(|s| s.starts_with("EXTERNAL")),
        "google_container_cluster" => {
            // Public control plane unless explicitly private.
            a.nested("private_cluster_config")
                .and_then(|n| n.get_bool("enable_private_endpoint"))
                != Some(true)
        }
        "aws_eks_cluster" => {
            // Public API endpoint on by default.
            a.nested("vpc_config")
                .and_then(|n| n.get_bool("endpoint_public_access"))
                != Some(false)
        }
        "azurerm_kubernetes_cluster" => a.get_bool("private_cluster_enabled") != Some(true),
        "azurerm_lb" | "azurerm_application_gateway" => a
            .nested("frontend_ip_configuration")
            .is_some_and(|n| n.has("public_ip_address_id")),
        // VPN gateways terminate on a public IP; the tunnel itself is encrypted.
        "google_compute_vpn_gateway"
        | "google_compute_ha_vpn_gateway"
        | "aws_vpn_gateway"
        | "azurerm_virtual_network_gateway" => true,
        _ => false,
    }
}

/// The transport-security tag for an edge's ingress flow, if it is encrypted by
/// construction — so it isn't flagged as cleartext (WYRM-T002 false positive).
/// Returns `Some("encrypted")` for IPSec/VPN tunnels, `Some("tls")` for HTTPS/SSL
/// -proxy load balancers, `None` for plain HTTP / unknown (stays flagged).
/// Detected structurally (protocols, proxy target), never by resource name.
fn edge_encryption(rtype: &str, a: Attrs) -> Option<&'static str> {
    // A managed Kubernetes control plane (kube-apiserver) is HTTPS/mTLS by
    // construction — its exposure is an authn/edge concern, never cleartext.
    if is_cluster(rtype) {
        return Some("tls");
    }
    match rtype {
        "google_compute_vpn_gateway"
        | "google_compute_ha_vpn_gateway"
        | "google_compute_vpn_tunnel"
        | "aws_vpn_gateway"
        | "aws_vpn_connection"
        | "azurerm_virtual_network_gateway" => Some("encrypted"),
        "google_compute_forwarding_rule" | "google_compute_global_forwarding_rule" => {
            let proto = a.get_str("ip_protocol").unwrap_or("");
            let ipsec = proto.eq_ignore_ascii_case("ESP") || proto.eq_ignore_ascii_case("AH");
            let ports = a
                .get_str("port_range")
                .or_else(|| a.get_str("ports"))
                .unwrap_or("");
            let ike = ports.contains("500") || ports.contains("4500");
            let target = a.get_str("target").unwrap_or("").to_lowercase();
            if ipsec || ike || target.contains("vpn") {
                Some("encrypted")
            } else if target.contains("https_proxy")
                || target.contains("ssl_proxy")
                || ports.contains("443")
            {
                Some("tls")
            } else {
                None
            }
        }
        _ => None,
    }
}

/// A trust zone a resource *defines*: VPC/subnet are network segments; a managed
/// cluster also anchors an internal zone for its workloads (see the k8s importer).
fn derived_zone(rtype: &str, name: &str) -> Option<(String, String, u8)> {
    let z = |prefix: &str, label: &str, rating: u8| {
        (
            sanitize_id(&format!("tz-{prefix}-{name}")),
            format!("{label}: {name}"),
            rating,
        )
    };
    match rtype {
        "google_compute_network" | "aws_vpc" | "azurerm_virtual_network" => {
            Some(z("net", "VPC", 75))
        }
        "google_compute_subnetwork" | "aws_subnet" | "azurerm_subnet" => {
            Some(z("subnet", "Subnet", 72))
        }
        "google_container_cluster" | "aws_eks_cluster" | "azurerm_kubernetes_cluster" => {
            Some(z("cluster", "Cluster (internal)", 72))
        }
        _ => None,
    }
}

fn is_cluster(rtype: &str) -> bool {
    matches!(
        rtype,
        "google_container_cluster" | "aws_eks_cluster" | "azurerm_kubernetes_cluster"
    )
}

/// A datastore reachable from the public internet (public IP / public access).
fn datastore_public(rtype: &str, a: Attrs) -> bool {
    match rtype {
        "google_sql_database_instance" => {
            a.nested("settings")
                .and_then(|s| s.nested("ip_configuration"))
                .and_then(|c| c.get_bool("ipv4_enabled"))
                == Some(true)
        }
        "aws_db_instance" | "aws_rds_cluster_instance" => {
            a.get_bool("publicly_accessible") == Some(true)
        }
        "google_storage_bucket" => a.get_str("public_access_prevention") == Some("inherited"),
        _ => false,
    }
}

/// Whether a datastore has encryption at rest. GCP and Azure encrypt every
/// managed store with provider keys by default, so absence is only meaningful on
/// AWS (where `storage_encrypted`/SSE is opt-in) or when an explicit key is set.
fn datastore_encrypted(rtype: &str, a: Attrs) -> bool {
    if rtype.starts_with("google_") || rtype.starts_with("azurerm_") {
        return true;
    }
    a.has("kms_key_name")
        || a.has("kms_key_id")
        || a.get_bool("storage_encrypted") == Some(true)
        || a.nested("server_side_encryption_configuration").is_some()
        || a.nested("encryption_configuration").is_some()
}

/// True when a backend service has IAP switched on (`iap { enabled = true }`).
/// A bare `iap {}` also counts — its presence signals intent; `enabled = false`
/// does not. Only backend-service resources carry the gate.
/// True when a backend service has a Cloud Armor policy attached (`security_policy`
/// set) — the WAF fronts that HTTPS backend.
fn cloud_armor_attached(rtype: &str, a: Attrs) -> bool {
    matches!(
        rtype,
        "google_compute_backend_service" | "google_compute_region_backend_service"
    ) && a.get_str("security_policy").is_some_and(|s| !s.is_empty())
}

fn iap_enabled(rtype: &str, a: Attrs) -> bool {
    if !matches!(
        rtype,
        "google_compute_backend_service" | "google_compute_region_backend_service"
    ) {
        return false;
    }
    match a.nested("iap") {
        Some(iap) => iap.get_bool("enabled") != Some(false),
        None => false,
    }
}

fn label_str(l: &hcl::BlockLabel) -> &str {
    l.as_str()
}

fn attr<'a>(body: &'a Body, key: &str) -> Option<&'a Expression> {
    body.iter().find_map(|s| match s {
        Structure::Attribute(a) if a.key.as_str() == key => Some(&a.expr),
        _ => None,
    })
}

fn attr_bool(body: &Body, key: &str) -> Option<bool> {
    match attr(body, key)? {
        Expression::Bool(b) => Some(*b),
        _ => None,
    }
}

fn attr_str<'a>(body: &'a Body, key: &str) -> Option<&'a str> {
    match attr(body, key)? {
        Expression::String(s) => Some(s.as_str()),
        _ => None,
    }
}

fn nested_body<'a>(body: &'a Body, block_id: &str) -> Option<&'a Body> {
    body.iter().find_map(|s| match s {
        Structure::Block(b) if b.identifier.as_str() == block_id => Some(b.body()),
        _ => None,
    })
}

/// A resource's attributes, from HCL (`resource {}` body) or plan-JSON (`values`).
/// Lets the exposure predicates read either backend uniformly, so the HCL and
/// plan-JSON importers can never drift apart.
#[derive(Clone, Copy)]
enum Attrs<'a> {
    Hcl(&'a Body),
    Json(&'a serde_json::Value),
}

impl<'a> Attrs<'a> {
    fn get_str(self, key: &str) -> Option<&'a str> {
        match self {
            Attrs::Hcl(b) => attr_str(b, key),
            Attrs::Json(v) => v.get(key).and_then(serde_json::Value::as_str),
        }
    }
    fn get_bool(self, key: &str) -> Option<bool> {
        match self {
            Attrs::Hcl(b) => attr_bool(b, key),
            Attrs::Json(v) => v.get(key).and_then(serde_json::Value::as_bool),
        }
    }
    fn has(self, key: &str) -> bool {
        match self {
            Attrs::Hcl(b) => attr(b, key).is_some(),
            Attrs::Json(v) => v.get(key).is_some_and(|x| !x.is_null()),
        }
    }
    /// A nested block/object by key. Plan-JSON renders a block as an array of
    /// objects (or a single object); take the first.
    fn nested(self, key: &str) -> Option<Attrs<'a>> {
        match self {
            Attrs::Hcl(b) => nested_body(b, key).map(Attrs::Hcl),
            Attrs::Json(v) => {
                let inner = v.get(key)?;
                let obj = inner.as_array().and_then(|a| a.first()).unwrap_or(inner);
                obj.is_object().then_some(Attrs::Json(obj))
            }
        }
    }
}

/// Terraform plan/state JSON (`terraform show -json`). Fully expanded — module
/// contents inlined with `module.foo.…` addresses, `count`/`for_each` resolved —
/// so nested resources are visible without descending into module sources.
#[derive(serde::Deserialize)]
struct PlanFile {
    #[serde(default)]
    planned_values: Option<StateValues>,
    /// `terraform show -json` of a state file uses `values` instead.
    #[serde(default)]
    values: Option<StateValues>,
}

#[derive(serde::Deserialize)]
struct StateValues {
    #[serde(default)]
    root_module: StateModule,
}

#[derive(serde::Deserialize, Default)]
struct StateModule {
    /// `""` for the root, `module.foo` / `module.foo.module.bar` for children.
    #[serde(default)]
    address: String,
    #[serde(default)]
    resources: Vec<StateResource>,
    #[serde(default)]
    child_modules: Vec<StateModule>,
}

#[derive(serde::Deserialize)]
struct StateResource {
    address: String,
    #[serde(rename = "type")]
    rtype: String,
    name: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    values: serde_json::Value,
}

/// Build a baseline from Terraform plan/state JSON. This is the accurate path:
/// every resource is present with its module-scoped address, so there is no
/// module blindness, no address collision, and `count`/`for_each` are expanded.
pub fn from_tfplan_json(text: &str, project_name: &str) -> Result<Otm, crate::Error> {
    let plan: PlanFile = serde_json::from_str(text)?;
    let root = plan
        .planned_values
        .or(plan.values)
        .ok_or_else(|| crate::Error::Hcl("no planned_values/values in plan JSON".into()))?;
    let mut b = Builder::default();
    walk_plan_module(&mut b, &root.root_module);
    Ok(b.build(project_name))
}

fn walk_plan_module(b: &mut Builder, m: &StateModule) {
    for r in &m.resources {
        if r.mode == "managed" {
            b.resource_from_plan(r, &m.address);
        }
    }
    for c in &m.child_modules {
        walk_plan_module(b, c);
    }
}

/// Heuristic: does this text look like Terraform plan/state JSON?
pub fn looks_like_tfplan(text: &str) -> bool {
    let head = &text[..text.len().min(4000)];
    head.contains("\"planned_values\"")
        || (head.contains("\"format_version\"") && head.contains("\"root_module\""))
        || (head.contains("\"values\"") && head.contains("\"root_module\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TF: &str = r#"
resource "aws_lb" "public" {
  internal = false
}
resource "aws_lb" "internal_only" {
  internal = true
}
resource "aws_db_instance" "main" {
  engine = "postgres"
}
resource "aws_wafv2_web_acl" "edge" {
  scope = "REGIONAL"
}
resource "google_container_cluster" "gke" {
  private_cluster_config {
    enable_private_endpoint = true
  }
}
"#;

    #[test]
    fn terraform_exposure_inventory() {
        let otm = from_terraform(TF, "cloud").unwrap();
        assert!(
            crate::validate::is_valid(&crate::validate(&otm)),
            "{:?}",
            crate::validate(&otm)
        );
        // public LB is internet-facing; internal LB is not.
        assert!(
            otm.dataflows
                .iter()
                .any(|d| d.source == EXTERNAL && d.destination.contains("public"))
        );
        assert!(
            !otm.dataflows
                .iter()
                .any(|d| d.destination.contains("internal-only"))
        );
        // database in the data tier.
        let db = otm
            .components
            .iter()
            .find(|c| c.id.contains("main"))
            .unwrap();
        assert_eq!(db.kind, "database");
        assert_eq!(
            db.parent.as_ref().unwrap().trust_zone.as_deref(),
            Some(TZ_DATA)
        );
        // WAF became a mitigation, not a component.
        assert!(otm.mitigations.iter().any(|m| m.name.contains("AWS WAF")));
        assert!(!otm.components.iter().any(|c| c.id.contains("edge")));
        // private GKE control plane → no ingress flow.
        assert!(!otm.dataflows.iter().any(|d| d.destination.contains("gke")));
    }

    const ENCRYPTED_EDGES: &str = r#"
resource "google_compute_forwarding_rule" "vpn_esp" {
  ip_protocol = "ESP"
}
resource "google_compute_global_forwarding_rule" "https_lb" {
  port_range = "443"
  target     = "google_compute_target_https_proxy.main.id"
}
resource "google_compute_global_forwarding_rule" "http_lb" {
  port_range = "80"
  target     = "google_compute_target_http_proxy.main.id"
}
resource "google_compute_backend_service" "web" {
  iap {
    enabled = true
  }
}
"#;

    #[test]
    fn vpn_and_https_edges_are_encrypted_http_is_not() {
        let otm = from_terraform(ENCRYPTED_EDGES, "cloud").unwrap();
        let flow = |needle: &str| {
            otm.dataflows
                .iter()
                .find(|d| d.destination.contains(needle))
        };
        // IPSec forwarding rule → encrypted tag.
        assert!(
            flow("vpn-esp")
                .unwrap()
                .tags
                .iter()
                .any(|t| t == "encrypted")
        );
        // HTTPS-proxy LB → tls tag; plain HTTP LB → untagged (still flagged).
        assert!(flow("https-lb").unwrap().tags.iter().any(|t| t == "tls"));
        assert!(flow("http-lb").unwrap().tags.is_empty());
    }

    #[test]
    fn networks_and_clusters_become_trust_zones() {
        let tf = r#"
resource "google_compute_network" "vpc" {}
resource "google_compute_subnetwork" "sub" {
  network = google_compute_network.vpc.id
}
resource "google_container_cluster" "gke" {
  private_cluster_config { enable_private_endpoint = true }
}
resource "google_container_node_pool" "np" {
  cluster = google_container_cluster.gke.id
}
"#;
        let otm = from_terraform(tf, "cloud").unwrap();
        assert!(crate::validate::is_valid(&crate::validate(&otm)));
        // VPC / subnet / cluster-internal are trust zones.
        let zone = |n: &str| otm.trust_zones.iter().any(|z| z.name == n);
        assert!(zone("VPC: vpc"));
        assert!(zone("Subnet: sub"));
        assert!(zone("Cluster (internal): gke"));
        // Network/subnet are zones only — no component; the cluster keeps its node.
        assert!(
            !otm.components
                .iter()
                .any(|c| c.id.contains("compute-network"))
        );
        assert!(otm.components.iter().any(|c| c.id.contains("gke")));
        // Node pool is now modeled as compute (was dropped before).
        assert!(otm.components.iter().any(|c| c.id.contains("node-pool")));
    }

    #[test]
    fn plan_json_expands_nested_module_resources() {
        // A DB lives inside module.data; an external LB at the root. Plan JSON
        // carries both with module-scoped addresses — no descent into sources.
        let plan = r#"{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [
        { "address": "aws_lb.edge", "type": "aws_lb", "name": "edge", "mode": "managed",
          "values": { "internal": false } }
      ],
      "child_modules": [
        { "address": "module.data",
          "resources": [
            { "address": "module.data.aws_db_instance.main", "type": "aws_db_instance",
              "name": "main", "mode": "managed", "values": { "engine": "postgres" } }
          ] }
      ]
    }
  }
}"#;
        let otm = from_tfplan_json(plan, "cloud").unwrap();
        assert!(crate::validate::is_valid(&crate::validate(&otm)));
        // The module-nested database is present, in the data tier.
        let db = otm
            .components
            .iter()
            .find(|c| c.name == "module.data.aws_db_instance.main")
            .expect("nested module resource surfaced");
        assert_eq!(db.kind, "database");
        assert_eq!(
            db.parent.as_ref().unwrap().trust_zone.as_deref(),
            Some(TZ_DATA)
        );
        // Tagged with its module so clients can group by it.
        assert_eq!(
            db.attributes.get("module").map(String::as_str),
            Some("module.data")
        );
        // The root LB is internet-facing.
        assert!(otm.dataflows.iter().any(|d| d.source == EXTERNAL));
        assert!(looks_like_tfplan(plan));
    }

    #[test]
    fn cloud_armor_attachment_links_waf_to_https_edges() {
        let tf = r#"
resource "google_compute_global_forwarding_rule" "https" {
  port_range = "443"
  target     = "google_compute_target_https_proxy.main.id"
}
resource "google_compute_backend_service" "web" {
  security_policy = "google_compute_security_policy.armor.id"
}
"#;
        let otm = from_terraform(tf, "cloud").unwrap();
        let armor = otm
            .mitigations
            .iter()
            .find(|m| m.id == "cloud-armor")
            .expect("Cloud Armor mitigation emitted");
        assert_eq!(armor.risk_reduction, Some(50));
        assert!(armor.addresses.iter().any(|r| r == "WYRM-T003"));
        assert!(armor.applies_to.iter().any(|t| t.contains("https")));
    }

    #[test]
    fn iap_backend_emits_auth_gate_on_https_edges() {
        let otm = from_terraform(ENCRYPTED_EDGES, "cloud").unwrap();
        let iap = otm
            .mitigations
            .iter()
            .find(|m| m.id == "iap-auth-gate")
            .expect("IAP mitigation emitted");
        assert_eq!(iap.risk_reduction, Some(80));
        assert!(iap.addresses.iter().any(|r| r == "WYRM-T005"));
        // Linked to the HTTPS edge (component + flow), not the HTTP or VPN one.
        assert!(iap.applies_to.iter().any(|t| t.contains("https-lb")));
        assert!(!iap.applies_to.iter().any(|t| t.contains("http-lb")));
    }

    #[test]
    fn scoped_docs_qualify_only_colliding_ids() {
        // Same resource name in two env modules must not clobber; a name unique
        // to one scope stays clean.
        let prod = r#"
resource "aws_db_instance" "main" { engine = "postgres" }
resource "aws_s3_bucket" "prod_only" {}
"#;
        let dev = r#"resource "aws_db_instance" "main" { engine = "postgres" }"#;
        let docs = vec![
            ("envs/prod".to_string(), prod.to_string()),
            ("envs/dev".to_string(), dev.to_string()),
        ];
        let (otm, skipped) = from_terraform_scoped(&docs, "cloud");
        assert_eq!(skipped, 0);
        let ids: Vec<&str> = otm.components.iter().map(|c| c.id.as_str()).collect();
        // The collision is disambiguated per scope — both survive.
        assert!(ids.contains(&"envs-prod-aws-db-instance-main"), "{ids:?}");
        assert!(ids.contains(&"envs-dev-aws-db-instance-main"), "{ids:?}");
        // The unique bucket keeps its clean, unqualified id.
        assert!(ids.contains(&"aws-s3-bucket-prod-only"), "{ids:?}");
        assert!(crate::validate::is_valid(&crate::validate(&otm)));
    }

    #[test]
    fn scoped_docs_without_collision_stay_unqualified() {
        // No cross-scope duplicate → ids are identical to the flat-walk output.
        let docs = vec![
            (
                "net".to_string(),
                r#"resource "aws_lb" "public" { internal = false }"#.to_string(),
            ),
            (
                "data".to_string(),
                r#"resource "aws_db_instance" "main" { engine = "postgres" }"#.to_string(),
            ),
        ];
        let (otm, _) = from_terraform_scoped(&docs, "cloud");
        let ids: Vec<&str> = otm.components.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"aws-lb-public"), "{ids:?}");
        assert!(ids.contains(&"aws-db-instance-main"), "{ids:?}");
    }
}
