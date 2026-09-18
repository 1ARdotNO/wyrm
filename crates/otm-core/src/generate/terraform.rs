//! Baseline model from Terraform (HCL).
//!
//! Terraform describes *resources*, not flows, so this importer is an exposure
//! inventory: each notable resource becomes a component (load balancers/APIs/
//! gateways that are internet-facing get an ingress dataflow; datastores land in
//! a data tier), and edge controls (WAF/Cloud Armor/DDoS) become mitigations.
//! Internal service-to-service flows aren't inferable from HCL without resolving
//! references, so they're left for review. See `docs/DETECTION.md`.

use super::*;
use crate::model::{Component, Dataflow, Mitigation, Otm, Parent, Project};
use hcl::{Body, Expression, Structure};
use std::collections::BTreeSet;

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
                    b.resource(rtype, rname, bl.body());
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
    components: std::collections::BTreeMap<String, Component>,
    dataflows: Vec<Dataflow>,
    mitigations: Vec<Mitigation>,
    has_edge: bool,
    has_db: bool,
}

impl Builder {
    /// A module call becomes a component; its type is inferred from name + source.
    fn module(&mut self, name: &str, source: &str) {
        let id = sanitize_id(&format!("module-{name}"));
        let kind = module_type(name, source);
        let store = is_datastore(kind);
        self.has_db |= store;
        self.put(
            &id,
            &format!("module.{name}"),
            kind,
            if store { TZ_DATA } else { TZ_INTERNAL },
        );
    }

    fn resource(&mut self, rtype: &str, rname: &str, body: &Body) {
        let id = sanitize_id(&format!("{rtype}-{rname}"));
        let display = format!("{rtype}.{rname}");

        // Edge controls attach nowhere specific here — record them as mitigations.
        if let Some(control) = mitigation_for(rtype) {
            self.mitigations.push(Mitigation {
                id: id.clone(),
                name: format!("{control} ({rname})"),
                description: None,
                risk_reduction: None,
            });
            return;
        }

        match classify(rtype) {
            Some(Kind::Datastore(k)) => {
                self.has_db = true;
                self.put(&id, &display, k, TZ_DATA);
            }
            Some(Kind::Compute) => self.put(&id, &display, "process", TZ_INTERNAL),
            Some(Kind::Edge) => {
                self.put(&id, &display, "web-service", TZ_INTERNAL);
                if is_internet_facing(rtype, body) {
                    self.ingress(&id, &display);
                }
            }
            None => {}
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

    fn ingress(&mut self, id: &str, name: &str) {
        self.has_edge = true;
        self.dataflows.push(Dataflow {
            id: format!("df-ingress-{id}"),
            name: format!("external request to {name}"),
            source: EXTERNAL.to_string(),
            destination: id.to_string(),
            assets: Vec::new(),
            attributes: Default::default(),
            tags: Vec::new(),
        });
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
        "google_firestore_database",
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
        "azurerm_lb",
        "azurerm_application_gateway",
    ];
    const COMPUTE: &[&str] = &[
        "aws_instance",
        "aws_ecs_service",
        "aws_lambda_function",
        "google_compute_instance",
        "google_cloud_run_service",
        "google_cloud_run_v2_service",
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
        "azurerm_web_application_firewall_policy" => Some("Azure WAF"),
        "azurerm_network_ddos_protection_plan" => Some("Azure DDoS Protection"),
        _ => None,
    }
}

/// Provider defaults favour exposure — treat "attribute absent" as internet-facing.
fn is_internet_facing(rtype: &str, body: &Body) -> bool {
    match rtype {
        "aws_lb" | "aws_alb" | "aws_elb" => attr_bool(body, "internal") != Some(true),
        "aws_apigatewayv2_api" => attr_bool(body, "disable_execute_api_endpoint") != Some(true),
        "aws_api_gateway_rest_api" => true,
        "google_compute_global_forwarding_rule" | "google_compute_forwarding_rule" => {
            attr_str(body, "load_balancing_scheme").is_none_or(|s| s.starts_with("EXTERNAL"))
        }
        "google_container_cluster" => {
            // Public control plane unless explicitly private.
            nested_attr_bool(body, "private_cluster_config", "enable_private_endpoint")
                != Some(true)
        }
        "azurerm_lb" | "azurerm_application_gateway" => {
            nested_has_attr(body, "frontend_ip_configuration", "public_ip_address_id")
        }
        _ => false,
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

fn nested_attr_bool(body: &Body, block_id: &str, key: &str) -> Option<bool> {
    attr_bool(nested_body(body, block_id)?, key)
}

fn nested_has_attr(body: &Body, block_id: &str, key: &str) -> bool {
    nested_body(body, block_id)
        .and_then(|b| attr(b, key))
        .is_some()
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
}
