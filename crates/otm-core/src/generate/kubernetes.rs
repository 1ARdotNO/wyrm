//! Baseline model from Kubernetes (and Istio) manifests.
//!
//! Services become components (type inferred from well-known ports); a Service of
//! type LoadBalancer/NodePort, an Ingress, or a public Istio Gateway becomes an
//! internet boundary crossing; Ingress backends and Istio VirtualService routes
//! become internal dataflows. TLS on an Ingress/Gateway tags the flow encrypted.

use super::*;
use crate::model::{Component, Dataflow, Mitigation, Otm, Parent, Project};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

type Yaml = serde_yaml_ng::Value;

#[derive(Deserialize, Default)]
struct Resource {
    #[serde(rename = "apiVersion", default)]
    api_version: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    metadata: Meta,
    #[serde(default)]
    spec: Yaml,
}

#[derive(Deserialize, Default)]
struct Meta {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

/// Build a baseline [`Otm`] from one or more Kubernetes/Istio manifests (a
/// multi-document YAML stream).
pub fn from_manifests(yaml: &str, project_name: &str) -> Result<Otm, crate::Error> {
    let mut resources = Vec::new();
    for document in serde_yaml_ng::Deserializer::from_str(yaml) {
        if let Ok(r) = Resource::deserialize(document) {
            resources.push(r);
        }
    }

    let mut b = Builder::default();
    // Services first so they're authoritative before ingress/routes stub anything.
    for r in resources
        .iter()
        .filter(|r| r.kind.as_deref() == Some("Service"))
    {
        b.service(r);
    }
    for r in resources
        .iter()
        .filter(|r| r.kind.as_deref() == Some("Ingress"))
    {
        b.ingress(r);
    }
    for r in resources
        .iter()
        .filter(|r| r.kind.as_deref() == Some("Gateway") && is_istio(r))
    {
        b.gateway(r);
    }
    for r in resources
        .iter()
        .filter(|r| r.kind.as_deref() == Some("VirtualService"))
    {
        b.virtual_service(r);
    }

    // GKE IAP: a Service referencing a BackendConfig with `iap.enabled: true` is
    // fronted by the Google-managed auth gate. Correlate and link the mitigation.
    let iap_configs: BTreeSet<String> = resources
        .iter()
        .filter(|r| r.kind.as_deref() == Some("BackendConfig"))
        .filter(|r| {
            r.spec
                .get("iap")
                .and_then(|i| i.get("enabled"))
                .and_then(Yaml::as_bool)
                == Some(true)
        })
        .filter_map(|r| r.metadata.name.clone())
        .collect();
    if !iap_configs.is_empty() {
        for r in resources
            .iter()
            .filter(|r| r.kind.as_deref() == Some("Service"))
        {
            if let Some(name) = &r.metadata.name {
                if backend_config_refs(&r.metadata.annotations)
                    .iter()
                    .any(|c| iap_configs.contains(c))
                {
                    b.iap_gate(&sanitize_id(name));
                }
            }
        }
    }

    // Kubernetes/Istio-native controls become mitigations that downgrade findings —
    // the mesh/namespace is treated as covering the workloads it governs.
    let istio = |r: &Resource, kind: &str| {
        r.kind.as_deref() == Some(kind)
            && r.api_version
                .as_deref()
                .is_some_and(|a| a.contains("istio.io"))
    };
    b.set_controls(Controls {
        mtls_strict: resources.iter().any(|r| {
            istio(r, "PeerAuthentication")
                && r.spec
                    .get("mtls")
                    .and_then(|m| m.get("mode"))
                    .and_then(Yaml::as_str)
                    == Some("STRICT")
        }),
        authz: resources.iter().any(|r| istio(r, "AuthorizationPolicy")),
        default_deny: resources
            .iter()
            .any(|r| r.kind.as_deref() == Some("NetworkPolicy") && is_default_deny(&r.spec)),
        egress: resources.iter().any(|r| {
            matches!(
                r.kind.as_deref(),
                Some("FQDNNetworkPolicy") | Some("CiliumNetworkPolicy")
            ) || (r.kind.as_deref() == Some("NetworkPolicy") && has_policy_type(&r.spec, "Egress"))
        }),
    });

    Ok(b.build(project_name))
}

/// A default-deny NetworkPolicy: selects every pod (`podSelector: {}`) and admits
/// no ingress — the baseline that turns a namespace from allow-all to deny-all.
fn is_default_deny(spec: &Yaml) -> bool {
    let selects_all = spec
        .get("podSelector")
        .and_then(Yaml::as_mapping)
        .is_some_and(|m| m.is_empty());
    let no_ingress = spec
        .get("ingress")
        .and_then(Yaml::as_sequence)
        .is_none_or(|s| s.is_empty());
    selects_all && has_policy_type(spec, "Ingress") && no_ingress
}

fn has_policy_type(spec: &Yaml, t: &str) -> bool {
    spec.get("policyTypes")
        .and_then(Yaml::as_sequence)
        .is_some_and(|s| s.iter().any(|v| v.as_str() == Some(t)))
}

/// Which Kubernetes/Istio-native controls the manifests declare.
#[derive(Default)]
struct Controls {
    mtls_strict: bool,
    authz: bool,
    default_deny: bool,
    egress: bool,
}

#[derive(Default)]
struct Builder {
    components: BTreeMap<String, Component>,
    dataflows: Vec<Dataflow>,
    mitigations: Vec<Mitigation>,
    has_edge: bool,
    has_db: bool,
    controls: Controls,
}

impl Builder {
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

    /// Link an IAP auth-gate mitigation to a service (and its ingress flow, if any).
    fn set_controls(&mut self, c: Controls) {
        self.controls = c;
    }

    /// Emit mitigations for the mesh/namespace-wide Kubernetes controls found, each
    /// linked to the workloads (and, for mTLS, the internal flows) it governs.
    fn emit_controls(&mut self, comp_ids: &[String]) {
        let internal_flows: Vec<String> = self
            .dataflows
            .iter()
            .filter(|d| d.source != EXTERNAL)
            .map(|d| d.id.clone())
            .collect();
        if self.controls.default_deny {
            self.mitigations.push(Mitigation {
                id: "k8s-network-policy".to_string(),
                name: "Default-deny NetworkPolicy (namespace isolation)".to_string(),
                description: Some("A default-deny NetworkPolicy restricts pod-to-pod and ingress reachability, limiting lateral movement and unsolicited access.".to_string()),
                risk_reduction: Some(40),
                applies_to: comp_ids.to_vec(),
                addresses: vec!["WYRM-T003".to_string(), "WYRM-T008".to_string()],
            });
        }
        if self.controls.authz {
            self.mitigations.push(Mitigation {
                id: "istio-authz".to_string(),
                name: "Istio AuthorizationPolicy (service authorization)".to_string(),
                description: Some("Istio AuthorizationPolicy enforces request-level authorization between workloads.".to_string()),
                risk_reduction: Some(60),
                applies_to: comp_ids.to_vec(),
                addresses: vec!["WYRM-T005".to_string(), "WYRM-T008".to_string()],
            });
        }
        if self.controls.mtls_strict {
            let mut applies = comp_ids.to_vec();
            applies.extend(internal_flows);
            self.mitigations.push(Mitigation {
                id: "istio-mtls-strict".to_string(),
                name: "Istio mutual TLS (STRICT)".to_string(),
                description: Some("STRICT PeerAuthentication requires mutual TLS for all service-to-service traffic — mutually authenticated and encrypted in transit.".to_string()),
                risk_reduction: Some(70),
                applies_to: applies,
                addresses: vec!["WYRM-T002".to_string(), "WYRM-T004".to_string(), "WYRM-T005".to_string()],
            });
        }
        if self.controls.egress {
            // No egress/exfiltration rule yet — record it as a documentary control.
            self.mitigations.push(Mitigation {
                id: "k8s-egress-policy".to_string(),
                name: "Egress network policy (FQDN/CIDR restriction)".to_string(),
                description: Some("Egress NetworkPolicy / FQDNNetworkPolicy restricts outbound destinations, limiting data exfiltration and command-and-control paths.".to_string()),
                risk_reduction: None,
                applies_to: Vec::new(),
                addresses: Vec::new(),
            });
        }
    }

    fn iap_gate(&mut self, service_id: &str) {
        let flow = format!("df-ingress-{service_id}");
        let mut applies_to = vec![service_id.to_string()];
        if self.dataflows.iter().any(|d| d.id == flow) {
            applies_to.push(flow);
        }
        self.mitigations.push(Mitigation {
            id: format!("iap-{service_id}"),
            name: "Identity-Aware Proxy (Google-managed auth gate)".to_string(),
            description: Some(
                "IAP blocks the backend until the caller is authenticated and holds roles/iap.httpsResourceAccessor. Verify the binding is not allUsers/allAuthenticatedUsers."
                    .to_string(),
            ),
            risk_reduction: Some(80),
            applies_to,
            addresses: vec!["WYRM-T003".to_string(), "WYRM-T005".to_string()],
        });
    }

    /// Add a placeholder for a referenced-but-undefined service.
    fn stub(&mut self, id: &str) {
        if !self.components.contains_key(id) {
            self.put(id, id, "process", TZ_INTERNAL);
        }
    }

    fn ingress_flow(&mut self, id: &str, name: &str, tags: Vec<String>) {
        self.has_edge = true;
        self.dataflows.push(Dataflow {
            id: format!("df-ingress-{id}"),
            name: format!("external request to {name}"),
            source: EXTERNAL.to_string(),
            destination: id.to_string(),
            assets: Vec::new(),
            attributes: Default::default(),
            tags,
        });
    }

    fn service(&mut self, r: &Resource) {
        let Some(name) = r.metadata.name.clone() else {
            return;
        };
        let id = sanitize_id(&name);
        let ports = collect_ports(&r.spec);
        let kind = classify_ports(&ports).unwrap_or("web-service");
        let is_store = is_datastore(kind);
        self.has_db |= is_store;
        let zone_id = if is_store { TZ_DATA } else { TZ_INTERNAL };
        self.put(&id, &name, kind, zone_id);

        let stype = r
            .spec
            .get("type")
            .and_then(Yaml::as_str)
            .unwrap_or("ClusterIP");
        let internal_lb = r
            .metadata
            .annotations
            .iter()
            .any(|(k, v)| k.contains("load-balancer-internal") && v == "true");
        if matches!(stype, "LoadBalancer" | "NodePort") && !internal_lb {
            let mut tags = Vec::new();
            let restricted = r
                .spec
                .get("loadBalancerSourceRanges")
                .and_then(Yaml::as_sequence)
                .is_some_and(|s| !s.is_empty());
            if restricted {
                tags.push("source-range-allowlist".to_string());
            }
            self.ingress_flow(&id, &name, tags);
        }
    }

    fn ingress(&mut self, r: &Resource) {
        let Some(name) = r.metadata.name.clone() else {
            return;
        };
        let id = sanitize_id(&name);
        self.put(&id, &name, "web-service", TZ_INTERNAL);

        let tls = r
            .spec
            .get("tls")
            .and_then(Yaml::as_sequence)
            .is_some_and(|s| !s.is_empty());
        let ingress_tags = if tls {
            vec!["tls".to_string()]
        } else {
            Vec::new()
        };
        self.ingress_flow(&id, &name, ingress_tags);

        for backend in ingress_backends(&r.spec) {
            let dest = sanitize_id(&backend);
            self.stub(&dest);
            self.dataflows.push(Dataflow {
                id: format!("df-{id}-{dest}"),
                name: format!("{name} → {backend}"),
                source: id.clone(),
                destination: dest,
                assets: Vec::new(),
                attributes: Default::default(),
                tags: Vec::new(),
            });
        }
    }

    fn gateway(&mut self, r: &Resource) {
        // Only public ingress gateways are an internet edge.
        let public = match r.spec.get("selector").and_then(Yaml::as_mapping) {
            Some(sel) => sel
                .values()
                .any(|v| v.as_str().is_some_and(|s| s.contains("ingressgateway"))),
            None => true,
        };
        if !public {
            return;
        }
        let Some(name) = r.metadata.name.clone() else {
            return;
        };
        let id = sanitize_id(&name);
        self.put(&id, &name, "web-service", TZ_INTERNAL);
        let tls = gateway_has_tls(&r.spec);
        let tags = if tls {
            vec!["tls".to_string()]
        } else {
            Vec::new()
        };
        self.ingress_flow(&id, &name, tags);
    }

    fn virtual_service(&mut self, r: &Resource) {
        let gateways: Vec<String> = r
            .spec
            .get("gateways")
            .and_then(Yaml::as_sequence)
            .map(|s| {
                s.iter()
                    .filter_map(Yaml::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        for gw in gateways.iter().filter(|g| g.as_str() != "mesh") {
            let gw_id = sanitize_id(gw.rsplit('/').next().unwrap_or(gw));
            self.stub(&gw_id);
            for host in vs_destinations(&r.spec) {
                let dest = sanitize_id(host_to_service(&host));
                self.stub(&dest);
                self.dataflows.push(Dataflow {
                    id: format!("df-{gw_id}-{dest}"),
                    name: format!("{gw_id} → {dest}"),
                    source: gw_id.clone(),
                    destination: dest,
                    assets: Vec::new(),
                    attributes: Default::default(),
                    tags: Vec::new(),
                });
            }
        }
    }

    fn build(mut self, project_name: &str) -> Otm {
        // Mesh/namespace-wide controls cover the workloads they govern — emit before
        // moving `components` out of `self`.
        let comp_ids: Vec<String> = self.components.keys().cloned().collect();
        self.emit_controls(&comp_ids);

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

        // A VirtualService can restate a route — dedup dataflows by id, and drop
        // self-loops (an Ingress whose backend sanitizes to its own id).
        let mut seen = BTreeSet::new();
        self.dataflows
            .retain(|d| d.source != d.destination && seen.insert(d.id.clone()));

        components.sort_by(|a, b| a.id.cmp(&b.id));
        self.dataflows.sort_by(|a, b| a.id.cmp(&b.id));

        Otm {
            otm_version: "0.2.0".to_string(),
            project: Project {
                id: sanitize_id(project_name),
                name: project_name.to_string(),
                owner: None,
                description: Some("Baseline generated by `wyrm init` from Kubernetes manifests — review zones and add asset sensitivity.".to_string()),
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

/// Service names of the BackendConfigs a Service's `cloud.google.com/backend-config`
/// annotation points at (shapes: `{"default":"cfg"}` and `{"ports":{"80":"cfg"}}`).
fn backend_config_refs(annotations: &BTreeMap<String, String>) -> Vec<String> {
    let Some(raw) = annotations.get("cloud.google.com/backend-config") else {
        return Vec::new();
    };
    let Ok(v) = serde_yaml_ng::from_str::<Yaml>(raw) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(def) = v.get("default").and_then(Yaml::as_str) {
        out.push(def.to_string());
    }
    if let Some(ports) = v.get("ports").and_then(Yaml::as_mapping) {
        out.extend(ports.values().filter_map(Yaml::as_str).map(str::to_string));
    }
    out
}

fn is_istio(r: &Resource) -> bool {
    r.api_version
        .as_deref()
        .is_some_and(|v| v.contains("istio.io"))
}

fn collect_ports(spec: &Yaml) -> Vec<u64> {
    spec.get("ports")
        .and_then(Yaml::as_sequence)
        .map(|s| {
            s.iter()
                .filter_map(|p| p.get("port").and_then(Yaml::as_u64))
                .collect()
        })
        .unwrap_or_default()
}

/// Classify a service by a well-known port, if any.
fn classify_ports(ports: &[u64]) -> Option<&'static str> {
    ports.iter().find_map(|p| match p {
        5432 | 3306 | 1433 | 1521 | 27017 => Some("database"),
        6379 | 11211 | 9200 | 9300 => Some("data-store"),
        5672 | 15672 | 9092 | 4222 => Some("message-queue"),
        _ => None,
    })
}

fn ingress_backends(spec: &Yaml) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(n) = backend_service_name(spec.get("defaultBackend")) {
        out.push(n);
    }
    if let Some(rules) = spec.get("rules").and_then(Yaml::as_sequence) {
        for rule in rules {
            let paths = rule
                .get("http")
                .and_then(|h| h.get("paths"))
                .and_then(Yaml::as_sequence);
            for path in paths.into_iter().flatten() {
                if let Some(n) = backend_service_name(path.get("backend")) {
                    out.push(n);
                }
            }
        }
    }
    out
}

fn backend_service_name(backend: Option<&Yaml>) -> Option<String> {
    let b = backend?;
    // networking.k8s.io/v1: backend.service.name; legacy: backend.serviceName.
    b.get("service")
        .and_then(|s| s.get("name"))
        .and_then(Yaml::as_str)
        .or_else(|| b.get("serviceName").and_then(Yaml::as_str))
        .map(str::to_string)
}

fn gateway_has_tls(spec: &Yaml) -> bool {
    spec.get("servers")
        .and_then(Yaml::as_sequence)
        .is_some_and(|servers| servers.iter().any(|s| s.get("tls").is_some()))
}

fn vs_destinations(spec: &Yaml) -> Vec<String> {
    let mut out = Vec::new();
    for proto in ["http", "tcp", "tls"] {
        for rule in spec
            .get(proto)
            .and_then(Yaml::as_sequence)
            .into_iter()
            .flatten()
        {
            for route in rule
                .get("route")
                .and_then(Yaml::as_sequence)
                .into_iter()
                .flatten()
            {
                if let Some(h) = route
                    .get("destination")
                    .and_then(|d| d.get("host"))
                    .and_then(Yaml::as_str)
                {
                    out.push(h.to_string());
                }
            }
        }
    }
    out
}

/// `reviews.default.svc.cluster.local` → `reviews`.
fn host_to_service(host: &str) -> &str {
    host.split('.').next().unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFESTS: &str = r#"
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  type: LoadBalancer
  ports: [{ port: 80, targetPort: 8080 }]
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: ClusterIP
  ports: [{ port: 8080 }]
---
apiVersion: v1
kind: Service
metadata:
  name: db
spec:
  type: ClusterIP
  ports: [{ port: 5432 }]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: shop-ingress
spec:
  tls: [{ hosts: ["shop.example.com"] }]
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            backend:
              service:
                name: api
"#;

    #[test]
    fn services_and_ingress_build_a_valid_baseline() {
        let otm = from_manifests(MANIFESTS, "shop").unwrap();
        assert!(
            crate::validate::is_valid(&crate::validate(&otm)),
            "{:?}",
            crate::validate(&otm)
        );
        // web, api, db, shop-ingress + external client.
        assert_eq!(otm.component("db").unwrap().kind, "database");
        assert_eq!(otm.trust_zone_of("db"), Some(TZ_DATA));
        // LoadBalancer service is internet-facing.
        assert!(
            otm.dataflows
                .iter()
                .any(|d| d.source == EXTERNAL && d.destination == "web")
        );
        // Ingress edge + TLS-tagged ingress flow + route to api.
        let ing = otm
            .dataflows
            .iter()
            .find(|d| d.destination == "shop-ingress")
            .unwrap();
        assert!(ing.tags.iter().any(|t| t == "tls"));
        assert!(
            otm.dataflows
                .iter()
                .any(|d| d.source == "shop-ingress" && d.destination == "api")
        );
    }

    #[test]
    fn istio_gateway_and_virtualservice_route() {
        let manifests = r#"
apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: public-gw
spec:
  selector: { istio: ingressgateway }
  servers:
    - port: { number: 443, name: https, protocol: HTTPS }
      tls: { mode: SIMPLE }
      hosts: ["*"]
---
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: reviews-route
spec:
  hosts: ["reviews.example.com"]
  gateways: ["public-gw"]
  http:
    - route:
        - destination:
            host: reviews.default.svc.cluster.local
"#;
        let otm = from_manifests(manifests, "mesh").unwrap();
        assert!(crate::validate::is_valid(&crate::validate(&otm)));
        // Gateway is an internet edge, TLS-terminated.
        let edge = otm.dataflows.iter().find(|d| d.source == EXTERNAL).unwrap();
        assert_eq!(edge.destination, "public-gw");
        assert!(edge.tags.iter().any(|t| t == "tls"));
        // VirtualService routes gateway -> reviews.
        assert!(
            otm.dataflows
                .iter()
                .any(|d| d.source == "public-gw" && d.destination == "reviews")
        );
    }

    #[test]
    fn backendconfig_iap_links_auth_gate_to_service() {
        let manifests = r#"
apiVersion: cloud.google.com/v1
kind: BackendConfig
metadata:
  name: iap-config
spec:
  iap:
    enabled: true
    oauth2ClientSecret: { secretName: my-secret }
---
apiVersion: v1
kind: Service
metadata:
  name: web
  annotations:
    cloud.google.com/backend-config: '{"default":"iap-config"}'
spec:
  type: NodePort
  ports: [{ port: 8080 }]
"#;
        let otm = from_manifests(manifests, "gke").unwrap();
        let iap = otm
            .mitigations
            .iter()
            .find(|m| m.id == "iap-web")
            .expect("IAP mitigation for the gated service");
        assert_eq!(iap.risk_reduction, Some(80));
        assert!(iap.applies_to.iter().any(|t| t == "web"));
        assert!(iap.applies_to.iter().any(|t| t == "df-ingress-web"));
    }

    #[test]
    fn native_controls_become_linked_mitigations() {
        let manifests = r#"
apiVersion: v1
kind: Service
metadata: { name: api }
spec: { type: LoadBalancer, ports: [{ port: 443 }] }
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny }
spec:
  podSelector: {}
  policyTypes: [Ingress]
---
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata: { name: mesh-mtls }
spec: { mtls: { mode: STRICT } }
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: { name: allow-nothing }
spec: {}
"#;
        let otm = from_manifests(manifests, "mesh").unwrap();
        let mit = |id: &str| otm.mitigations.iter().find(|m| m.id == id);
        let np = mit("k8s-network-policy").expect("default-deny NetworkPolicy mitigation");
        assert!(np.applies_to.iter().any(|t| t == "api"));
        assert!(np.addresses.iter().any(|r| r == "WYRM-T008"));
        let mtls = mit("istio-mtls-strict").expect("STRICT mTLS mitigation");
        assert_eq!(mtls.risk_reduction, Some(70));
        assert!(mit("istio-authz").is_some());
    }

    #[test]
    fn permissive_mtls_is_not_a_mitigation() {
        // Only STRICT PeerAuthentication counts; PERMISSIVE must not.
        let manifests = r#"
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata: { name: perm }
spec: { mtls: { mode: PERMISSIVE } }
"#;
        let otm = from_manifests(manifests, "mesh").unwrap();
        assert!(!otm.mitigations.iter().any(|m| m.id == "istio-mtls-strict"));
    }
}
