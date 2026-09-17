# Infrastructure detection matrix

How `wyrm init` maps infrastructure-as-code to Open Threat Model elements. Two
rules of thumb, learned the hard way from provider defaults:

1. **Defaults favor exposure.** `aws_lb.internal` defaults to `false`; GKE treats
   an absent `private_cluster_config` as public. Treat *attribute absent* as
   **internet-facing**, never "unknown."
2. **A WAF/IAP/mTLS is a `mitigation`, not a component.** It attaches to the
   ingress dataflow and *downgrades* the exposed-endpoint finding — carrying
   `mode` (block vs log) and coverage. It never erases the finding.

OTM targets: `component` (a service/resource), `trustZone` (boundary, trustRating
0–100; internet≈10, private≈80), `dataflow` (source→dest), `mitigation` (control).

## Implementation order (highest confidence, single-attribute first)

1. K8s `Service.spec.type ∈ {LoadBalancer, NodePort}` → external. *(shipped)*
2. K8s `Ingress` (any) → external HTTP entrypoint. *(shipped)*
3. Istio `Gateway` (public ingress selector) + `VirtualService` routing. *(shipped)*
4. `aws_lb.internal == false` (or absent) → internet LB.
5. GCP `google_compute_(global_)forwarding_rule.load_balancing_scheme` starts `EXTERNAL` → internet LB.
6. GKE `private_cluster_config.enable_private_endpoint` absent/false → public control plane.
7. Azure `frontend_ip_configuration.public_ip_address_id` present → public frontend.
8. `aws_security_group` ingress `cidr_blocks` contains `0.0.0.0/0` → world-open.

## Kubernetes / Istio

| Signal | OTM | Internet-facing? |
|---|---|---|
| `Service.spec.type` LoadBalancer / NodePort | component + ingress dataflow | yes |
| `Service.spec.type` ClusterIP / ExternalName | component (internal) | no |
| `Service` well-known port (5432/3306/6379/27017/…) | classify as database / data-store | — |
| `Service.spec.loadBalancerSourceRanges` | mitigation (source-IP allowlist) | narrows |
| internal-LB annotation (`*-load-balancer-internal: "true"`) | downgrade to private zone | no |
| `Ingress` (+ `spec.rules[].backend.service`) | edge component + dataflow per backend | yes |
| `Ingress.spec.tls[]` | mitigation → tag flow `tls` | — |
| Istio `Gateway` (public `istio: ingressgateway` selector) | edge component + ingress dataflow | yes |
| Istio `Gateway.servers[].tls.mode` (SIMPLE/MUTUAL/PASSTHROUGH) | mitigation (MUTUAL = mTLS) | — |
| Istio `VirtualService` (`gateways` + `http[].route.destination.host`) | dataflow gateway→destination | inherits |
| Istio `AuthorizationPolicy.action`, `PeerAuthentication.mtls.mode=STRICT` | mitigation | no |
| `NetworkPolicy` (empty `podSelector`, policyTypes) | trust boundary / default-deny | no |

## CNI / overlay networking (informational)

The CNI decides whether `NetworkPolicy` is even enforced — a boundary you *declare*
does nothing under a CNI that ignores it. Detect the CNI to know if segmentation is
real:

| Signal | Meaning | OTM effect |
|---|---|---|
| `flannel` / `kube-flannel` daemonset/image | Flannel CNI — **no NetworkPolicy enforcement** | `NetworkPolicy` boundaries are declarative-only → don't credit them as mitigations |
| `calico` / `tigera-operator`, `cilium` | Policy-enforcing CNI | `NetworkPolicy` counts as a real trust boundary/mitigation |

## SD-WAN / mesh VPN (Tailscale, and similar)

A mesh VPN inverts the default: workloads on the tailnet are **not** internet-exposed
(a private trust zone) — *except* where explicitly published. Detect both directions.

| Signal | Meaning | OTM mapping |
|---|---|---|
| `tailscale_*` provider / `tailscale` operator, subnet router, `tailscale serve` | Service reachable only on the tailnet | private `trustZone` (high trustRating) + mitigation (identity-based access) |
| **`tailscale funnel`** (config/annotation) | Service deliberately **published to the public internet** | internet `dataflow` — an exposure signal, overrides the private-zone assumption |
| `tailscale` ACLs (`acls`, `grants`) | Tailnet segmentation | mitigation (network ACL) |
| WireGuard / other mesh (Netmaker, ZeroTier, Nebula) config | Private overlay | private `trustZone` |

## GCP (Terraform)

| Signal | OTM | Internet? |
|---|---|---|
| `google_container_cluster.private_cluster_config.enable_private_endpoint` | control-plane zone | public if absent/false |
| `…enable_private_nodes` | node zone | public if false |
| `…master_authorized_networks_config.cidr_blocks` | mitigation (IP allowlist) | narrows |
| `google_compute_(global_)forwarding_rule.load_balancing_scheme` `EXTERNAL*` | external LB + ingress dataflow | yes (EXTERNAL*) |
| `google_compute_backend_service.iap { enabled = true }` | mitigation (IAP auth) | — |
| `google_compute_backend_service.security_policy` / `edge_security_policy` | mitigation (Cloud Armor WAF) | — |
| `google_compute_security_policy` (`type` CLOUD_ARMOR*) | mitigation (WAF) | no |
| `google_compute_network` / `_subnetwork` | trustZone (VPC / subnet) | no |

## AWS (Terraform)

| Signal | OTM | Internet? |
|---|---|---|
| `aws_lb`/`aws_alb.internal` (default false) | LB component + dataflow | yes when false/absent |
| `aws_apigatewayv2_api` (unless `disable_execute_api_endpoint`) | component + dataflow | yes |
| `aws_api_gateway_rest_api.endpoint_configuration.types` EDGE/REGIONAL vs PRIVATE | zone | yes unless PRIVATE |
| `aws_security_group` ingress `cidr_blocks` `0.0.0.0/0` | boundary + world dataflow | yes |
| `aws_wafv2_web_acl` (+ `_association.resource_arn`) | mitigation (WAF) bound to target | no |
| `aws_vpc` / `aws_subnet.map_public_ip_on_launch` | trustZone (public vs private) | subnet hint |

## Azure (Terraform)

| Signal | OTM | Internet? |
|---|---|---|
| `azurerm_application_gateway.sku` WAF_v2 / `firewall_policy_id` | mitigation (WAF) | — |
| `frontend_ip_configuration.public_ip_address_id` (App GW / LB) | component + ingress dataflow | yes |
| `azurerm_lb` frontend with `subnet_id`+`private_ip_address` only | internal zone | no |
| `azurerm_public_ip` | internet marker → follow `.id` to consumer | yes |
| `azurerm_web_application_firewall_policy` | mitigation (WAF) | no |
| `azurerm_virtual_network` / `_subnet` | trustZone | no |

## Cloud-native WAF & DDoS (AWS / GCP / Azure)

The hyperscalers' own edge protections — also modeled as `mitigation`s on the
ingress dataflow.

| Provider | Signal (grep) | Mitigation |
|---|---|---|
| AWS | `aws_wafv2_web_acl` + `_association` | AWS WAF |
| AWS | `aws_shield_protection` (`resource_arn`) | AWS Shield Advanced (DDoS) |
| GCP | `google_compute_security_policy` `type = CLOUD_ARMOR*` (WAF preconfigured rules / adaptive protection) | Cloud Armor (WAF + DDoS) |
| GCP | backend `security_policy` / `edge_security_policy` ref | Cloud Armor bound to backend |
| Azure | `azurerm_web_application_firewall_policy`, App GW `WAF_v2`, Front Door WAF policy | Azure WAF |
| Azure | `azurerm_network_ddos_protection_plan` (+ VNet association) | Azure DDoS Protection |

## Edge WAF (Cloudflare & Fastly)

A WAF emits an OTM `mitigation` on the ingress dataflow with a `mode` annotation
(`block` vs `log`) and coverage %. **Presence ≠ protection** — a rule with
`action = "log"`, `enabled = false`, or a dangling config is detect-only.

| Provider | Signal (grep) | Mitigation | Enforcing? |
|---|---|---|---|
| Cloudflare | `cloudflare_ruleset` phase `http_request_firewall_managed`, rule `action = "execute"` of managed id `efb7b8c949ac4650a09736fc376e9aee` | Cloudflare Managed WAF | yes |
| Cloudflare | same, managed id `4814384a9e5d4991b9815dcfc25d2f1f` | OWASP Core Ruleset | yes |
| Cloudflare | phase `http_request_firewall_custom`, action `block`/`challenge`/`managed_challenge` | custom firewall rules | yes |
| Cloudflare | phase `http_ratelimit` (`rules[].ratelimit`) / `cloudflare_rate_limit` | rate limiting (DoS/brute-force) | yes |
| Cloudflare | `cloudflare_bot_management` / phase `http_request_sbfm` | bot management | yes |
| Fastly | `fastly_service_waf_configuration` **bound** via service `waf { waf_id }` | Fastly classic WAF | block if `http_violation_score_threshold` + rules `status=block` |
| Fastly | `sigsci_edge_deployment(_service)` `agent_mode/level = "blocking"` | Next-Gen WAF (Signal Sciences) | blocking |
| Fastly | `fastly_service_vcl` `product_enablement {}` (NGWAF) + `traffic_ramp` | Next-Gen WAF (native) | ramp % = coverage |

**Gotchas:** Cloudflare `kind = "root"` is account-level (all zones); rule
`expression` scope narrows coverage. Fastly classic WAF is deprecated → Next-Gen;
`fastly_service_waf_configuration` not referenced by a service `waf {}` block is
inert. `traffic_ramp`/`percent_enabled < 100` = partial coverage — annotate, don't
treat as full.

## Reverse proxies & access control

The proxy itself is just routing — **the middleware/plugin is the security signal.**
A tunneled proxy (Pangolin, Cloudflare Tunnel) means services have *no inbound
internet port* at all: model the authenticated edge, not a direct exposure.

| Signal (grep) | Meaning | OTM mapping |
|---|---|---|
| Pangolin (`fossorial/pangolin`, `newt`, `gerbil`) | Tunneled reverse proxy + SSO over WireGuard; targets reached via tunnel, not direct | private zone + mitigation (authenticated ZTNA edge) |
| Cloudflare Tunnel (`cloudflared`, `cloudflare_tunnel`, `tunnel:` ingress), `ngrok` | Outbound-only tunnel — no inbound port | mitigation (no direct exposure) |
| Traefik / Caddy / nginx / HAProxy / Envoy | Reverse-proxy edge | edge component; look to its middleware/labels for controls |
| Traefik `ipAllowList`/`ipWhiteList` middleware, nginx `allow`/`deny`, `loadBalancerSourceRanges`, SG CIDR | IP allowlisting | mitigation (source allowlist) |
| Authelia, Authentik, oauth2-proxy, Keycloak, Pomerium, Ory Oathkeeper, vouch-proxy | Forward-auth / SSO in front of a service | mitigation (authentication) |
| Traefik `forwardAuth` middleware, nginx `auth_request` | Delegated auth to an SSO proxy | mitigation (authentication) |
| Istio `AuthorizationPolicy` `action: CUSTOM` + `provider` (ext_authz → oauth2-proxy), `RequestAuthentication` (JWT) | OAuth2 / JWT authz at the gateway | mitigation (authentication) |
| fail2ban, CrowdSec (`crowdsec`, Traefik `bouncer` plugin) | Intrusion prevention / IP-reputation blocking | mitigation (brute-force / DoS) |

**Gotcha:** a reverse proxy alone is not a control — an unauthenticated Traefik/nginx
in front of a service adds routing, not security. Only credit a mitigation when a
middleware (auth, ipAllowList, rate limit, CrowdSec bouncer) is actually attached.

## Sources

Cloudflare WAF/Terraform, Fastly WAF & Next-Gen WAF (Terraform + Signal Sciences),
Kubernetes Service/Ingress/NetworkPolicy, Istio Gateway/AuthorizationPolicy, and
HashiCorp `google`/`aws`/`azurerm` provider docs (resource attribute names taken
from provider source markdown; Registry pages are JS-rendered). Full URL list in
the research notes on issue #12.
