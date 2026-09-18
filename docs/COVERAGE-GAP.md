# Wyrm importer — infrastructure coverage gap

What two real GCP infra repos (`gcp-repo-a`, `gcp-repo-b`)
actually contain vs. what the wyrm Terraform/Kubernetes importers recognize today.
This is the roadmap for importer work (see tasks #41 clusters/VPC-zones, #44 TF↔k8s,
#29 IAM, #46 module grouping).

## Headline

`classify()` is an **allowlist of ~40 mostly-AWS resource types**. The most common
resources in these GCP repos are **IAM members, DNS records, and pub/sub IAM
bindings** — none recognized, so they're silently dropped. The repos are ~90%
IAM/identity, DNS, and org-policy by resource count, and wyrm models almost none of
it. The `module_type()` name heuristic softens the datastore/compute gap for HCL
module imports, but the **plan-JSON path expands modules into raw resources**, where
every gap below becomes real.

## Prioritized security-relevant misses (fix order)

1. **Boundary controls** — `google_compute_firewall` (10) and k8s `NetworkPolicy`
   (137) are dropped; model as mitigations/edges and flag `0.0.0.0/0`. Highest
   signal-to-effort.
2. **VPC / subnet / namespace as trust zones** — replace the fixed 3-zone model with
   segments from `google_compute_network`/`_subnetwork` and k8s `Namespace`. VPC-SC
   `service_perimeter` is a strong boundary. (task #41)
3. **Public-bucket / public-IAM detection** — no `is_internet_facing` case for storage;
   `allUsers`/`allAuthenticatedUsers` on buckets/topics/IAP is undetected — the classic
   exposure finding, currently silent.
4. **Service accounts & static credentials as principals/assets** —
   `google_service_account` (12), `_service_account_key` (7), `google_storage_hmac_key`.
   Keys are exportable secrets. (tension with `expand_exclude("iam")`, which strips
   these — see task #29)
5. **WIF federation trust boundary** — `google_iam_workload_identity_pool[_provider]`
   is an external-identity trust edge into GCP.
6. **Missing WAF: `sigsci_site*` (24)** — Signal Sciences/Fastly WAF; add to
   `mitigation_for()` alongside Cloud Armor/AWS WAF.
7. **Datastore name-suffix gaps** — `google_bigquery_dataset`, `google_spanner_database`,
   `google_redis_cluster`, `google_kms_crypto_key` dropped because only the
   `_instance`/`_ring` form is allowlisted. Cheap wins.
8. **k8s workloads & RBAC** — model `Deployment`/`Pod`/`Job` as compute (not just
   `Service`), and `Role`/`RoleBinding`/`ServiceAccount` as the identity layer; handle
   k8s `Secret`.

## Networking (trust zones & boundary controls) — largely dropped

| resource | count | currently | should be | sec |
|---|--:|---|---|---|
| `google_compute_firewall` | 10 | dropped | boundary control / mitigation (flag `0.0.0.0/0`) | high |
| `google_compute_subnetwork` | 6 | dropped | **trust zone** (network segment) | high |
| `google_compute_network` | 3 | dropped | **trust zone** (VPC) | high |
| `google_compute_router_nat` | 2 | dropped | egress control (NAT) | med |
| `google_access_context_manager_service_perimeter` | 1 | dropped | **VPC-SC boundary / mitigation** | high |
| `google_compute_vpn_gateway` | 1 | edge (encrypted) ✓ | recognized | ok |

`google_compute_vpn_tunnel` is in `edge_encryption()` but NOT in `classify()`'s EDGE
list → dead branch (dropped before the tag applies).

## Data (datastores, secrets, keys) — mixed

Recognized: `google_redis_instance`, `_secret_manager_secret`, `_storage_bucket`,
`_kms_key_ring`, `_sql_database_instance`, `_spanner_instance`, `kubernetes_secret`.
Dropped by suffix mismatch: `google_bigquery_dataset` (**high** — analytical PII),
`google_spanner_database`, `google_redis_cluster`, `google_kms_crypto_key`,
`google_storage_hmac_key` (**high** — static credential). **No public-bucket detection.**
`google_secret_manager_secret_iam_member` (7) — who can read secrets — dropped.

## IAM / Identity — entirely dropped (largest category by count)

`google_project_iam_member` (60), `_service_account` (12), `_service_account_key` (7),
`_iam_workload_identity_pool[_provider]` (4), `_project_iam_custom_role` (27),
`_org_policy_policy` (12), audit configs, folder/org bindings — all dropped. For threat
modeling: SAs are principals, SA/HMAC keys are exportable credentials,
`allUsers`/`allAuthenticatedUsers` are public-exposure findings. Note `expand_exclude("iam")`
currently *strips* this by intent — revisit for the security-relevant subset.

## Edge / Load-balancing — partial (entrypoint caught)

Recognized: `google_compute_forwarding_rule`, `_global_forwarding_rule` (gated on
`load_balancing_scheme`). Dropped: `target_https_proxy`, `url_map`, `backend_bucket`
(public content), `global_address`/`address` (public IP = exposure signal).

## DNS / Certs — dropped

`google_dns_record_set` (87 — enumerates the public hostname surface), `_managed_zone`,
`certificate_manager_*` — all dropped.

## Observability / third-party

`sigsci_site*` (24 — real WAF, should be a mitigation), `logging_project_sink`
(log-export control), `google_project_service` (41 — enabled-API attack surface).

## Kubernetes — substantial gaps

Handled: `Service`, `Ingress`, Istio `Gateway`/`VirtualService`, `BackendConfig`.
Dropped (by actual frequency): `DestinationRule` (197, mTLS evidence), **`NetworkPolicy`
(137 — the east-west boundary control)**, `Pod` (59), `ClusterRoleBinding`/`RoleBinding`
(71, RBAC), `Namespace` (28 — isolation boundary → trust zone), `ServiceAccount` (11),
`Secret` (1 — not handled at all), `Deployment` (3 — only `Service` is modeled today).
