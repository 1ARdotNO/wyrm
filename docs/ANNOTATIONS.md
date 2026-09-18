# Annotating infrastructure for wyrm

`wyrm init` infers *topology* from infrastructure, but the risk-bearing context —
which data is sensitive, how access is provisioned, what talks to what internally,
what controls exist — usually isn't in the infra. You supply that context through
**annotations**, in two channels that share one schema:

1. **Inline comments**, adjacent to a resource (Trivy-style) — context lives with
   the code.
2. **An external `.threatmodel/data.yaml`** — keyed by resource address, so you can
   add context *without touching the code*.

Both are applied during `wyrm init`, and both survive regeneration.

## The schema (both channels)

Keys you can set on a resource:

| Key | Meaning |
|---|---|
| `type` | override the inferred component type (`database`, `web-service`, `identity`, …) |
| `zone` | place the component in a trust zone (id) |
| `assets` / `stored` | attach sensitive data assets it processes / stores (by id) |
| `tags` | add tags (e.g. `tls`) |
| `mitigations` | named controls protecting it |
| `flows` | internal dataflows this resource *sends to* (target addresses) — fills the gaps infra can't infer |
| `provisioning` | for identities: `manual` / `approval` / `attribute-based` / `jit` / `break-glass` |
| `privilege` | `high` / `low` |
| `ignore` | suppress a finding by rule id (Trivy-style), optionally with `reason` / `expires` |

Plus a top-level `assets:` list to *define* the data assets themselves (id, name,
confidentiality/integrity/availability).

## Channel 1 — inline comments

A `# wyrm:` comment attaches to the resource/service it immediately precedes.
Multiple lines accumulate. `key=value`; list values are comma-separated.

```hcl
# wyrm: assets=pii type=database zone=tz-data
resource "google_sql_database_instance" "main" { ... }

# wyrm: provisioning=jit privilege=high
resource "google_project_iam_member" "cluster_admin" { ... }
```

```yaml
services:
  # wyrm: assets=pii tags=tls flows=db
  api:
    image: our/api
```

(Comments are read from the raw file text — HCL/YAML parsers discard them — and
matched to the next `resource`/`module`/service block. Inline suppressions:
`# wyrm: ignore=WYRM-T004 reason="cache is single-tenant"`.)

## Channel 2 — `.threatmodel/data.yaml`

For teams that don't want threat-model metadata in their infra code. Keyed by
**resource address** (`<type>.<name>`, or a module/service name):

```yaml
assets:
  - { id: pii, name: Customer PII, risk: { confidentiality: 100, integrity: 80 } }

resources:
  google_sql_database_instance.main:
    stored: [pii]
    zone: tz-data
  google_container_cluster.workloads_main_cluster:
    type: web-service
    assets: [pii]
    flows: [google_sql_database_instance.main]
  google_project_iam_member.cluster_admin:
    type: identity
    provisioning: jit
    privilege: high
```

Auto-loaded from `.threatmodel/data.yaml`; override with `wyrm init --data <file>`.

## Precedence & lifecycle

Applied in order during `wyrm init`:

1. **Generate** topology from infra.
2. **Exclude** noise (`--exclude`).
3. **Enrich** with annotations — **inline > external > generated** (inline wins on
   conflict; both override inferred values).
4. **Merge** with the existing model — direct hand-edits to the `.otm.yaml` still win.

So you can mix all of it: let wyrm generate, drop IAM noise, annotate sensitivity
and internal flows in `data.yaml` (or inline), and hand-tweak the `.otm.yaml` — and
every re-run preserves the lot.

> Status: the **external `.threatmodel/data.yaml`** channel ships first; inline
> comment parsing is the next slice (same schema).
