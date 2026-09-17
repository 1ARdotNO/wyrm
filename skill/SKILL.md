---
name: wyrm-threat-modeling
description: Author, analyze, and maintain threat models as code with wyrm and the Open Threat Model (OTM) format. Use when the user wants to create or edit a threat model, generate one from infrastructure (docker-compose / Kubernetes), interpret STRIDE findings, add mitigations, or gate threat models in CI.
---

# wyrm — threat modeling as code

wyrm turns a threat model into a plain [OTM](https://github.com/iriusrisk/OpenThreatModel)
file (`*.otm.yaml`) in the repo, runs a STRIDE rule engine over it, and can generate
a baseline from infrastructure. Models live in **`.threatmodel/`** at the repo root.

## When to use this skill

- "Create/update a threat model for this service"
- "Generate a threat model from our docker-compose / k8s manifests"
- "Why is wyrm flagging this? How do I fix it?"
- "Add a mitigation / mark this data as sensitive"
- "Gate threat models in CI"

## CLI

Install: `cargo install --git https://github.com/1ARdotNO/wyrm wyrm-cli`
(or download a binary from the GitHub releases).

```sh
wyrm init                     # baseline from ./docker-compose.yml (auto-detected)
wyrm init --from k8s/         # from a directory of Kubernetes/Istio manifests
wyrm init --from main.tf -o - # print to stdout instead of writing
wyrm validate                 # structural checks over .threatmodel/
wyrm analyze                  # STRIDE findings; exits non-zero on HIGH+ (CI gate)
wyrm analyze --fail-on critical --json
wyrm diagram                  # Mermaid data-flow diagram to stdout
```

`wyrm init` **merges** into an existing model: it regenerates the topology from
infra but preserves human edits (assets, mitigations, tags). Use `--force` to
overwrite. Always prefer editing a model and re-running `analyze` over hand-fixing.

## OTM format (the parts wyrm uses)

```yaml
otmVersion: 0.2.0
project: { id: shop, name: Shop, owner: security@shop.io }

trustZones:                       # boundaries; trustRating 0-100 (internet≈10, private≈80)
  - { id: tz-internet, name: Internet,  risk: { trustRating: 10 } }
  - { id: tz-private,  name: Private,   risk: { trustRating: 80 } }

assets:                           # what's worth protecting; CIA ratings 0-100
  - { id: pii, name: Customer PII, risk: { confidentiality: 100, integrity: 80, availability: 50 } }

components:                       # services/stores; type is free-form
  - id: api
    name: API
    type: web-service             # web-service | database | data-store | process | external-entity | message-queue
    parent: { trustZone: tz-internet }
    assets: { processed: [pii] }  # or stored: [...]
  - id: db
    name: Database
    type: database
    parent: { trustZone: tz-private }
    assets: { stored: [pii] }

dataflows:
  - id: save
    name: Save profile
    source: api                   # component id
    destination: db               # component id
    assets: [pii]                 # asset ids carried
    tags: [tls]                   # mark encrypted; also: attributes.protocol=https/mtls/wss

mitigations:                      # controls a reviewer adds
  - { id: m-waf, name: Cloudflare WAF, riskReduction: 80 }
```

## The STRIDE rules

`analyze` fires these (catalogue in `threats/library.yaml`):

| Rule | Severity | Fires when |
|---|---|---|
| WYRM-T001 | critical | sensitive data (confidentiality ≥ 70) crosses a trust boundary **unencrypted** |
| WYRM-T002 | high | any flow crosses a trust boundary **unencrypted** |
| WYRM-T003 | high | component in a low-trust zone (≤ 30) processes/stores sensitive data |
| WYRM-T004 | high | a database/datastore sits in a low-trust zone (≤ 40) |
| WYRM-T005 | medium | a cross-boundary flow carries data but records no peer authentication |

## How to resolve findings

- **T001 / T002 (unencrypted)** → the flow really is encrypted? add `tags: [tls]`
  (or `attributes: { protocol: https }`). Not encrypted? that's a real finding —
  enforce TLS/mTLS, then tag it.
- **T003** → move sensitive processing to a higher-trust zone, or add auth/validation
  and record a `mitigation`.
- **T004** → put the datastore in a private (higher trustRating) zone.
- **T005** → authenticate both ends; record a `mitigation` and reference it.

A finding clears when the model reflects a real control — never by deleting the
element. Encryption is recognised from a flow's `tags` or `attributes`
(`tls`, `https`, `mtls`, `wss`, `ssh`, `encrypted`, or `isEncrypted: "true"`).

## Typical workflow

1. `wyrm init` (or write `.threatmodel/<system>.otm.yaml` by hand).
2. Add **assets** with confidentiality and attach them to components/dataflows —
   this is the part infra can't infer and drives the most important findings.
3. `wyrm analyze` — read the findings.
4. For each real risk, add the control and tag/mitigate it; re-run until the gate
   passes at your chosen `--fail-on` level.
5. Commit the model alongside the code; gate it in CI.
