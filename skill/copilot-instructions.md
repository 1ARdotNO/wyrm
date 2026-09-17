# wyrm threat modeling — Copilot instructions

Copy this into `.github/copilot-instructions.md` in a repo that uses wyrm (or paste
into a Copilot chat). It teaches Copilot to work with wyrm and the OTM format.

---

This repository uses **wyrm** for threat modeling as code. Threat models are
[Open Threat Model (OTM)](https://github.com/iriusrisk/OpenThreatModel) files in
**`.threatmodel/*.otm.yaml`**. When asked to create, update, or reason about a
threat model:

**CLI:** `wyrm init` (baseline from docker-compose/Kubernetes; merges into an
existing model), `wyrm validate`, `wyrm analyze` (STRIDE findings; exits non-zero
on HIGH+ — the CI gate), `wyrm diagram` (Mermaid). Prefer editing the model and
re-running `wyrm analyze` over hand-fixing.

**OTM shape:** `project`; `trustZones` (`risk.trustRating` 0-100, internet≈10,
private≈80); `assets` (`risk.confidentiality/integrity/availability` 0-100);
`components` (`type`: web-service/database/data-store/process/external-entity;
`parent.trustZone`; `assets.processed/stored`); `dataflows` (`source`,
`destination`, `assets`, `tags`); `mitigations`.

**STRIDE rules & fixes:**
- Unencrypted flow across a trust boundary (WYRM-T001 critical if it carries
  sensitive data, T002 high otherwise) → add `tags: [tls]` to the flow when it's
  genuinely encrypted (`https`/`mtls`/`wss`/`ssh` also count); otherwise enforce
  TLS first.
- Sensitive component in a low-trust zone (T003) → move it to a higher-trust zone
  or add auth + a `mitigation`.
- Datastore in a low-trust zone (T004) → move it to a private zone.
- Unauthenticated cross-boundary flow (T005) → authenticate both ends; record a
  `mitigation`.

**Key rule:** a finding clears only when the model reflects a real control — never
by deleting the element. The most valuable edits are adding `assets` with
confidentiality ratings and attaching them to the right components/dataflows;
infra can't infer sensitivity.
