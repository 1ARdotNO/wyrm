# Threat-catalogue coverage analysis (pytm vs Threagile)

An 8-agent study (2 researchers → 1 synthesis → 5 adversarial QA) of whether
wyrm's `WYRM-T001–T007` catalogue covers enough, benchmarked against OWASP pytm
and Threagile OSS. This is the roadmap for expanding `threats/library.yaml`.

## Verdict — EXPAND, do not rebuild

The 7-rule core is correct and well-factored (T001/T002 transport crypto, T003
exposed sensitive component, T004 datastore-in-low-trust, T005 unauthenticated
cross-boundary flow, T006/T007 identity blast-radius) — and T003/T006/T007 are
*stricter* than either reference tool. The architecture (data-driven AND-ed
predicates, YAML re-validated in CI, mitigation down-ranking) is sound.

The gap is **coverage, not design**:
- **DoS** and **component-level EoP/Spoofing** (beyond datastores/identities) are absent.
- The predicate vocabulary only tests **positive tag presence**, so it cannot assert
  **control absence** — which is exactly how pytm (`isHardened`, `authorizesSource`,
  `isResilient`, `implementsAuthenticationScheme`) and Threagile (missing-WAF,
  missing-2FA, missing-vault, missing-segmentation) model most infra threats.
- No **co-location/segmentation** or **dataflow-source-trust** reasoning.

App-layer web families (injection, SQLi/XSS/XXE/SSRF, deserialization, input
validation) are **correctly out of scope** — they're code-shaped, not graph-shaped;
OTM lacks the request semantics.

## Proposed new predicates (4)

| Predicate | What it adds |
|---|---|
| `lacksControl{control}` | control-ABSENCE over a component/dataflow, via an alias table (authz, hardened, rateLimit, resilience, backup, mfa, signing, integrity, waf, logging…). **Highest-leverage** — unlocks 6–8 rules. |
| `sharesZoneWith{minSiblings, maxSiblingTrust?}` | co-location: N+ other components in the same zone (segmentation, IdP/vault isolation). |
| `sourceLowTrust{maxTrust}` | dataflow whose **source** sits in a low-trust zone (ingress from internet; wyrm only reasons about the target today). |
| `modelLacksKind{kinds}` | model-global negation (secrets present but no vault; auth flows but no identity store). |

## Proposed rules + 5-lens QA consensus

Verdicts are keep/revise/drop across the 5 adversarial reviewers.

| Rule | Sev | STRIDE | Source | QA (keep/rev/drop) |
|---|---|---|---|---|
| T008 Compute reachable without authorization | high | EoP | pytm | **5/0/0** ✅ |
| T012 IdP / secrets vault not isolated | high | EoP | threagile | **5/0/0** ✅ |
| T020 Exposed secret store / source repo / CI | high | InfoDisc | threagile | **5/0/0** ✅ |
| T009 Unguarded access from the internet | high | EoP | threagile | 2/3/0 (revise) |
| T010 Shared datastore, multiple consumers | high | Tampering | pytm | 1/4/0 (revise) |
| T011 Missing network segmentation | high | EoP | threagile | 2/3/0 (revise) |
| T013 Secrets stored but no vault present | high | InfoDisc | threagile | 2/3/0 (revise) |
| T016 Internet-facing web app has no WAF | med | Tampering | threagile | 1/4/0 (revise) |
| T017 Sensitive service without MFA | med | Spoofing | threagile | 1/4/0 (revise) |
| T018 Unsigned artifact crosses a boundary | med | Tampering | pytm | 2/3/0 (revise; high cost) |
| T014 Internet-facing lacks rate limits | med | DoS | pytm | 2/1/2 (borderline) |
| T019 Datastore has no backup/replication | med | DoS | first-principles | 1/2/2 — **DROP** (ops, not a threat) |
| T015 Internet-facing not hardened | med | InfoDisc | pytm | 0/1/4 — **DROP** (unfalsifiable catch-all) |

## Cross-cutting prerequisites the QA converged on (build these first)

1. **`lacksControl` noise floor.** Every absence rule fires when a tag simply
   isn't modelled. Distinguish "control provably absent" from "never mentioned" —
   cap `lacksControl`-only findings at low/info unless a `modeledControls` opt-in
   is declared. *This governs whether half the set is usable.*
2. **`lacksControl` must also check linked Mitigation objects** (`appliesTo`), not
   just tags — else it double-counts against the existing `apply_mitigations` pass.
3. **Exposed-component posture roll-up.** T003/T008/T014/T016/T017/T020 all iterate
   the same internet-facing node → 5+ findings on one component. Collapse into one
   posture finding (or a suppression/ranking pass) before the noise budget blows.
4. **Nested-zone soundness** — `lowTrustZone`/`sharesZoneWith` must resolve via
   `trust_zone_of()` (walk `parent.component`), not read `parent.trustZone`
   directly, or they miss nested components. *(Fixed for `lowTrustZone` — see the
   commit landing this doc.)*

## High-value rules the QA said the set still MISSES

- **Residual-risk rule** — a high/critical finding (T001–T003) with **no linked
  mitigation** covering it. "The highest-value thing a threat-model-as-code tool
  can do that a scanner can't — surface *unmitigated* risk." (needs a post-pass
  over findings × mitigations.)
- **Repudiation (R)** is entirely absent, before and after — `lacksControl{logging}`
  on a sensitive/cross-boundary flow fills it with the same new primitive.
- **Egress / exfiltration** — a high-trust datastore with an outbound flow to a
  low-trust zone (mirror of T009).
- **Integrity / Availability** of assets are unreachable — every rule keys only on
  `minConfidentiality`.
- **Missing-trust-zone meta-lint** — a component with no `parent.trustZone` dodges
  every zone-based rule silently.
