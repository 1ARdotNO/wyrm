# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for
anything exploitable.

- Preferred: use GitHub's **[Report a vulnerability](https://github.com/1ARdotNO/wyrm/security/advisories/new)**
  (Security → Advisories) — private vulnerability reporting is enabled on this repo.
- We aim to acknowledge reports within a few days and to coordinate a fix and
  disclosure timeline with you.

Please include: affected version/commit, a description, reproduction steps, and
impact. Proof-of-concept code is welcome but never test against systems or data
you don't own.

## Supported versions

wyrm is pre-1.0; only the latest `main` is supported. Fixes land on `main` and in
the next tagged release.

## Scope & handling notes

- **Untrusted models.** wyrm parses OTM documents (YAML/JSON) that may come from
  other repos or contributors. Parsing is memory-safe Rust with no code
  execution; a malformed model should fail to parse, never escape the parser.
- **Importers invoke external tools.** `wyrm init` shells out to `helm`,
  `kustomize`/`kubectl`, and reads Terraform/plan sources you point it at. Those
  tools run their own templating — only run `wyrm init` on infrastructure sources
  you trust, as you would `helm template` or `terraform plan` on them.
- **The GUI live-writes the file.** `wyrm-gui` saves every edit back to the
  `.otm.yaml` you opened; it touches no other path and runs no network calls.
- **Automated hardening.** Dependencies and GitHub Actions are monitored by
  Renovate; every change is gated by CI (fmt, clippy `-D warnings`, tests,
  cargo-deny, CodeQL, Trivy, MegaLinter) before merge. Our own workflows are
  SHA-pinned and statically analysed by [zizmor](https://docs.zizmor.sh)
  (credential persistence, cache poisoning, permissions).

## What is not a vulnerability

- A "missing" threat finding: the rule library is best-effort and intentionally
  extensible, not a guarantee of completeness. Propose a rule instead.
- Findings that require an already-compromised host or working tree.
