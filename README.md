# wyrm

**Threat modeling that lives with your code.**

_The dragon, evolved — threat models as code._

wyrm takes OWASP Threat Dragon's mission (accessible, developer-friendly threat
modeling) and moves it into your codebase. A threat model is a plain
[Open Threat Model (OTM)][otm] file in the repo — versioned, diff-reviewable, and
enforced in CI. wyrm parses it, validates it, runs a STRIDE rule engine over it,
renders a data-flow diagram from it, and can **generate a baseline from your
infrastructure**.

📖 **Docs & live demo: <https://1ardotno.github.io/wyrm/>** · [What it auto-detects](https://1ardotno.github.io/wyrm/detect.html)

## Features

- **OTM engine** — parse/validate OTM (YAML or JSON), a data-driven STRIDE rule
  engine, and Mermaid diagram generation. One Rust core, shared everywhere.
- **CLI** — `wyrm init | validate | analyze | diagram`. `analyze` exits non-zero on
  HIGH+ findings, so it drops straight into CI.
- **Auto-detection** — `wyrm init` builds a baseline model from **docker-compose**
  or **Kubernetes/Istio** manifests, and **reconciles** on re-run (regenerates the
  topology without clobbering your mitigations). [Detection matrix →](docs/DETECTION.md)
- **Editors** — [Zed](editors/zed) and [VS Code](editors/vscode) extensions give
  live diagnostics via `wyrm-lsp`; an [Obsidian plugin](editors/obsidian) renders
  `otm` blocks inline; an [IntelliJ](editors/intellij) plugin (LSP4IJ) covers the
  JetBrains family; and [`editors/lsp`](editors/lsp) has drop-in configs for
  Neovim, Emacs, Sublime, Helix — any LSP editor. All share the same engine.
- **CI integration** — prebuilt release binaries + a PR workflow that regenerates,
  merges reviewer edits, and gates on severity.
- **AI skill** — a [`skill/`](skill) that teaches Claude, GitHub Copilot, and ChatGPT
  to use wyrm and author/fix OTM models. [Setup →](https://1ardotno.github.io/wyrm/ai.html)
- **Migrate in** — `wyrm import --from threagile|pytm <file>` converts existing
  [Threagile](https://threagile.io) models or [pytm](https://github.com/OWASP/pytm)
  `--json` exports to OTM. Come as you are.

## Install

```sh
# From source
cargo install --git https://github.com/1ARdotNO/wyrm wyrm-cli

# Or grab a prebuilt binary
curl -sSL https://github.com/1ARdotNO/wyrm/releases/latest/download/wyrm-x86_64-unknown-linux-gnu.tar.gz | tar -xz
```

## Quickstart

```sh
# Generate a baseline from your infrastructure
wyrm init                       # auto-detects docker-compose in the cwd
wyrm init --from k8s/           # a directory of Kubernetes/Istio manifests

# Review the generated .threatmodel/<project>.otm.yaml, add asset sensitivity, then:
wyrm analyze                    # STRIDE findings; exits non-zero on HIGH+ (the CI gate)
wyrm analyze --fail-on critical # loosen the gate
wyrm diagram                    # Mermaid data-flow diagram
wyrm validate                   # structural checks only
```

Re-running `wyrm init` **merges** — the topology refreshes from infra while your
assets, mitigations, and `tls`/control tags are preserved (`--force` to overwrite).
That's what makes the CI loop safe: regenerate on every push, keep the reviewer's
mitigations, fail the check only on unresolved HIGH+ findings. See the
[CI example](https://1ardotno.github.io/wyrm/#ci).

## Writing a model

```yaml
otmVersion: 0.2.0
project: { id: shop, name: Shop }
trustZones:
  - { id: tz-net, name: Internet, risk: { trustRating: 10 } }
  - { id: tz-db,  name: Private,  risk: { trustRating: 80 } }
assets:
  - { id: pii, name: Customer PII, risk: { confidentiality: 100 } }
components:
  - { id: api, name: API, type: web-service, parent: { trustZone: tz-net }, assets: { processed: [pii] } }
  - { id: db,  name: DB,  type: database,    parent: { trustZone: tz-db } }
dataflows:
  - { id: save, name: Save profile, source: api, destination: db, assets: [pii], tags: [tls] }
```

## Repository layout

```
crates/otm-core      the engine: OTM model, validation, STRIDE rules, Mermaid,
                     and the infra importers (generate/{compose,kubernetes})
crates/wyrm-cli      the `wyrm` binary — a thin shell over otm-core
crates/wyrm-lsp      language server (diagnostics) — powers the editor plugins
editors/zed          Zed extension (WASM) → wyrm-lsp
editors/vscode       VS Code extension (LSP client) → wyrm-lsp
editors/obsidian     Obsidian plugin: renders ```otm blocks (otm-core via WASM)
editors/obsidian/wasm  otm-core compiled to WebAssembly
editors/intellij     IntelliJ/JetBrains plugin scaffold (LSP4IJ) → wyrm-lsp
crates/otm-core/threats/library.yaml   the STRIDE rule catalogue (adapted from pytm)
docs/                GitHub Pages site + DETECTION.md
.threatmodel/        this repo's own model (dogfood)
```

**The golden rule:** analysis logic lives in `otm-core` exactly once. The CLI, the
LSP, the Zed extension, and the Obsidian plugin (via WASM) are all thin clients.

## Why not just use…?

| | Editing | Storage format | Model source | In-repo / CI gate | Engine |
|---|---|---|---|---|---|
| **Threat Dragon** | GUI canvas | tool-specific JSON | hand-drawn | no | manual |
| **pytm** | Python program | imperative `.py` | hand-coded | partial | Python threat lib |
| **Threagile** | text (YAML) | own YAML schema | hand-written | yes | Go rules |
| **wyrm** | your editor (text) | **OTM** (standard) | **auto-detected + reconciled** | **yes** | Rust, data-driven |

## Convention

Store models in **`.threatmodel/`** at the repo root, named `*.otm.yaml` (or
`.otm.json`). They live with the code and travel with it.

## License

MIT. STRIDE rules adapted from [OWASP pytm][pytm] (MIT). Diagrams by [Mermaid][mermaid].

[otm]: https://github.com/iriusrisk/OpenThreatModel
[pytm]: https://github.com/OWASP/pytm
[mermaid]: https://mermaid.js.org/
