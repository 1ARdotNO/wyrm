# wyrm

**Threat modeling that lives with your code.**

_The dragon, evolved — threat models as code._

wyrm takes OWASP Threat Dragon's mission (accessible, developer-friendly threat
modeling) and moves it into your codebase. Instead of a drag-and-drop canvas in a
separate app, a threat model is a plain [Open Threat Model (OTM)][otm] file in the
repo — versioned, diff-reviewable, and enforced in CI. wyrm parses it, validates
it, runs a STRIDE rule engine over it, and renders a data-flow diagram from it.

```
.threatmodel/example.otm.yaml   ← your model, next to the code it protects
```

## Why not just use …?

| | Editing | Storage format | In-repo / CI gate | Engine |
|---|---|---|---|---|
| **Threat Dragon** | GUI canvas | tool-specific JSON (geometry-coupled) | no | manual |
| **pytm** | Python program | imperative `.py` | partial | Python threat lib |
| **wyrm** | your editor (text) | **OTM** (YAML/JSON, tool-agnostic) | **yes** | Rust, data-driven rules |

OTM is a published, platform-independent standard, so a wyrm model isn't locked to
wyrm. The STRIDE rule catalogue is **data** (`threats/library.yaml`), adapted from
pytm's threat library — grow it without recompiling.

## Install / build

```sh
cargo build --release
./target/release/wyrm --help
```

## Use

```sh
wyrm validate                     # structural checks over .threatmodel/
wyrm analyze                      # run STRIDE rules; exits non-zero on HIGH+ (CI gate)
wyrm analyze --fail-on critical   # loosen the gate
wyrm analyze --json               # machine-readable findings
wyrm diagram                      # emit a Mermaid data-flow diagram
```

`analyze` is designed to drop straight into CI: it exits non-zero when a finding
meets `--fail-on` (default `high`), failing the build on a real design flaw.

## Architecture

One Rust core, many thin clients — the analysis exists exactly once:

- **`otm-core`** — OTM parsing, validation, the STRIDE rule engine, and Mermaid
  rendering. The whole product.
- **`wyrm-cli`** — the `wyrm` binary (this repo).
- **Zed extension** _(planned)_ — a language server wrapping `otm-core` for
  in-editor completion and diagnostics on `*.otm.yaml`.
- **Obsidian plugin** _(planned)_ — `otm-core` compiled to WASM, with a JSON
  Canvas ↔ OTM bridge so you can draw the model visually.

## Convention

Store models in **`.threatmodel/`** at the repo root, named `*.otm.yaml`
(or `.otm.json`). They live with the code and travel with it.

## License

MIT. Threat rules adapted from [OWASP pytm][pytm] (MIT).

[otm]: https://github.com/iriusrisk/OpenThreatModel
[pytm]: https://github.com/OWASP/pytm
