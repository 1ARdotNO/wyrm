# Contributing to wyrm

Thanks for helping. wyrm is small and fast to hack on.

## Layout

```
crates/otm-core   the engine: OTM model, validation, STRIDE rules, diagram render
crates/wyrm-cli   the `wyrm` binary — a thin shell over otm-core
threats/          the STRIDE rule catalogue (data, not code)
.threatmodel/     example model(s); also wyrm's own dogfood target
```

The golden rule: **analysis logic lives in `otm-core` exactly once.** The CLI,
and later the Zed LSP and Obsidian plugin (via WASM), are all thin clients. Don't
reimplement a rule in a client.

## Before you push

CI mirrors these; running them locally keeps the aggressive automerge green.

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo run --bin wyrm -- validate    # dogfood
```

## Adding a threat rule

Most new detections need **no Rust** — add an entry to `threats/library.yaml`
using the existing predicate vocabulary. Only touch `otm-core/src/rules.rs` when
you need a genuinely new predicate, and add a test in
`crates/otm-core/tests/analysis.rs` that proves it fires (and that a safe model
does not trip it).

## Dependencies

Renovate opens and auto-merges dependency PRs that stay green. New direct
dependencies must pass `cargo deny check` (permissive license, no advisories).
