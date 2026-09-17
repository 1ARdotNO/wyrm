# Wyrm — Zed extension

Live threat-model diagnostics in [Zed](https://zed.dev): open a `*.otm.yaml` file
and wyrm validates its structure and runs STRIDE rules as you type, surfacing
findings as inline diagnostics.

## Prerequisites

The extension launches the `wyrm-lsp` language server, which must be on your PATH:

```sh
cargo install --git https://github.com/1ARdotNO/wyrm wyrm-lsp
```

## Install (dev)

Until it's in the Zed extension registry, install as a dev extension:

1. `zed: install dev extension` from the command palette
2. Select this `editors/zed` directory

Open any file ending in `.otm.yaml` / `.otm.yml` and diagnostics appear.

## What you get

- YAML syntax highlighting (reuses the tree-sitter YAML grammar)
- Structural validation (dangling references, duplicate ids)
- STRIDE findings positioned on the offending element

Diagnostics are computed by `otm-core`, the same engine behind the `wyrm` CLI —
the editor and CI always agree.

## Build

```sh
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
```
