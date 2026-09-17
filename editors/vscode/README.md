# Wyrm — VS Code extension

Live threat-model diagnostics in VS Code: open a `*.otm.yaml` file and wyrm
validates its structure and runs STRIDE rules as you type, surfacing findings
inline — powered by the `wyrm-lsp` language server (the same engine as the CLI
and the Zed extension).

## Prerequisites

Install the language server so it's on your PATH:

```sh
cargo install --git https://github.com/1ARdotNO/wyrm wyrm-lsp
```

(Or set `wyrm.serverPath` in settings to point at a `wyrm-lsp` binary.)

## Build & run (dev)

```sh
npm install
npm run build
```

Press `F5` in VS Code to launch an Extension Development Host, then open any
`.otm.yaml` file — diagnostics appear inline and in the Problems panel.

## Package

```sh
npx @vscode/vsce package
```
