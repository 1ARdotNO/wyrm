# wyrm-gui

A light native editor for `.otm.yaml` threat models — a GUI companion to the CLI,
LSP, and editor extensions. Built with [egui/eframe](https://github.com/emilk/egui):
one self-contained window, no Electron, no Zed-sized runtime.

## What it does

- **Browse** the model — trust zones, components, dataflows, assets, mitigations.
- **Edit** in an inspector: rename, set a component's type/zone/assets, drag asset
  CIA ratings, add/remove dataflow **tags**, and drop **mitigations** from a
  built-in library (WAF, IAP, TLS, SSO, network policy…) that link to the selected
  element and carry the right `riskReduction`/`addresses`.
- **Live-save** — every committed edit writes straight back to the file, so the
  LSP in your editor re-lints instantly.
- **Live findings** — the STRIDE engine re-runs on each change; the panel shows
  what fired and what a mitigation downgraded.
- **Undo / redo** — `Cmd-Z` / `Cmd-Shift-Z` (or `Cmd-Y`), full-model history.
- **One Dark** styling, borrowed from Zed's palette.

## Run

```sh
cargo run -p wyrm-gui -- .threatmodel/my-system.otm.yaml
# or install it and let the CLI / editors launch it:
cargo install --path crates/wyrm-gui
wyrm gui .threatmodel/my-system.otm.yaml
```

It lives **outside** the core Cargo workspace (its own `Cargo.lock`) so the heavy
windowing dependency tree never touches the core build, test, or license gates.

## Launch from your editor

- **VS Code** — open a `.otm.yaml` and run **“Wyrm: Open in GUI editor”** (also in
  the editor title bar). Configurable via `wyrm.guiPath`.
- **Any editor / terminal** — `wyrm gui <file>` (set `WYRM_GUI_BIN` to override the
  binary path).
- **Zed** — add a task in `.zed/tasks.json`:
  ```json
  [{ "label": "wyrm gui", "command": "wyrm", "args": ["gui", "$ZED_FILE"] }]
  ```
