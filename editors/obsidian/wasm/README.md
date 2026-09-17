# otm-wasm

WebAssembly bindings for `otm-core` — the same engine as the `wyrm` CLI and LSP,
compiled for JavaScript. This is what lets the Obsidian plugin run wyrm's analysis
without shelling out to a binary.

## Build

```sh
wasm-pack build --target nodejs --out-dir pkg   # for node/Electron (Obsidian desktop)
wasm-pack build --target web --out-dir pkg      # for browser/bundler
```

## API

```js
const wyrm = require("./pkg/otm_wasm.js");
wyrm.analyze(modelYaml);    // -> JSON string of STRIDE findings
wyrm.validate(modelYaml);   // -> JSON string of structural diagnostics
wyrm.toMermaid(modelYaml);  // -> Mermaid flowchart source
```

Findings use the same shape as `wyrm analyze --json`.
