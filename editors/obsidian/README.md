# Wyrm — Obsidian plugin

Render threat models inside your notes. Write an Open Threat Model in a fenced
`otm` block and the plugin draws the data-flow diagram and lists STRIDE findings
right below it — powered by the same `otm-core` engine as the CLI and Zed
extension, compiled to WebAssembly (no external binary needed).

````markdown
```otm
otmVersion: 0.2.0
project: { id: shop, name: Shop }
trustZones:
  - { id: tz-net, name: Internet, risk: { trustRating: 10 } }
  - { id: tz-db,  name: Private,  risk: { trustRating: 80 } }
assets:
  - { id: pii, name: PII, risk: { confidentiality: 100 } }
components:
  - { id: api, name: API, type: web-service, parent: { trustZone: tz-net }, assets: { processed: [pii] } }
  - { id: db,  name: DB,  type: database,    parent: { trustZone: tz-db } }
dataflows:
  - { id: save, name: Save, source: api, destination: db, assets: [pii] }
```
````

## Build

Requires `wasm-pack` (`cargo install wasm-pack`) to compile the engine.

```sh
npm install
npm run build     # builds wasm, typechecks, bundles main.js
```

Then copy `manifest.json`, `main.js`, and `styles.css` into
`<vault>/.obsidian/plugins/wyrm/` and enable it in Obsidian.

## Status

Engine calls (`analyze`/`toMermaid`) are verified in node; the build produces a
bundled `main.js`. In-Obsidian testing (rendering, mobile) is tracked in the repo.
The JSON Canvas ↔ OTM bridge (draw the DFD visually, convert to OTM) is the next
step.
