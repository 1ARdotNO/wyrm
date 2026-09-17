// Build the wasm core (web target) and inline it for the plugin bundle.
// Produces src/wasm/{otm_wasm.js, otm_wasm.d.ts, otm_wasm_bytes.js} — the glue
// plus the wasm bytes as base64, so esbuild can bundle everything into main.js.
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, copyFileSync, mkdirSync } from "node:fs";

const WASM_DIR = "wasm";
const OUT = "src/wasm";

mkdirSync(OUT, { recursive: true });

console.log("→ wasm-pack build (web target)");
execSync("wasm-pack build --target web --out-dir pkg-web", {
  cwd: WASM_DIR,
  stdio: "inherit",
});

copyFileSync(`${WASM_DIR}/pkg-web/otm_wasm.js`, `${OUT}/otm_wasm.js`);
copyFileSync(`${WASM_DIR}/pkg-web/otm_wasm.d.ts`, `${OUT}/otm_wasm.d.ts`);

const wasm = readFileSync(`${WASM_DIR}/pkg-web/otm_wasm_bg.wasm`);
writeFileSync(`${OUT}/otm_wasm_bytes.js`, `export const WASM_BASE64 = "${wasm.toString("base64")}";\n`);
writeFileSync(`${OUT}/otm_wasm_bytes.d.ts`, `export const WASM_BASE64: string;\n`);

console.log(`→ inlined ${(wasm.length / 1024).toFixed(0)} KiB wasm as base64`);
