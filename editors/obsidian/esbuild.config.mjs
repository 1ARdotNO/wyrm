import esbuild from "esbuild";
import builtins from "builtin-modules";

const production = process.argv.includes("production");

const ctx = await esbuild.context({
  entryPoints: ["src/main.ts"],
  bundle: true,
  format: "cjs",
  platform: "browser",
  target: "es2020",
  // Obsidian, Electron, and node builtins are provided by the host at runtime.
  external: ["obsidian", "electron", ...builtins],
  sourcemap: production ? false : "inline",
  minify: production,
  outfile: "main.js",
  logLevel: "info",
  // The wasm glue's default `import.meta.url` load path is dead code — we always
  // init from inlined bytes — so its cjs warning is noise.
  logOverride: { "empty-import-meta": "silent" },
});

if (production) {
  await ctx.rebuild();
  await ctx.dispose();
} else {
  await ctx.watch();
}
