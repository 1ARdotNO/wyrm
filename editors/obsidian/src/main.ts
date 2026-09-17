import { MarkdownRenderer, Notice, Plugin } from "obsidian";
import init, { analyze, toMermaid } from "./wasm/otm_wasm.js";
import { WASM_BASE64 } from "./wasm/otm_wasm_bytes.js";

interface Finding {
  ruleId: string;
  title: string;
  stride: string;
  severity: "critical" | "high" | "medium" | "low";
  elementId: string;
  elementName: string;
  description: string;
  mitigation: string;
}

// The wasm engine is initialised once, lazily, from the inlined bytes.
let wasmReady: Promise<void> | null = null;
function ensureWasm(): Promise<void> {
  if (!wasmReady) {
    const bytes = Uint8Array.from(atob(WASM_BASE64), (c) => c.charCodeAt(0));
    wasmReady = init({ module_or_path: bytes }).then(() => undefined);
  }
  return wasmReady;
}

export default class WyrmPlugin extends Plugin {
  async onload(): Promise<void> {
    // Render ```otm blocks as a data-flow diagram + STRIDE findings.
    this.registerMarkdownCodeBlockProcessor("otm", async (source, el, ctx) => {
      try {
        await ensureWasm();
        const mermaid = toMermaid(source);
        const findings: Finding[] = JSON.parse(analyze(source));
        await this.render(el, mermaid, findings, ctx.sourcePath);
      } catch (err) {
        el.createEl("pre", { cls: "wyrm-error", text: `Wyrm: ${(err as Error).message}` });
      }
    });
  }

  private async render(
    el: HTMLElement,
    mermaid: string,
    findings: Finding[],
    sourcePath: string,
  ): Promise<void> {
    const wrap = el.createDiv({ cls: "wyrm" });

    // Diagram — delegate to Obsidian's own Mermaid renderer.
    const diagram = wrap.createDiv({ cls: "wyrm-diagram" });
    await MarkdownRenderer.render(this.app, "```mermaid\n" + mermaid + "\n```", diagram, sourcePath, this);

    // Findings.
    const header = wrap.createDiv({ cls: "wyrm-header" });
    if (findings.length === 0) {
      header.setText("✓ No STRIDE findings");
      header.addClass("wyrm-clean");
      return;
    }
    header.setText(`${findings.length} finding${findings.length === 1 ? "" : "s"}`);

    const list = wrap.createDiv({ cls: "wyrm-findings" });
    for (const f of findings) {
      const item = list.createDiv({ cls: "wyrm-finding" });
      const top = item.createDiv({ cls: "wyrm-finding-top" });
      top.createSpan({ cls: `wyrm-badge wyrm-${f.severity}`, text: f.severity.toUpperCase() });
      top.createSpan({ cls: "wyrm-stride", text: f.stride });
      top.createSpan({ cls: "wyrm-title", text: `${f.title} — ${f.elementName}` });
      item.createDiv({ cls: "wyrm-desc", text: f.description });
      item.createDiv({ cls: "wyrm-fix", text: `↳ ${f.mitigation}` });
    }
  }

  onunload(): void {
    new Notice("Wyrm unloaded");
  }
}
