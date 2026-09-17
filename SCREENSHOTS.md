# Screenshots wanted

The docs site (`docs/`) has self-made visuals for anything wyrm can render on its
own — the Mermaid diagram and the CLI findings are live/real. What's left needs a
real application on screen, so let's capture these together. Drop the files at the
listed paths and they slot straight into the site.

Legend: **[self]** I can script it · **[you]** needs your machine/GUI · **[pair]** easiest together.

## High priority

1. **Zed inline diagnostics** — `docs/assets/zed-diagnostics.png` **[pair]**
   Replaces the current illustration. Open `.threatmodel/example.otm.yaml` in Zed
   with the wyrm extension + `wyrm-lsp` on PATH; hover the `df-login` flow so the
   WYRM-T001 popover shows. Capture the editor pane + the diagnostic. ~1600px wide.

2. **Terminal: `wyrm analyze`** — `docs/assets/analyze.png` **[self/you]**
   A real terminal running `wyrm analyze` in a repo, showing the colored
   CRIT/HIGH/MED findings and the non-zero exit. Nice-to-have alongside the CSS
   version already on the page. Dark theme, ~100 cols.

3. **CI gate failing a PR** — `docs/assets/ci-gate.png` **[you]**
   A GitHub PR checks panel where the `build` job failed because `wyrm analyze`
   found a HIGH+ finding. This is the money shot for "enforced in CI."

## Medium priority

4. **Zed Problems panel** — `docs/assets/zed-problems.png` **[pair]**
   The full list of findings for the example model in Zed's diagnostics panel.

5. **`wyrm diagram` → Mermaid preview** — `docs/assets/diagram-preview.png` **[pair]**
   `wyrm diagram` output pasted into a Markdown file, rendered in Zed's Markdown
   preview — shows the "picture with zero drawing surface" story.

## Later (once the Obsidian plugin lands)

6. **Obsidian JSON Canvas ↔ OTM** — `docs/assets/obsidian-canvas.png` **[pair]**
7. **Obsidian STRIDE register (Bases/Dataview)** — `docs/assets/obsidian-register.png` **[pair]**

## Capture tips

- macOS: `⌘⇧4` then space to grab a window with shadow; or `⌘⇧5` for a region.
- Keep a consistent dark theme across shots for a cohesive gallery.
- 2× / Retina is fine — the site scales images down.
