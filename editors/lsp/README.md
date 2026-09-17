# Wyrm for any LSP editor

wyrm ships a language server, `wyrm-lsp`, so **any editor with an LSP client** can
show live OTM validation and STRIDE diagnostics on `*.otm.yaml` files. Zed, VS
Code, and the JetBrains family have dedicated packages (see `editors/`); this
folder has drop-in configs for everything else.

**Prerequisite:** `wyrm-lsp` on your PATH —
`cargo install --git https://github.com/1ARdotNO/wyrm wyrm-lsp`.

The universal recipe: **run `wyrm-lsp` over stdio, scoped to `*.otm.yaml` / `*.otm.yml`.**

| Editor | Config | Client |
|---|---|---|
| Neovim (0.11+) | [`neovim.lua`](neovim.lua) | built-in `vim.lsp` |
| Emacs | [`emacs.el`](emacs.el) | Eglot |
| Sublime Text | [`sublime-LSP.json`](sublime-LSP.json) + [`OTM.sublime-syntax`](OTM.sublime-syntax) | LSP package |
| Helix | see below | built-in |
| JetBrains (all IDEs) | [`../intellij`](../intellij) | LSP4IJ plugin |

## Helix

`languages.toml`:

```toml
[language-server.wyrm]
command = "wyrm-lsp"

[[language]]
name = "otm"
scope = "source.yaml"
file-types = [{ glob = "*.otm.yaml" }, { glob = "*.otm.yml" }]
grammar = "yaml"
language-servers = ["wyrm"]
```

## Anything else

Point your editor's LSP client at the command `wyrm-lsp` (stdio) for documents
matching `*.otm.yaml`. That's it — the server does the rest.
