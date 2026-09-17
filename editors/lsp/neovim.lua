-- Wyrm LSP for OTM threat models in Neovim (0.11+, native vim.lsp API).
-- Requires wyrm-lsp on PATH:
--   cargo install --git https://github.com/1ARdotNO/wyrm wyrm-lsp
--
-- Drop this in your config (e.g. source it from init.lua).

-- Treat *.otm.yaml as a yaml filetype with an `otm` sub-type (keeps YAML syntax).
vim.filetype.add({
  pattern = {
    [".*%.otm%.ya?ml"] = "yaml.otm",
  },
})

vim.lsp.config.wyrm = {
  cmd = { "wyrm-lsp" },
  filetypes = { "yaml.otm" },
  root_markers = { ".threatmodel", ".git" },
}

vim.lsp.enable("wyrm")

-- Older Neovim / nvim-lspconfig users: define the client manually instead —
--   require("lspconfig.configs").wyrm = {
--     default_config = { cmd = { "wyrm-lsp" }, filetypes = { "yaml" },
--       root_dir = require("lspconfig.util").root_pattern(".threatmodel", ".git") },
--   }
--   require("lspconfig").wyrm.setup({})
