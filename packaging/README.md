# Packaging & distribution

Everything here is prepared so publishing to each channel is a small, well-defined
step once the credentials exist. Tracking: [issue #18](https://github.com/1ARdotNO/wyrm/issues/18).

## Prebuilt binaries (done)

Tagging `vX.Y.Z` builds `wyrm` (and `wyrm-lsp`) for macOS + Linux and publishes a
GitHub Release (`.github/workflows/release.yml`). Install:

```sh
curl -sSL https://github.com/1ARdotNO/wyrm/releases/latest/download/wyrm-x86_64-unknown-linux-gnu.tar.gz | tar -xz
```

## Homebrew (macOS/Linux) — needs a tap repo

1. Create a repo `1ARdotNO/homebrew-wyrm`.
2. Copy [`homebrew/wyrm.rb`](homebrew/wyrm.rb) to its `Formula/wyrm.rb` (real
   sha256s for v0.1.0 are already filled in).
3. Users then: `brew install 1ARdotNO/wyrm/wyrm`.
4. On each release, bump `version` + the four `sha256`s (or run
   `brew bump-formula-pr --url=<new tarball> Formula/wyrm.rb`).

## crates.io — needs `CARGO_REGISTRY_TOKEN`

Crates are publish-ready (`cargo publish --dry-run -p otm-core` passes). Publish in
dependency order:

```sh
cargo publish -p otm-core
cargo publish -p wyrm-lsp
cargo publish -p wyrm-cli
```

Then anyone can `cargo install wyrm-cli`.

## VS Code Marketplace — needs `VSCE_PAT`

1. Create a publisher `1ARdotNO` at <https://marketplace.visualstudio.com/manage>.
2. Generate an Azure DevOps PAT (Marketplace: Manage) → add as repo secret `VSCE_PAT`.
3. `cd editors/vscode && npm ci && npx @vscode/vsce publish` (a `vscode-*` tag can
   automate this). Optionally also publish to [OpenVSX](https://open-vsx.org) for
   VSCodium/Cursor.

## Obsidian community plugins

1. `cd editors/obsidian && npm ci && npm run build`, then create a GitHub Release
   whose tag == `manifest.json` version, with assets `manifest.json`, `main.js`,
   `styles.css`.
2. Submit a PR to
   [obsidianmd/obsidian-releases](https://github.com/obsidianmd/obsidian-releases)
   adding wyrm to `community-plugins.json`.

## Zed extension registry

Submit a PR to
[zed-industries/extensions](https://github.com/zed-industries/extensions) adding
the `wyrm` extension (id from `editors/zed/extension.toml`).

## JetBrains Marketplace — needs a token

Compile-verify `editors/intellij` with a JDK 17, then `./gradlew publishPlugin`
with a JetBrains Marketplace token.
