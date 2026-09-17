# Wyrm — IntelliJ / JetBrains plugin

Live threat-model diagnostics in JetBrains IDEs (IntelliJ IDEA, GoLand, PyCharm,
…): open a `*.otm.yaml` file and wyrm validates it and runs STRIDE rules via the
`wyrm-lsp` language server, using [LSP4IJ](https://github.com/redhat-developer/lsp4ij)
for the LSP integration.

> **Status: scaffold.** Unlike the Zed/VS Code/Obsidian plugins, this one was
> **not compiled** in the environment it was authored in (no JDK/Gradle available).
> The structure follows the documented LSP4IJ `LanguageServerFactory` pattern, but
> pin the plugin/platform versions to your toolchain and verify the LSP4IJ API
> against the version you build with before publishing.

## Prerequisites

- JDK 17+ and Gradle (the wrapper will fetch Gradle).
- Install the LSP4IJ plugin in your IDE (the Gradle build also declares it).
- `wyrm-lsp` on PATH: `cargo install --git https://github.com/1ARdotNO/wyrm wyrm-lsp`.

## Build & run

```sh
./gradlew buildPlugin      # produces build/distributions/*.zip
./gradlew runIde           # launches a sandbox IDE with the plugin
```

Open any `.otm.yaml` file — diagnostics appear inline and in the Problems view.
