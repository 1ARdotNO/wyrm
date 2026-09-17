package dev.wyrm

import com.intellij.openapi.project.Project
import com.redhat.devtools.lsp4ij.LanguageServerFactory
import com.redhat.devtools.lsp4ij.server.ProcessStreamConnectionProvider
import com.redhat.devtools.lsp4ij.server.StreamConnectionProvider

/**
 * Wires the `wyrm-lsp` language server into JetBrains IDEs via LSP4IJ. The binary
 * must be on PATH: `cargo install --git https://github.com/1ARdotNO/wyrm wyrm-lsp`.
 */
class WyrmLanguageServerFactory : LanguageServerFactory {
    override fun createConnectionProvider(project: Project): StreamConnectionProvider =
        WyrmConnectionProvider()
}

private class WyrmConnectionProvider : ProcessStreamConnectionProvider() {
    init {
        super.setCommands(listOf("wyrm-lsp"))
    }
}
