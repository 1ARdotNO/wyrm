//! Wyrm Zed extension.
//!
//! Registers the OTM language and launches `wyrm-lsp`, which supplies live
//! validation and STRIDE diagnostics. The language server binary is expected on
//! PATH (`cargo install --git https://github.com/1ARdotNO/wyrm wyrm-lsp`, or a
//! release build on PATH); a future revision can download it from GitHub
//! releases automatically.

use zed_extension_api::{self as zed, Command, LanguageServerId, Result, Worktree};

struct WyrmExtension;

impl zed::Extension for WyrmExtension {
    fn new() -> Self {
        WyrmExtension
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> Result<Command> {
        let path = worktree.which("wyrm-lsp").ok_or_else(|| {
            "wyrm-lsp not found on PATH — install it with: \
             cargo install --git https://github.com/1ARdotNO/wyrm wyrm-lsp"
                .to_string()
        })?;

        Ok(Command {
            command: path,
            args: Vec::new(),
            env: worktree.shell_env(),
        })
    }
}

zed::register_extension!(WyrmExtension);
