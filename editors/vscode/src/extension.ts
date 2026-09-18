import { ExtensionContext, workspace, window, commands } from "vscode";
import { spawn } from "child_process";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

export function activate(context: ExtensionContext): void {
  const serverPath = workspace.getConfiguration("wyrm").get<string>("serverPath", "wyrm-lsp");

  // "Open in GUI editor" — spawn wyrm-gui on the active .otm.yaml in its own window.
  context.subscriptions.push(
    commands.registerCommand("wyrm.openGui", () => {
      const doc = window.activeTextEditor?.document;
      if (!doc || !/\.otm\.ya?ml$/.test(doc.fileName)) {
        window.showWarningMessage("Wyrm: open a .otm.yaml file first.");
        return;
      }
      void doc.save();
      const guiPath = workspace.getConfiguration("wyrm").get<string>("guiPath", "wyrm-gui");
      const child = spawn(guiPath, [doc.fileName], { detached: true, stdio: "ignore" });
      child.on("error", () =>
        window.showErrorMessage(
          `Wyrm: could not launch '${guiPath}'. Install it with: ` +
            `cargo install --git https://github.com/1ARdotNO/wyrm wyrm-gui`,
        ),
      );
      child.unref();
    }),
  );

  const serverOptions: ServerOptions = {
    command: serverPath,
    transport: TransportKind.stdio,
  };

  // Attach by file pattern so `.otm.yaml` files keep native YAML highlighting
  // while wyrm-lsp supplies the diagnostics.
  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", pattern: "**/*.otm.yaml" },
      { scheme: "file", pattern: "**/*.otm.yml" },
    ],
  };

  client = new LanguageClient("wyrm", "Wyrm", serverOptions, clientOptions);
  client.start().catch(() => {
    window.showErrorMessage(
      `Wyrm: could not start '${serverPath}'. Install it with: ` +
        `cargo install --git https://github.com/1ARdotNO/wyrm wyrm-lsp`,
    );
  });

  context.subscriptions.push({ dispose: () => void client?.stop() });
}

export function deactivate(): Thenable<void> | undefined {
  return client?.stop();
}
