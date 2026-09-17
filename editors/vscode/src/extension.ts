import { ExtensionContext, workspace, window } from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

export function activate(context: ExtensionContext): void {
  const serverPath = workspace.getConfiguration("wyrm").get<string>("serverPath", "wyrm-lsp");

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
