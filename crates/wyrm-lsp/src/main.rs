//! wyrm-lsp — a language server for OTM threat models.
//!
//! Thin transport around [`otm_core`]: on every open/change it recomputes
//! diagnostics (structural validation + STRIDE findings) and publishes them.
//! Full-document sync keeps it simple; models are small.

mod diagnostics;

use lsp_server::{Connection, Message, Notification};
use lsp_types::{
    DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams,
    PublishDiagnosticsParams, ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind,
    Uri,
};
use std::error::Error;

type Res<T> = Result<T, Box<dyn Error + Sync + Send>>;

fn main() -> Res<()> {
    let (connection, io_threads) = Connection::stdio();

    let capabilities = serde_json::to_value(ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        ..Default::default()
    })?;
    connection.initialize(capabilities)?;

    main_loop(&connection)?;
    io_threads.join()?;
    Ok(())
}

fn main_loop(connection: &Connection) -> Res<()> {
    for msg in &connection.receiver {
        match msg {
            Message::Request(req) => {
                if connection.handle_shutdown(&req)? {
                    return Ok(());
                }
            }
            Message::Notification(notif) => handle_notification(connection, notif)?,
            Message::Response(_) => {}
        }
    }
    Ok(())
}

fn handle_notification(connection: &Connection, notif: Notification) -> Res<()> {
    match notif.method.as_str() {
        "textDocument/didOpen" => {
            let p: DidOpenTextDocumentParams = serde_json::from_value(notif.params)?;
            publish(connection, p.text_document.uri, &p.text_document.text)?;
        }
        "textDocument/didChange" => {
            let p: DidChangeTextDocumentParams = serde_json::from_value(notif.params)?;
            // Full sync: the final change carries the whole document.
            if let Some(change) = p.content_changes.into_iter().next_back() {
                publish(connection, p.text_document.uri, &change.text)?;
            }
        }
        "textDocument/didClose" => {
            let p: DidCloseTextDocumentParams = serde_json::from_value(notif.params)?;
            // Clear the editor's squiggles for a closed file.
            publish(connection, p.text_document.uri, "")?;
        }
        _ => {}
    }
    Ok(())
}

fn publish(connection: &Connection, uri: Uri, text: &str) -> Res<()> {
    let params = PublishDiagnosticsParams {
        uri,
        diagnostics: diagnostics::compute(text),
        version: None,
    };
    let notif = Notification::new(
        "textDocument/publishDiagnostics".to_string(),
        serde_json::to_value(params)?,
    );
    connection.sender.send(Message::Notification(notif))?;
    Ok(())
}
