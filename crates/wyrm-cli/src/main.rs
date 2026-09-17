//! wyrm — threat modeling that lives with your code.
//!
//! Thin CLI over `otm-core`. All analysis lives in the core crate; this binary
//! only handles argument parsing, file discovery, and output formatting.

use clap::{Parser, Subcommand, ValueEnum};
use otm_core::rules::{Finding, Severity};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Default in-repo location for threat models — they live with the code.
const DEFAULT_DIR: &str = ".threatmodel";

#[derive(Parser)]
#[command(
    name = "wyrm",
    version,
    about = "Threat modeling that lives with your code"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check structural integrity of model(s) (references, duplicate ids).
    Validate(Targets),
    /// Run the STRIDE rule engine and report findings.
    Analyze {
        #[command(flatten)]
        targets: Targets,
        /// Fail (non-zero exit) if any finding is at or above this severity.
        #[arg(long, value_enum, default_value_t = SeverityArg::High)]
        fail_on: SeverityArg,
        /// Emit findings as JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Render a Mermaid data-flow diagram to stdout.
    Diagram(Targets),
}

#[derive(clap::Args)]
struct Targets {
    /// Model files or directories. Defaults to `.threatmodel/` in the cwd.
    paths: Vec<PathBuf>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityArg {
    fn threshold(self) -> Severity {
        match self {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Command::Validate(t) => cmd_validate(&resolve(&t.paths)?),
        Command::Analyze {
            targets,
            fail_on,
            json,
        } => cmd_analyze(&resolve(&targets.paths)?, fail_on.threshold(), json),
        Command::Diagram(t) => cmd_diagram(&resolve(&t.paths)?),
    }
}

fn cmd_validate(files: &[PathBuf]) -> Result<ExitCode, String> {
    let mut clean = true;
    for file in files {
        let otm = otm_core::parse_file(file).map_err(|e| e.to_string())?;
        let diags = otm_core::validate(&otm);
        if diags.is_empty() {
            println!("✓ {}  ok", file.display());
        } else {
            clean = false;
            println!("✗ {}", file.display());
            for d in &diags {
                let tag = match d.severity {
                    otm_core::validate::Severity::Error => "error",
                    otm_core::validate::Severity::Warning => "warn ",
                };
                println!("  {tag}  [{}] {}", d.code, d.message);
            }
        }
    }
    Ok(if clean {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn cmd_analyze(files: &[PathBuf], fail_on: Severity, json: bool) -> Result<ExitCode, String> {
    let lib = otm_core::ThreatLibrary::bundled();
    let mut all: Vec<Finding> = Vec::new();
    for file in files {
        let otm = otm_core::parse_file(file).map_err(|e| e.to_string())?;
        all.extend(lib.analyze(&otm));
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&all).map_err(|e| e.to_string())?
        );
    } else if all.is_empty() {
        println!("No findings.");
    } else {
        for f in &all {
            println!(
                "[{}] {:?}  {}  ({})\n    {} — {}\n    ↳ {}",
                sev_label(f.severity),
                f.stride,
                f.title,
                f.element_name,
                f.rule_id,
                f.description.trim(),
                f.mitigation,
            );
        }
        println!("\n{} finding(s).", all.len());
    }

    let breached = all.iter().any(|f| f.severity >= fail_on);
    Ok(if breached {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_diagram(files: &[PathBuf]) -> Result<ExitCode, String> {
    for file in files {
        let otm = otm_core::parse_file(file).map_err(|e| e.to_string())?;
        println!("```mermaid");
        print!("{}", otm_core::render::mermaid(&otm));
        println!("```");
    }
    Ok(ExitCode::SUCCESS)
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Low => "LOW",
        Severity::Medium => "MED",
        Severity::High => "HIGH",
        Severity::Critical => "CRIT",
    }
}

/// Expand the given paths into concrete `*.otm.yaml`/`*.otm.json` files. With no
/// paths, scan the default `.threatmodel/` directory.
fn resolve(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let roots: Vec<PathBuf> = if paths.is_empty() {
        vec![PathBuf::from(DEFAULT_DIR)]
    } else {
        paths.to_vec()
    };

    let mut files = Vec::new();
    for root in roots {
        if root.is_dir() {
            collect_dir(&root, &mut files)?;
        } else if root.is_file() {
            files.push(root);
        } else {
            return Err(format!("no such file or directory: {}", root.display()));
        }
    }
    files.sort();
    if files.is_empty() {
        return Err(format!(
            "no threat models found (looked for *.otm.yaml / *.otm.json under {DEFAULT_DIR}/)"
        ));
    }
    Ok(files)
}

fn collect_dir(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_file() && is_model(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_model(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    name.ends_with(".otm.yaml") || name.ends_with(".otm.yml") || name.ends_with(".otm.json")
}
