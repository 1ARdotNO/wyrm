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
    /// Generate a baseline model from infrastructure (docker-compose).
    Init {
        /// Compose file to read (default: auto-detect in the current directory).
        #[arg(long)]
        from: Option<PathBuf>,
        /// Where to write the model (default: .threatmodel/<name>.otm.yaml; `-` for stdout).
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// Project name (default: current directory name).
        #[arg(long)]
        name: Option<String>,
        /// Overwrite an existing model instead of merging into it.
        #[arg(long)]
        force: bool,
    },
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
        /// Extra rules file to add to the bundled catalogue (defaults to
        /// `.threatmodel/rules.yaml` if present).
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Render a Mermaid data-flow diagram to stdout.
    Diagram(Targets),
    /// Import a threat model from another tool (Threagile, pytm, JSON Canvas).
    Import {
        /// Source format.
        #[arg(long, value_enum)]
        from: ImportFormat,
        /// File to import (Threagile YAML, pytm `--json`, or a `.canvas` file).
        file: PathBuf,
        /// Output path (default `.threatmodel/<name>.otm.yaml`; `-` for stdout).
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Export a model to another format (JSON Canvas).
    Export {
        /// Target format.
        #[arg(long, value_enum)]
        to: ExportFormat,
        #[command(flatten)]
        targets: Targets,
        /// Output path (`-` for stdout).
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum ImportFormat {
    Threagile,
    Pytm,
    Canvas,
}

#[derive(Copy, Clone, ValueEnum)]
enum ExportFormat {
    Canvas,
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
        Command::Init {
            from,
            output,
            name,
            force,
        } => cmd_init(from, output, name, force),
        Command::Validate(t) => cmd_validate(&resolve(&t.paths)?),
        Command::Analyze {
            targets,
            fail_on,
            json,
            rules,
        } => cmd_analyze(&resolve(&targets.paths)?, fail_on.threshold(), json, rules),
        Command::Diagram(t) => cmd_diagram(&resolve(&t.paths)?),
        Command::Import { from, file, output } => cmd_import(from, file, output),
        Command::Export {
            to,
            targets,
            output,
        } => cmd_export(to, &resolve(&targets.paths)?, output),
    }
}

fn cmd_export(
    to: ExportFormat,
    files: &[PathBuf],
    output: Option<PathBuf>,
) -> Result<ExitCode, String> {
    let file = files.first().ok_or("no model to export")?;
    let otm = otm_core::parse_file(file).map_err(|e| e.to_string())?;
    let out = match to {
        ExportFormat::Canvas => otm_core::canvas::from_otm(&otm).map_err(|e| e.to_string())?,
    };
    if matches!(output.as_deref(), Some(p) if p.as_os_str() == "-") {
        println!("{out}");
    } else {
        let dest = output.unwrap_or_else(|| file.with_extension("").with_extension("canvas"));
        std::fs::write(&dest, &out).map_err(|e| format!("{}: {e}", dest.display()))?;
        eprintln!("Wrote {}.", dest.display());
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_import(
    from: ImportFormat,
    file: PathBuf,
    output: Option<PathBuf>,
) -> Result<ExitCode, String> {
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    let otm = match from {
        ImportFormat::Threagile => otm_core::migrate::from_threagile(&text),
        ImportFormat::Pytm => otm_core::migrate::from_pytm(&text),
        ImportFormat::Canvas => otm_core::canvas::to_otm(&text),
    }
    .map_err(|e| e.to_string())?;

    let body = otm_core::to_yaml(&otm).map_err(|e| e.to_string())?;
    let doc = format!(
        "# Imported by `wyrm import` from {}.\n# Review, add mitigations, then `wyrm analyze`.\n{body}",
        file.display()
    );

    if matches!(output.as_deref(), Some(p) if p.as_os_str() == "-") {
        print!("{doc}");
        return Ok(ExitCode::SUCCESS);
    }
    let dest = output.unwrap_or_else(|| {
        PathBuf::from(DEFAULT_DIR).join(format!("{}.otm.yaml", sanitize_filename(&otm.project.id)))
    });
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(&dest, &doc).map_err(|e| format!("{}: {e}", dest.display()))?;
    eprintln!(
        "Imported {} — {} components, {} dataflows → {}.",
        file.display(),
        otm.components.len(),
        otm.dataflows.len(),
        dest.display()
    );
    eprintln!("Next: review it, then `wyrm analyze`.");
    Ok(ExitCode::SUCCESS)
}

const COMPOSE_CANDIDATES: &[&str] = &[
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
];

fn cmd_init(
    from: Option<PathBuf>,
    output: Option<PathBuf>,
    name: Option<String>,
    force: bool,
) -> Result<ExitCode, String> {
    let source = match from {
        Some(p) => p,
        None => COMPOSE_CANDIDATES
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or_else(|| {
                format!(
                    "no compose file found (looked for {}); pass --from",
                    COMPOSE_CANDIDATES.join(", ")
                )
            })?,
    };

    let project = name.unwrap_or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "project".to_string())
    });

    let text = read_source(&source)?;
    let mut otm = if looks_like_terraform(&text) {
        // Parse each .tf independently so one unparseable file (a template with
        // placeholders, or unsupported HCL) doesn't abort the whole scan.
        let docs = collect_docs(&source, &["tf"])?;
        let (otm, skipped) =
            otm_core::generate::from_terraform_docs(docs.iter().map(String::as_str), &project);
        if skipped > 0 {
            eprintln!(
                "note: skipped {skipped} unparseable .tf file(s) (placeholders / unsupported HCL)."
            );
        }
        otm
    } else if looks_like_k8s(&text) {
        otm_core::generate::from_manifests(&text, &project).map_err(|e| e.to_string())?
    } else {
        otm_core::generate::from_compose(&text, &project).map_err(|e| e.to_string())?
    };

    let stdout = matches!(output.as_deref(), Some(p) if p.as_os_str() == "-");
    let dest = (!stdout).then(|| {
        output.unwrap_or_else(|| {
            PathBuf::from(DEFAULT_DIR).join(format!("{}.otm.yaml", sanitize_filename(&project)))
        })
    });

    // Reconcile with an existing model so a reviewer's edits survive regeneration.
    let mut merged = false;
    if let Some(dest) = &dest {
        if dest.exists() && !force {
            let existing = otm_core::parse_file(dest)
                .map_err(|e| format!("existing model {}: {e}", dest.display()))?;
            otm = otm_core::generate::merge(otm, existing);
            merged = true;
        }
    }

    let body = otm_core::to_yaml(&otm).map_err(|e| e.to_string())?;
    let doc = format!(
        "# Baseline threat model generated by `wyrm init` from {}.\n\
         # Topology is regenerated; your assets/mitigations/tags are preserved on merge.\n{body}",
        source.display()
    );

    match &dest {
        None => print!("{doc}"),
        Some(dest) => {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("{}: {e}", parent.display()))?;
            }
            std::fs::write(dest, &doc).map_err(|e| format!("{}: {e}", dest.display()))?;
            let how = if merged {
                "Updated (merged — your annotations preserved)"
            } else {
                "Wrote"
            };
            eprintln!(
                "{how} {} — {} components, {} dataflows from {}.",
                dest.display(),
                otm.components.len(),
                otm.dataflows.len(),
                source.display()
            );
            eprintln!("Next: review it, then `wyrm analyze`.");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Recursively collect files with the given extensions, skipping hidden dirs
/// (`.git`, `.terraform`, …) and vendored trees so real repos scan cleanly.
fn walk_ext(dir: &Path, exts: &[&str], out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if name.starts_with('.') || matches!(name, "node_modules" | "vendor") {
                continue;
            }
            walk_ext(&path, exts, out)?;
        } else if path.is_file()
            && path
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| exts.contains(&x))
        {
            out.push(path);
        }
    }
    Ok(())
}

/// Read a file, or every matching file in a directory tree, as individual docs
/// (so each can be parsed independently and failures isolated).
fn collect_docs(source: &Path, exts: &[&str]) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    if source.is_dir() {
        walk_ext(source, exts, &mut files)?;
        files.sort();
    } else {
        files.push(source.to_path_buf());
    }
    let mut docs = Vec::with_capacity(files.len());
    for f in files {
        docs.push(std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?);
    }
    Ok(docs)
}

/// Read a source file, or concatenate a directory into one stream. A directory of
/// Terraform (`.tf`) is preferred (joined with newlines); otherwise YAML files are
/// joined as a multi-document manifest stream.
fn read_source(source: &Path) -> Result<String, String> {
    if !source.is_dir() {
        return std::fs::read_to_string(source).map_err(|e| format!("{}: {e}", source.display()));
    }

    let gather = |exts: &[&str]| -> Result<Vec<PathBuf>, String> {
        let mut files = Vec::new();
        walk_ext(source, exts, &mut files)?;
        files.sort();
        Ok(files)
    };

    let concat = |files: Vec<PathBuf>, sep: &str| -> Result<String, String> {
        let mut parts = Vec::new();
        for f in files {
            parts.push(std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?);
        }
        Ok(parts.join(sep))
    };

    let tf = gather(&["tf"])?;
    if !tf.is_empty() {
        return concat(tf, "\n");
    }
    let yaml = gather(&["yaml", "yml"])?;
    if !yaml.is_empty() {
        return concat(yaml, "\n---\n");
    }
    Err(format!("no .tf/.yaml/.yml files in {}", source.display()))
}

/// Heuristic: does this look like Kubernetes/Istio manifests vs a compose file?
fn looks_like_k8s(text: &str) -> bool {
    text.lines()
        .map(str::trim_start)
        .any(|l| l.starts_with("apiVersion:") || l.starts_with("kind:"))
}

/// Heuristic: does this look like Terraform (HCL)?
fn looks_like_terraform(text: &str) -> bool {
    text.lines().map(str::trim_start).any(|l| {
        l.starts_with("resource \"")
            || l.starts_with("provider \"")
            || l.starts_with("module \"")
            || l.starts_with("terraform {")
    })
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

const RULES_FILE: &str = "rules.yaml";

fn cmd_analyze(
    files: &[PathBuf],
    fail_on: Severity,
    json: bool,
    rules: Option<PathBuf>,
) -> Result<ExitCode, String> {
    let mut lib = otm_core::ThreatLibrary::bundled();

    // Extend with a user catalogue: an explicit --rules file, else
    // .threatmodel/rules.yaml if it exists.
    let extra = rules.or_else(|| {
        let default = PathBuf::from(DEFAULT_DIR).join(RULES_FILE);
        default.is_file().then_some(default)
    });
    if let Some(path) = extra {
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let custom = otm_core::ThreatLibrary::from_yaml(&text)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        lib.rules.extend(custom.rules);
    }

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
