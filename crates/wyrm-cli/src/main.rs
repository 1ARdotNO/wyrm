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
        /// Exclude generated elements whose id/name matches a pattern (repeatable).
        /// `iam` is a shortcut for identity/access/policy noise.
        #[arg(long)]
        exclude: Vec<String>,
        /// Annotation file with extra context (default: `.threatmodel/data.yaml`).
        #[arg(long)]
        data: Option<PathBuf>,
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
        /// Emit findings as JSON instead of text (alias for --format json).
        #[arg(long)]
        json: bool,
        /// Output format for the findings.
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
        /// Write output to a file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
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
    /// Open a model in the wyrm GUI editor (spawns the `wyrm-gui` binary).
    Gui {
        /// Model file to edit. Defaults to the first `.otm.yaml` in `.threatmodel/`.
        file: Option<PathBuf>,
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

#[derive(Copy, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    /// SARIF 2.1.0 — for GitHub code scanning and SAST tooling.
    Sarif,
    Yaml,
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
            exclude,
            data,
        } => cmd_init(from, output, name, force, exclude, data),
        Command::Validate(t) => cmd_validate(&resolve(&t.paths)?),
        Command::Analyze {
            targets,
            fail_on,
            json,
            format,
            output,
            rules,
        } => cmd_analyze(
            &resolve(&targets.paths)?,
            fail_on.threshold(),
            format.unwrap_or(if json {
                OutputFormat::Json
            } else {
                OutputFormat::Text
            }),
            output,
            rules,
        ),
        Command::Diagram(t) => cmd_diagram(&resolve(&t.paths)?),
        Command::Import { from, file, output } => cmd_import(from, file, output),
        Command::Export {
            to,
            targets,
            output,
        } => cmd_export(to, &resolve(&targets.paths)?, output),
        Command::Gui { file } => cmd_gui(file),
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

/// Launch the GUI editor on a model. The GUI ships as a separate `wyrm-gui`
/// binary (heavy native deps), so we spawn it from PATH rather than link it.
fn cmd_gui(file: Option<PathBuf>) -> Result<ExitCode, String> {
    let file = match file {
        Some(f) => f,
        None => resolve(&[])?
            .into_iter()
            .next()
            .ok_or("no model found; pass a file: wyrm gui path.otm.yaml")?,
    };
    let bin = std::env::var("WYRM_GUI_BIN").unwrap_or_else(|_| "wyrm-gui".to_string());
    match std::process::Command::new(&bin).arg(&file).spawn() {
        Ok(_) => {
            eprintln!("Opened {} in the wyrm GUI.", file.display());
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => Err(format!(
            "could not launch `{bin}` ({e}). Install it with `cargo install --path crates/wyrm-gui` \
             or set WYRM_GUI_BIN to its path."
        )),
    }
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
    exclude: Vec<String>,
    data: Option<PathBuf>,
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
    let mut otm = build_model(&source, &text, &project)?;

    // Classify components into a deployment environment (folder convention, an
    // explicit scope→env map, or a literal label). `.threatmodel/environments.yaml`
    // tunes it; its absence uses the common `environments/<env>` layout.
    let env_cfg = {
        let p = PathBuf::from(DEFAULT_DIR).join("environments.yaml");
        match std::fs::read_to_string(&p) {
            Ok(doc) => otm_core::environ::config_from_yaml(&doc)
                .map_err(|e| format!("{}: {e}", p.display()))?,
            Err(_) => Default::default(),
        }
    };
    otm_core::environ::classify_environments(&mut otm, &env_cfg);

    // Strip excluded noise from the generated topology (before merge, so any IAM
    // the reviewer hand-annotates is never removed).
    if !exclude.is_empty() {
        let patterns: Vec<String> = exclude
            .iter()
            .flat_map(|t| otm_core::generate::expand_exclude(t))
            .collect();
        otm_core::generate::exclude(&mut otm, &patterns);
    }

    // Enrich with human-supplied context (annotation file) before merge.
    let data_path = data.or_else(|| {
        let p = PathBuf::from(DEFAULT_DIR).join("data.yaml");
        p.is_file().then_some(p)
    });
    if let Some(path) = data_path {
        let doc = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        otm_core::enrich::enrich(&mut otm, &doc).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    // Inline `# wyrm:` comments in the Terraform source win last (highest precedence).
    if looks_like_terraform(&text) {
        otm_core::enrich::enrich_inline(&mut otm, &text).map_err(|e| e.to_string())?;
    }

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

/// Terraform docs paired with their module scope — the file's directory relative
/// to the scan root. Lets the importer path-qualify resource ids that collide
/// across modules/envs (a flat walk alone clobbers same-named resources).
fn tf_docs_scoped(source: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    if walk_ext(source, &["tf"], &mut files).is_err() {
        return Vec::new();
    }
    files.sort();
    files
        .into_iter()
        .filter_map(|f| {
            let text = std::fs::read_to_string(&f).ok()?;
            let scope = f
                .parent()
                .and_then(|p| p.strip_prefix(source).ok())
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            Some((scope, text))
        })
        .collect()
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
/// Build a baseline from a source. A directory holding **both** Terraform and
/// Kubernetes manifests is imported as one model — k8s workloads are dropped into
/// the TF cluster's zone so the cluster and what runs on it live together.
/// Run a renderer (`helm template`, `kustomize build`, …) and return its stdout.
fn render(bin: &str, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| format!("`{bin}` not available ({e}); install it to import this source"))?;
    if !out.status.success() {
        return Err(format!(
            "`{bin} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Render a local Kubernetes source directory to plain manifests: a Helm chart via
/// `helm template`, a Kustomize overlay via `kustomize build`, else its raw YAML.
fn render_k8s_source(dir: &Path) -> Result<String, String> {
    if dir.join("Chart.yaml").is_file() {
        render("helm", &["template", &dir.to_string_lossy()])
    } else if dir.join("kustomization.yaml").is_file() || dir.join("kustomization.yml").is_file() {
        let d = dir.to_string_lossy().into_owned();
        render("kustomize", &["build", &d]).or_else(|_| render("kubectl", &["kustomize", &d]))
    } else {
        Ok(collect_docs(dir, &["yaml", "yml"])?.join("\n---\n"))
    }
}

/// Follow GitOps pointers — ArgoCD `Application`, Flux `Kustomization`/`HelmRelease`
/// — to the local path they deploy, render it, and return the manifests plus notes.
/// Remote git sources can't be followed offline; those become a note, not a render.
fn follow_gitops(root: &Path) -> (Vec<String>, Vec<String>) {
    let mut rendered = Vec::new();
    let mut notes = Vec::new();
    let val =
        |v: &serde_yaml_ng::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_owned);

    for doc in collect_docs(root, &["yaml", "yml"]).unwrap_or_default() {
        for part in doc.split("\n---") {
            let Ok(v) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(part) else {
                continue;
            };
            let api = val(&v, "apiVersion").unwrap_or_default();
            let kind = val(&v, "kind").unwrap_or_default();
            let Some(spec) = v.get("spec") else { continue };
            let name = v
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|x| x.as_str())
                .unwrap_or("app");

            // Collect the deploy source path(s) and whether any is a remote repo.
            let mut paths: Vec<String> = Vec::new();
            let mut remote = false;
            if api.contains("argoproj.io") && kind == "Application" {
                let mut sources = Vec::new();
                if let Some(s) = spec.get("source") {
                    sources.push(s);
                }
                if let Some(arr) = spec.get("sources").and_then(|x| x.as_sequence()) {
                    sources.extend(arr.iter());
                }
                for s in sources {
                    if let Some(p) = val(s, "path") {
                        paths.push(p);
                    }
                    if val(s, "repoURL").is_some_and(|u| u.contains("://")) {
                        remote = true;
                    }
                }
            } else if api.contains("kustomize.toolkit.fluxcd.io") && kind == "Kustomization" {
                if let Some(p) = val(spec, "path") {
                    paths.push(p);
                }
            } else if api.contains("helm.toolkit.fluxcd.io") && kind == "HelmRelease" {
                if let Some(p) = spec
                    .get("chart")
                    .and_then(|c| c.get("spec"))
                    .and_then(|s| s.get("chart"))
                    .and_then(|x| x.as_str())
                {
                    paths.push(p.to_owned());
                }
            } else {
                continue;
            }

            let mut resolved = false;
            for p in &paths {
                let dir = root.join(p.trim_start_matches("./").trim_start_matches('/'));
                if dir.is_dir() {
                    match render_k8s_source(&dir) {
                        Ok(m) => {
                            rendered.push(m);
                            resolved = true;
                        }
                        Err(e) => notes.push(format!("{kind} '{name}': {e}")),
                    }
                }
            }
            if !resolved {
                notes.push(if remote {
                    format!(
                        "{kind} '{name}' deploys from a remote repo; clone it under {} and re-run to include its workloads.",
                        root.display()
                    )
                } else {
                    format!("{kind} '{name}' source path not found under {}; skipped.", root.display())
                });
            }
        }
    }
    (rendered, notes)
}

fn build_model(source: &Path, text: &str, project: &str) -> Result<otm_core::model::Otm, String> {
    use otm_core::generate as g;

    if g::looks_like_tfplan(text) {
        // `terraform show -json` — fully expanded module-nested resources.
        return g::from_tfplan_json(text, project).map_err(|e| e.to_string());
    }

    // Helm chart / Kustomize overlay: render to plain manifests via the tool, then
    // import the result. Keeps wyrm out of the templating business.
    if source.is_dir()
        && (source.join("Chart.yaml").is_file()
            || source.join("kustomization.yaml").is_file()
            || source.join("kustomization.yml").is_file())
    {
        let rendered = render_k8s_source(source)?;
        return g::from_manifests(&rendered, project).map_err(|e| e.to_string());
    }

    // Collect each IaC kind present (a dir may carry both TF and k8s). Terraform
    // docs keep their module scope (directory) so colliding ids can be qualified.
    let tf_docs: Vec<(String, String)> = if source.is_dir() {
        tf_docs_scoped(source)
    } else if looks_like_terraform(text) {
        vec![(String::new(), text.to_string())]
    } else {
        Vec::new()
    };
    let mut k8s_text: Option<String> = if source.is_dir() {
        let joined = collect_docs(source, &["yaml", "yml"])
            .unwrap_or_default()
            .join("\n---\n");
        looks_like_k8s(&joined).then_some(joined)
    } else if looks_like_k8s(text) {
        Some(text.to_string())
    } else {
        None
    };

    // Follow GitOps pointers (ArgoCD/Flux) to the local source they deploy and fold
    // those workloads in — otherwise the referenced app is invisible to the model.
    if source.is_dir() {
        let (extra, notes) = follow_gitops(source);
        for n in notes {
            eprintln!("note: {n}");
        }
        if !extra.is_empty() {
            let joined = extra.join("\n---\n");
            k8s_text = Some(match k8s_text {
                Some(base) => format!("{base}\n---\n{joined}"),
                None => joined,
            });
        }
    }

    let has_tf = tf_docs.iter().any(|(_, d)| looks_like_terraform(d));

    let build_tf = |docs: &[(String, String)]| {
        let (otm, skipped) = g::from_terraform_scoped(docs, project);
        if skipped > 0 {
            eprintln!(
                "note: skipped {skipped} unparseable .tf file(s) (placeholders / unsupported HCL)."
            );
        }
        otm
    };

    match (has_tf, k8s_text) {
        (true, Some(k8s)) => {
            // Cross-link: fold the k8s workloads into the TF model's cluster zone.
            let tf = build_tf(&tf_docs);
            let mut k8s = g::from_manifests(&k8s, project).map_err(|e| e.to_string())?;
            g::place_in_cluster(&tf, &mut k8s);
            Ok(g::combine(tf, k8s))
        }
        (true, None) => Ok(build_tf(&tf_docs)),
        (false, Some(k8s)) => g::from_manifests(&k8s, project).map_err(|e| e.to_string()),
        (false, None) => g::from_compose(text, project).map_err(|e| e.to_string()),
    }
}

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
    format: OutputFormat,
    output: Option<PathBuf>,
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

    // OWASP Risk Rating config: org defaults from .threatmodel/risk.yaml, if any.
    let risk_cfg = {
        let p = PathBuf::from(DEFAULT_DIR).join("risk.yaml");
        if p.is_file() {
            let t = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            otm_core::risk::config_from_yaml(&t).map_err(|e| format!("{}: {e}", p.display()))?
        } else {
            otm_core::risk::RiskConfig::default()
        }
    };

    // Keep each finding's source file + line so SARIF can point at it.
    let mut all: Vec<Finding> = Vec::new();
    let mut located: Vec<(Finding, String, u32)> = Vec::new();
    for file in files {
        let source =
            std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
        let otm = otm_core::parse(&source).map_err(|e| e.to_string())?;
        let uri = file.display().to_string();
        let mut fs = lib.analyze(&otm);
        otm_core::risk::annotate(&mut fs, &otm, &risk_cfg);
        for f in fs {
            let line = otm_core::sarif::locate_line(&source, &f.element_id);
            located.push((f.clone(), uri.clone(), line));
            all.push(f);
        }
    }

    let rendered = match format {
        OutputFormat::Text => text_report(&all),
        OutputFormat::Json => serde_json::to_string_pretty(&all).map_err(|e| e.to_string())?,
        OutputFormat::Yaml => otm_core::sarif::findings_yaml(&all),
        OutputFormat::Sarif => {
            let items: Vec<otm_core::sarif::Located> = located
                .iter()
                .map(|(f, u, l)| otm_core::sarif::Located {
                    finding: f,
                    uri: u.clone(),
                    line: *l,
                })
                .collect();
            otm_core::sarif::to_sarif(&items, &lib.rules)
        }
    };

    match &output {
        Some(path) => {
            std::fs::write(path, &rendered).map_err(|e| format!("{}: {e}", path.display()))?;
            eprintln!("Wrote {} finding(s) to {}.", all.len(), path.display());
        }
        None => print!("{rendered}"),
    }

    let breached = all.iter().any(|f| f.severity >= fail_on);
    Ok(if breached {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn text_report(all: &[Finding]) -> String {
    if all.is_empty() {
        return "No findings.\n".to_string();
    }
    let mut s = String::new();
    for f in all {
        s += &format!(
            "[{}] {:?}  {}  ({})\n    {} — {}\n    ↳ {}\n",
            sev_label(f.severity),
            f.stride,
            f.title,
            f.element_name,
            f.rule_id,
            f.description.trim(),
            f.mitigation,
        );
        if let Some(r) = &f.risk {
            s += &format!(
                "    risk: {:?} (likelihood {:.1} {:?} × impact {:.1} {:?})\n",
                r.level, r.likelihood, r.likelihood_band, r.impact, r.impact_band,
            );
        }
        if f.is_residual() {
            s += "    ⚠ residual — no mitigation recorded for this serious finding\n";
        }
    }
    let residual = all.iter().filter(|f| f.is_residual()).count();
    s += &format!("\n{} finding(s)", all.len());
    if residual > 0 {
        s += &format!(", {residual} unmitigated (high+)");
    }
    s += ".\n";
    s
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

#[cfg(test)]
mod tests {
    use super::*;

    // Hermetic: raw-manifest sources need no external helm/kustomize binary.
    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wyrm-gitops-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn follows_argocd_application_to_local_path() {
        let root = scratch("argo");
        write(
            &root.join("app.yaml"),
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata: { name: web }\nspec:\n  source: { repoURL: https://github.com/x/y.git, path: apps/web }\n",
        );
        write(
            &root.join("apps/web/svc.yaml"),
            "apiVersion: v1\nkind: Service\nmetadata: { name: frontend }\nspec: { ports: [{ port: 443 }], selector: { app: f } }\n",
        );
        let (rendered, notes) = follow_gitops(&root);
        assert!(rendered.iter().any(|m| m.contains("frontend")));
        assert!(notes.is_empty(), "local path resolved, no notes: {notes:?}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn notes_remote_source_that_cannot_be_followed() {
        let root = scratch("remote");
        write(
            &root.join("app.yaml"),
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata: { name: remote }\nspec:\n  source: { repoURL: https://github.com/x/y.git, path: not/here }\n",
        );
        let (rendered, notes) = follow_gitops(&root);
        assert!(rendered.is_empty());
        assert!(notes.iter().any(|n| n.contains("remote repo")));
        std::fs::remove_dir_all(&root).ok();
    }
}
