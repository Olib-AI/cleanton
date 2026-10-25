use std::path::PathBuf;

use clap::{Parser, Subcommand};
use cleanton_common::{
    CleantonConfig, CleantonError, CleanupAction, ExecutionResult, Result, ScanError, ScanResult,
    display,
};
use cleanton_engine::{
    ActionAnnotation, AnalyzedFull, AnalyzedPlan, DockerAnalysis, DockerCleaner, DockerCleanupPlan,
    DockerCleanupResult, MlAdjustment, ORPHAN_CATEGORY, Orchestrator, Suggestions,
};
use cleanton_recipes::RecipeSet;
use cleanton_scanner::ScanOptions;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

mod fda;

const WARNING_PRINT_LIMIT: usize = 5;

/// Cap on recipe groups printed in the human plan summary. There are typically
/// tens of groups, not thousands, but a pathological plan is still bounded.
const GROUP_PRINT_LIMIT: usize = 40;

/// Bumped to 2 when the `plan`/`clean` JSON gained per-action ML annotation
/// fields (`ml_label`, `ml_confidence`, `adjustment`, `ml_note`) and the
/// top-level `held` array. All previously emitted fields are still present.
const JSON_SCHEMA_VERSION: u64 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "cleanton",
    version,
    about = "Rust-native macOS disk cleaner by Olib AI",
    after_help = "Cleanton by Olib AI · https://www.olib.ai"
)]
struct Cli {
    #[arg(short, long, global = true, value_name = "PATH")]
    root: Vec<PathBuf>,

    #[arg(short, long, global = true)]
    json: bool,

    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(long, global = true, value_name = "DEPTH")]
    max_depth: Option<usize>,

    #[arg(long, global = true)]
    follow_symlinks: bool,

    #[arg(long, global = true)]
    include_cloud: bool,

    #[arg(long, global = true)]
    include_external_volumes: bool,

    #[arg(long, global = true, value_name = "PATTERN")]
    exclude: Vec<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    Plan,
    Clean {
        #[arg(short = 'n', long)]
        dry_run: bool,

        #[arg(short = 'y', long)]
        yes: bool,
    },
    Recipes {
        #[command(subcommand)]
        command: RecipeCommand,
    },
    Services {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    Docker {
        #[command(subcommand)]
        command: DockerCommand,
    },
    Config {
        #[command(subcommand)]
        command: Option<ConfigCommand>,
    },
    /// Diagnose Full Disk Access and print first-run permission guidance.
    Doctor,
    /// Read-only supply-chain security scan of installed packages (npm/pnpm/
    /// bun/yarn globals, Python site-packages, VS Code/Cursor extensions;
    /// `--root` adds project `node_modules`/venv trees under that root).
    /// The first run records the installed set as a trusted baseline; later
    /// runs show the DIFF: new, updated, and — the high signal — packages
    /// changed WITHOUT a version bump. Known unchanged packages are suppressed,
    /// and heuristic verdicts alert only when CORROBORATED (a known-malware
    /// signature, or critical findings across two distinct attack categories
    /// with at least one anchored in an install/lifecycle script — runtime
    /// bundles and CI/test/docs contexts never corroborate by themselves);
    /// everything else is a neutral notice.
    /// Detection and notification only — nothing is removed or modified; only
    /// the baseline metadata file is ever written.
    /// Exit codes: 0 = no alerts (notices and a fresh baseline are fine),
    /// 3 = a corroborated suspicious alert, 5 = a corroborated malicious
    /// alert or any package changed without a version bump.
    Security {
        /// Record the CURRENT package set as the trusted baseline (even when
        /// a baseline already exists).
        #[arg(long)]
        establish_baseline: bool,

        /// Also list AV-flagged packages that are unchanged since the
        /// baseline (the raw pre-baseline view; never affects the exit code).
        #[arg(long)]
        all: bool,

        /// Mark a flagged package as reviewed/trusted (repeatable). Updates
        /// only the baseline file — the package itself is never touched.
        #[arg(long, value_name = "PACKAGE")]
        review: Vec<String>,

        /// Mark EVERY flagged package as reviewed/trusted.
        #[arg(long)]
        review_all: bool,

        /// Override the baseline file location
        /// (default: `~/.config/cleanton/security_baseline.json`).
        #[arg(long, value_name = "PATH")]
        baseline: Option<PathBuf>,
    },
    /// Watch installed packages continuously and report new risk as it
    /// appears (the lightweight background helper).
    ///
    /// Cheap by construction: while nothing changes the watcher costs one
    /// `stat` per package root per tick and sleeps in between, backing off from
    /// the base interval to 15 minutes on a quiet machine. When a package
    /// manager installs or updates something, only the affected directories are
    /// examined: an advisory lookup by version, a lifecycle-hook check, and one
    /// content scan of that single package — so a newly installed package is
    /// checked immediately without rescanning everything.
    ///
    /// Read-only, like the rest of the security engine: it reports and never
    /// removes, quarantines, or modifies a package.
    Watch {
        /// Base idle interval between checks, in seconds.
        #[arg(long, default_value_t = 30, value_name = "SECONDS")]
        interval: u64,
        /// Take one pass and exit (for cron, or a launchd `StartInterval` job).
        #[arg(long)]
        once: bool,
        /// Print a launchd agent definition for this watcher and exit (macOS).
        /// It is printed, never installed: writing to `~/Library/LaunchAgents`
        /// stays the user's decision.
        #[arg(long)]
        print_agent: bool,
    },
    Interactive,
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum ConfigCommand {
    Path,
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum RecipeCommand {
    Validate,
    List,
}

#[derive(Debug, Clone, Subcommand)]
enum ServiceCommand {
    List,
    Status {
        #[arg(value_name = "SERVICE_ID")]
        service_id: String,
    },
    Start {
        #[arg(value_name = "SERVICE_ID")]
        service_id: String,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    Stop {
        #[arg(value_name = "SERVICE_ID")]
        service_id: String,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    Restart {
        #[arg(value_name = "SERVICE_ID")]
        service_id: String,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    Enable {
        #[arg(value_name = "SERVICE_ID")]
        service_id: String,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    Disable {
        #[arg(value_name = "SERVICE_ID")]
        service_id: String,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    DeleteOrphanedPlist {
        #[arg(value_name = "SERVICE_ID")]
        service_id: String,
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum DockerCommand {
    Analyze,
    Clean {
        #[arg(long)]
        dangling_images: bool,

        #[arg(long)]
        stopped_containers: bool,

        #[arg(long)]
        build_cache: bool,

        #[arg(long)]
        unused_volumes: bool,

        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let result = run_app(cli).await;
    match result {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    }
}

async fn run_app(cli: Cli) -> Result<i32> {
    let command = cli.command.clone().unwrap_or(Command::Interactive);

    if let Command::Config {
        command: Some(ConfigCommand::Path),
    } = command
    {
        return run_config_path(cli.json);
    }

    // `doctor` is a diagnostics path: it must work even if the config cannot be
    // loaded, so it runs before config loading like `config path`.
    if let Command::Doctor = command {
        return run_doctor(cli.json);
    }

    let config = CleantonConfig::load()?;

    match command {
        Command::Plan => run_plan(&cli, &config).await,
        Command::Clean { dry_run, yes } => run_clean(&cli, &config, dry_run, yes).await,
        Command::Recipes { command } => run_recipes(command, cli.json),
        Command::Services { command } => run_services(&config, command, cli.json).await,
        Command::Docker { command } => run_docker(command, cli.json).await,
        Command::Config { command: None } => {
            print_json(&config)?;
            Ok(0)
        }
        Command::Config {
            command: Some(ConfigCommand::Path),
        } => unreachable!("config path is handled before config loading"),
        Command::Doctor => unreachable!("doctor is handled before config loading"),
        Command::Security {
            establish_baseline,
            all,
            review,
            review_all,
            baseline,
        } => run_security(&cli, establish_baseline, all, &review, review_all, baseline),
        Command::Watch {
            interval,
            once,
            print_agent,
        } => Ok(run_watch(&cli, interval, once, print_agent)),
        Command::Interactive => run_interactive(&cli, &config).await,
    }
}

fn run_config_path(json: bool) -> Result<i32> {
    let Some(path) = CleantonConfig::config_path() else {
        return Err(CleantonError::Config(
            "could not determine config path because HOME is not set".to_owned(),
        ));
    };

    if json {
        print_json(&serde_json::json!({
            "path": path,
        }))?;
    } else {
        println!("{}", path.display());
    }
    Ok(0)
}

/// `cleanton doctor`: report the Full Disk Access situation and print clear,
/// non-alarming, context-correct guidance. Always exits 0 — it is informational
/// diagnostics and never an error.
fn run_doctor(json: bool) -> Result<i32> {
    let context = fda::host_context();
    let status = fda::probe();
    let guidance = fda::guidance_lines(context);

    if json {
        print_json(&serde_json::json!({
            "host_context": context.as_str(),
            "terminal": fda::terminal_label(),
            "full_disk_access": status.as_str(),
            "headline": fda::headline(context),
            "settings_url": fda::SETTINGS_FDA_URL,
            "guidance": guidance,
        }))?;
        return Ok(0);
    }

    println!("Cleanton doctor: Full Disk Access");
    println!("  host: {}", fda::headline(context));
    let status_label = match status {
        fda::FdaStatus::Granted => "looks granted (a protected location was readable)",
        fda::FdaStatus::LikelyMissing => "likely MISSING (a protected location was denied)",
        fda::FdaStatus::Unknown => "could not be determined",
    };
    println!("  full disk access: {status_label}");

    if status.is_likely_missing() || matches!(status, fda::FdaStatus::Unknown) {
        println!();
        for line in &guidance {
            println!("{line}");
        }
    } else {
        println!(
            "  No action needed. If a scan still reports skipped locations, some categories \
             require re-consent between runs."
        );
    }
    Ok(0)
}

/// Print a concise, non-alarming Full Disk Access pointer to stderr when a scan
/// came back incomplete or with permission warnings *and* a probe suggests FDA
/// is missing. Written to stderr so it never corrupts `--json` stdout, and only
/// emitted once per invocation.
fn maybe_print_fda_hint(incomplete: bool, warning_count: usize) {
    if !incomplete && warning_count == 0 {
        return;
    }
    if !fda::probe().is_likely_missing() {
        return;
    }
    let context = fda::host_context();
    eprintln!();
    eprintln!("Some locations were skipped due to missing permissions.");
    eprintln!("  {}", fda::headline(context));
    eprintln!("  Run `cleanton doctor` for step-by-step Full Disk Access guidance.");
}

async fn run_docker(command: DockerCommand, json: bool) -> Result<i32> {
    let cleaner = DockerCleaner::new()?;
    match command {
        DockerCommand::Analyze => {
            let analysis = cleaner.analyze().await?;
            if json {
                print_json(&analysis)?;
            } else {
                print_docker_analysis(&analysis);
            }
            if analysis.total_reclaimable == 0 {
                Ok(2)
            } else {
                Ok(0)
            }
        }
        DockerCommand::Clean {
            dangling_images,
            stopped_containers,
            build_cache,
            unused_volumes,
            yes,
        } => {
            let plan = DockerCleanupPlan {
                clean_dangling_images: dangling_images,
                clean_stopped_containers: stopped_containers,
                clean_unused_volumes: unused_volumes,
                clean_build_cache: build_cache,
            };

            if !docker_plan_has_actions(&plan) {
                if json {
                    print_json(&serde_json::json!({
                        "ok": false,
                        "message": "select at least one Docker cleanup target"
                    }))?;
                } else {
                    eprintln!(
                        "No Docker cleanup target selected. Pass one or more of --dangling-images, --stopped-containers, --build-cache, or --unused-volumes."
                    );
                }
                return Ok(2);
            }

            if !yes {
                let analysis = cleaner.analyze().await?;
                if json {
                    print_json(&serde_json::json!({
                        "dry_run": true,
                        "requires_confirmation": true,
                        "plan": plan,
                        "analysis": analysis,
                        "message": "pass --yes to apply this Docker cleanup plan"
                    }))?;
                } else {
                    print_docker_analysis(&analysis);
                    println!("Docker cleanup dry run");
                    println!(
                        "  dangling images: {}",
                        bool_label(plan.clean_dangling_images)
                    );
                    println!(
                        "  stopped containers: {}",
                        bool_label(plan.clean_stopped_containers)
                    );
                    println!("  build cache: {}", bool_label(plan.clean_build_cache));
                    println!(
                        "  unused volumes: {}",
                        bool_label(plan.clean_unused_volumes)
                    );
                    println!("Pass --yes to apply this Docker cleanup plan.");
                }
                return Ok(0);
            }

            let result = cleaner.clean(plan).await?;
            if json {
                print_json(&result)?;
            } else {
                print_docker_cleanup_result(&result);
            }
            Ok(0)
        }
    }
}

fn docker_plan_has_actions(plan: &DockerCleanupPlan) -> bool {
    plan.clean_dangling_images
        || plan.clean_stopped_containers
        || plan.clean_unused_volumes
        || plan.clean_build_cache
}

async fn run_services(config: &CleantonConfig, command: ServiceCommand, json: bool) -> Result<i32> {
    let manager = cleanton_services::ServiceManager::new(config.clone());
    match command {
        ServiceCommand::List => {
            let services = manager.list_services().await?;
            let discovery = cleanton_services::ServiceDiscovery {
                services,
                errors: Vec::new(),
            };
            if json {
                print_json(&discovery)?;
            } else {
                for service in &discovery.services {
                    let marker =
                        if cleanton_services::is_protected(&service.id, &service.plist_path) {
                            "read-only"
                        } else {
                            "mutable"
                        };
                    println!("{} {:?} {}", service.id, service.service_type, marker);
                }
            }
            Ok(0)
        }
        ServiceCommand::Status { service_id } => {
            let status = manager.get_status(&service_id).await?;
            if json {
                print_json(&serde_json::json!({
                    "service_id": service_id,
                    "status": status,
                }))?;
            } else {
                println!("{service_id}: {}", service_status_label(&status));
            }
            Ok(0)
        }
        ServiceCommand::Start { service_id, yes } => {
            run_service_mutation(json, &service_id, "start", yes, || async {
                manager.start_service(&service_id).await
            })
            .await
        }
        ServiceCommand::Stop { service_id, yes } => {
            run_service_mutation(json, &service_id, "stop", yes, || async {
                manager.stop_service(&service_id).await
            })
            .await
        }
        ServiceCommand::Restart { service_id, yes } => {
            run_service_mutation(json, &service_id, "restart", yes, || async {
                manager.restart_service(&service_id).await
            })
            .await
        }
        ServiceCommand::Enable { service_id, yes } => {
            run_service_mutation(json, &service_id, "enable", yes, || async {
                manager.enable_service(&service_id).await
            })
            .await
        }
        ServiceCommand::Disable { service_id, yes } => {
            run_service_mutation(json, &service_id, "disable", yes, || async {
                manager.disable_service(&service_id).await
            })
            .await
        }
        ServiceCommand::DeleteOrphanedPlist { service_id, yes } => {
            run_service_mutation(json, &service_id, "delete-orphaned-plist", yes, || async {
                manager.delete_orphaned_plist(&service_id).await
            })
            .await
        }
    }
}

async fn run_service_mutation<F, Fut>(
    json: bool,
    service_id: &str,
    operation: &str,
    yes: bool,
    execute: F,
) -> Result<i32>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    if !yes {
        if json {
            print_json(&serde_json::json!({
                "ok": false,
                "service_id": service_id,
                "operation": operation,
                "requires_confirmation": true,
                "message": "pass --yes to apply this service mutation"
            }))?;
        } else {
            eprintln!(
                "Refusing to {operation} {service_id}: pass --yes to apply this service mutation."
            );
        }
        return Ok(3);
    }

    execute().await?;

    if json {
        print_json(&serde_json::json!({
            "ok": true,
            "service_id": service_id,
            "operation": operation,
        }))?;
    } else {
        println!("{operation} applied to {service_id}");
    }
    Ok(0)
}

fn service_status_label(status: &cleanton_services::ServiceStatus) -> String {
    match status {
        cleanton_services::ServiceStatus::Running { pid, .. } => format!("running (pid {pid})"),
        cleanton_services::ServiceStatus::Stopped => "stopped".to_owned(),
        cleanton_services::ServiceStatus::Loaded => "loaded".to_owned(),
        cleanton_services::ServiceStatus::Error(message) => format!("error ({message})"),
    }
}

async fn run_plan(cli: &Cli, config: &CleantonConfig) -> Result<i32> {
    let orchestrator = Orchestrator::new(config.clone())?;
    let (event_tx, _event_rx) = mpsc::channel(128);
    let options = scan_options(cli, config);
    warn_unscannable_roots(&options.roots);

    // Full Results view: the ML-aware filesystem plan, Docker accounting
    // (root-independent), and review-only suggestions (duplicates + large items).
    let scan = orchestrator.scan_only(options, event_tx).await?;
    let full = orchestrator.analyze_full(&scan).await;
    if cli.json {
        print_json(&full_json(&scan, &full)?)?;
    } else {
        print_analyzed_summary(&full.analyzed, Some(&scan));
        print_docker_section(&full.docker);
        print_suggestions_section(&full.suggestions);
    }

    maybe_print_fda_hint(full.analyzed.plan.incomplete_scan, scan.errors.len());

    // Exit codes reflect the executable plan only; held/demoted items are not
    // part of `analyzed.plan.actions` and never auto-execute.
    if full.analyzed.plan.incomplete_scan {
        Ok(4)
    } else if full.analyzed.plan.actions.is_empty() {
        Ok(2)
    } else {
        Ok(0)
    }
}

async fn run_clean(cli: &Cli, config: &CleantonConfig, dry_run: bool, yes: bool) -> Result<i32> {
    let orchestrator = Orchestrator::new(config.clone())?;
    let (event_tx, _event_rx) = mpsc::channel(128);
    let options = scan_options(cli, config);
    warn_unscannable_roots(&options.roots);

    let scan = orchestrator.scan_only(options, event_tx.clone()).await?;
    let analyzed = orchestrator.analyze(&scan);

    if dry_run || !yes {
        if cli.json {
            print_json(&analyzed_json(&scan, &analyzed)?)?;
        } else {
            print_analyzed_summary(&analyzed, Some(&scan));
        }
        if !yes && !dry_run {
            eprintln!("Dry run only. Pass --yes to execute the displayed plan.");
        }
        maybe_print_fda_hint(analyzed.plan.incomplete_scan, scan.errors.len());
        if analyzed.plan.incomplete_scan {
            return Ok(4);
        } else if analyzed.plan.actions.is_empty() {
            return Ok(2);
        }
        return Ok(0);
    }

    if analyzed.plan.incomplete_scan {
        if cli.json {
            print_json(&analyzed_json(&scan, &analyzed)?)?;
        } else {
            print_analyzed_summary(&analyzed, Some(&scan));
        }
        eprintln!("Execution refused: incomplete scan due to permission issues.");
        maybe_print_fda_hint(true, scan.errors.len());
        return Ok(4);
    }

    if analyzed.plan.actions.is_empty() {
        if cli.json {
            print_json(&analyzed_json(&scan, &analyzed)?)?;
        } else {
            print_analyzed_summary(&analyzed, Some(&scan));
        }
        return Ok(2);
    }

    // Only `analyzed.plan` is executed. Held/demoted candidates are excluded by
    // construction, so a one-shot `clean --yes` can never act on them.
    let execution = orchestrator.execute_plan(&analyzed.plan, &event_tx)?;
    if cli.json {
        print_json(&execution)?;
    } else {
        print_execution_summary(&execution);
    }
    Ok(0)
}

/// `cleanton security`: read-only supply-chain scan of installed packages,
/// interpreted through the trusted baseline (first run establishes it; later
/// runs show only the diff). Detection + notification only — no path in this
/// command removes, modifies, or quarantines anything; `--review`/
/// `--review-all` write ONLY the baseline metadata file.
///
/// Exit codes (distinct from plan/clean's 2 = empty and 4 = incomplete):
/// 0 = no alerts (uncorroborated notices and a fresh baseline are fine),
/// 3 = a new/updated package has a CORROBORATED suspicious verdict, 5 = a
/// new/updated package has a CORROBORATED malicious verdict OR any package
/// changed without a version bump (same-version tamper). Reviews are applied
/// BEFORE the exit code is computed, so `--review-all` on a surfaced set
/// exits 0.
/// The background watcher: a slow, cheap loop that checks packages the moment
/// they appear.
fn run_watch(cli: &Cli, interval: u64, once: bool, print_agent: bool) -> i32 {
    use cleanton_engine::background::{PackageWatcher, WatchEvent, WatchOptions};

    let options = WatchOptions::with_idle_seconds(interval);
    let mut watcher = PackageWatcher::for_default_targets(options);

    if print_agent {
        println!("{}", launch_agent_plist(interval));
        return 0;
    }

    if !cli.json {
        let roots = watcher.roots().collect::<Vec<_>>();
        if roots.is_empty() {
            println!(
                "No package locations found to watch (no global node_modules, \
                 site-packages, gem tree, Cargo registry, or Go module cache exists)."
            );
            return 0;
        }
        println!(
            "Watching {} package location(s); idle interval {}s, backing off to {}s while quiet.",
            roots.len(),
            options.idle.as_secs(),
            options.max_idle.as_secs()
        );
        for target in roots {
            println!("  - {} ({})", target.root.display(), target.kind.label());
        }
        println!("Ctrl-C stops the watcher. Nothing is ever removed.");
    }

    let cancel = std::sync::atomic::AtomicBool::new(false);
    let mut alerts = 0_usize;
    let mut emit = |event: WatchEvent| {
        if cli.json {
            match serde_json::to_string(&watch_event_json(&event)) {
                Ok(line) => println!("{line}"),
                Err(err) => eprintln!("warning: could not serialize event: {err}"),
            }
            return;
        }
        match event {
            WatchEvent::Quiet | WatchEvent::RootChanged { .. } => {}
            other => print_watch_event(&other),
        }
    };
    if once {
        for event in watcher.tick(&cancel) {
            if matches!(
                event,
                WatchEvent::Advisory { .. } | WatchEvent::ContentFinding { .. }
            ) {
                alerts = alerts.saturating_add(1);
            }
            emit(event);
        }
    } else {
        watcher.run(&cancel, &mut emit);
    }
    if alerts > 0 { 3 } else { 0 }
}

/// One watch event as JSON (the `--json` stream shape).
fn watch_event_json(event: &cleanton_engine::background::WatchEvent) -> serde_json::Value {
    use cleanton_engine::background::WatchEvent;

    match event {
        WatchEvent::Quiet => serde_json::json!({ "event": "quiet" }),
        WatchEvent::RootChanged { root, new_packages } => serde_json::json!({
            "event": "root_changed",
            "root": root.display().to_string(),
            "new_packages": new_packages,
        }),
        WatchEvent::Advisory {
            package,
            version,
            advisory,
            severity,
            summary,
            remediation,
        } => serde_json::json!({
            "event": "advisory",
            "package": package,
            "version": version,
            "advisory": advisory,
            "severity": cleanton_engine::security::severity_label(*severity),
            "summary": summary,
            "remediation": remediation,
        }),
        WatchEvent::InstallHook { package, hook } => serde_json::json!({
            "event": "install_hook",
            "package": package,
            "hook": hook,
        }),
        WatchEvent::ContentFinding {
            package,
            verdict,
            findings,
            headline,
        } => serde_json::json!({
            "event": "content_finding",
            "package": package,
            "verdict": cleanton_engine::security::verdict_label(*verdict),
            "findings": findings,
            "headline": headline,
        }),
    }
}

fn print_watch_event(event: &cleanton_engine::background::WatchEvent) {
    use cleanton_engine::background::WatchEvent;
    use cleanton_engine::security::{severity_label, verdict_label};

    match event {
        WatchEvent::Quiet | WatchEvent::RootChanged { .. } => {}
        WatchEvent::Advisory {
            package,
            version,
            advisory,
            severity,
            summary,
            remediation,
        } => println!(
            "[{}] {package} {version}: {advisory} ({summary}) - {remediation}",
            severity_label(*severity)
        ),
        WatchEvent::InstallHook { package, hook } => println!(
            "[info] {package} runs a `{hook}` script at install time; review it if the package is unfamiliar"
        ),
        WatchEvent::ContentFinding {
            package,
            verdict,
            findings,
            headline,
        } => println!(
            "[{}] {package}: {findings} finding(s) - {headline}",
            verdict_label(*verdict)
        ),
    }
}

/// A launchd agent that runs the watcher as a user background job. Printed, not
/// installed: the plist path and the decision to load it are the user's.
fn launch_agent_plist(interval: u64) -> String {
    let binary = std::env::current_exe().map_or_else(
        |_| "/usr/local/bin/cleanton".to_owned(),
        |path| path.display().to_string(),
    );
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.cleanton.watch</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>watch</string>
        <string>--interval</string>
        <string>{interval}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>LowPriorityIO</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardErrorPath</key>
    <string>/tmp/cleanton-watch.err</string>
</dict>
</plist>"#
    )
}

fn run_security(
    cli: &Cli,
    establish_baseline: bool,
    all: bool,
    review: &[String],
    review_all: bool,
    baseline: Option<PathBuf>,
) -> Result<i32> {
    use cleanton_engine::security;

    let baseline_path = baseline.or_else(cleanton_engine::default_baseline_path);
    if baseline_path.is_none() && !cli.json {
        println!("note: HOME is not set, so no baseline can be stored; showing the raw scan.");
    }
    let options = security::SecurityScanOptions {
        baseline_path: baseline_path.clone(),
        establish_baseline,
        include_unchanged: all,
    };

    let targets = security::discover_targets(&cli.root);
    if targets.is_empty() {
        if cli.json {
            print_json(&security::SecurityReport::empty())?;
        } else {
            println!(
                "No package locations found to scan (no global node_modules, \
                 site-packages, or editor extension directories exist)."
            );
        }
        return Ok(0);
    }

    if !cli.json {
        println!(
            "Security scan (read-only) of {} location(s):",
            targets.len()
        );
        for target in &targets {
            println!("  - {} ({})", target.root.display(), target.kind.label());
        }
    }

    // Live progress goes to stderr (throttled) so `--json` stdout stays clean.
    let progress = |progress: cleanton_engine::SecurityProgress| {
        if progress.total > 0
            && (progress.scanned.is_multiple_of(25) || progress.scanned == progress.total)
        {
            eprint!("\rscanned {}/{} packages", progress.scanned, progress.total);
            if progress.scanned == progress.total {
                eprintln!();
            }
        }
    };
    let mut report = security::scan_targets_with_options(targets, &options, None, &progress);

    // Apply requested reviews (baseline metadata only; packages untouched),
    // then report the post-review state.
    let mut review_notes: Vec<String> = Vec::new();
    if review_all || !review.is_empty() {
        let Some(path) = baseline_path.as_deref() else {
            return Err(CleantonError::Config(
                "cannot mark packages reviewed: no baseline path (HOME is not set)".to_owned(),
            ));
        };
        if review_all {
            let trusted = report.trust_all_flagged(path)?;
            review_notes.push(format!(
                "Marked {trusted} package(s) as reviewed/trusted in the baseline."
            ));
        } else {
            for name in review {
                // Trust every flagged row matching the requested name (a name
                // can appear in more than one tree kind).
                let mut trusted_names = Vec::new();
                while let Some(index) = report
                    .flagged
                    .iter()
                    .position(|pkg| &pkg.name == name || pkg.display_name() == *name)
                {
                    trusted_names.push(report.trust_flagged(index, path)?);
                }
                if trusted_names.is_empty() {
                    review_notes.push(format!(
                        "warning: '{name}' is not in the flagged list; nothing to review."
                    ));
                } else {
                    review_notes.push(format!(
                        "Marked {} as reviewed/trusted in the baseline.",
                        trusted_names.join(", ")
                    ));
                }
            }
        }
    }

    if cli.json {
        print_json(&report)?;
        for note in &review_notes {
            eprintln!("{note}");
        }
    } else {
        print_security_report(&report);
        for note in &review_notes {
            println!("{note}");
        }
    }
    Ok(report.exit_code())
}

/// Human-readable security report: the diff table (worst-first: same-version
/// tampers and corroborated alerts on top, neutral notices below) followed by
/// the shared summary line. The STATUS column is the ASSESSMENT — notice rows
/// show "notice", never a raw heuristic verdict; the raw verdict appears only
/// as an indented "heuristics: … (uncorroborated)" detail. Wording is
/// deliberately review-only ("review this package") — there is no auto-fix
/// and never will be.
fn print_security_report(report: &cleanton_engine::SecurityReport) {
    use cleanton_engine::security::severity_label;

    println!();
    if report.flagged.is_empty() {
        println!("{}", report.summary_message());
        return;
    }

    println!(
        "{:<26} {:<10} {:>5}  {:<9} {:<32} TOP FINDING",
        "CHANGE", "STATUS", "SCORE", "SEVERITY", "PACKAGE",
    );
    for package in &report.flagged {
        let severity = package.worst_severity().map_or("-", severity_label);
        let top = package
            .top_findings
            .first()
            .map_or("(no detail)", |finding| finding.title.as_str());
        println!(
            "{:<26} {:<10} {:>5}  {:<9} {:<32} {}",
            package.change_label(),
            package.assessment_label(),
            package.score,
            severity,
            package.display_name(),
            top
        );
        println!(
            "{:<26} {:<10} {:>5}  {:<9} path: {}",
            "",
            "",
            "",
            "",
            package.path.display()
        );
        if let Some(note) = package.heuristic_note() {
            println!("{:<26} {:<10} {:>5}  {:<9} {note}", "", "", "", "");
        }
        if package.is_tampered() {
            println!(
                "{:<26} {:<10} {:>5}  {:<9} ⚠ {}",
                "",
                "",
                "",
                "",
                package.change.notice()
            );
        }
        // Recommended next steps (advisory; the user runs these, not Cleanton).
        for (idx, step) in package.action_lines().iter().enumerate() {
            let label = if idx == 0 { "next:" } else { "" };
            println!("{:<26} {:<10} {:>5}  {label:<9} {step}", "", "", "");
        }
    }
    println!();
    for error in report.errors.iter().take(WARNING_PRINT_LIMIT) {
        eprintln!("warning: could not scan {error}");
    }
    println!("{}", report.summary_message());
    println!(
        "Review each flagged package at its path above and remove or reinstall it \
         with its package manager if you did not expect it. Cleanton only reports; \
         it never changes packages. Use --review <package> (or --review-all) to \
         trust what you have reviewed."
    );
}

async fn run_interactive(_cli: &Cli, config: &CleantonConfig) -> Result<i32> {
    cleanton_ui::run_tui(config).await?;
    Ok(0)
}

fn run_recipes(command: RecipeCommand, json: bool) -> Result<i32> {
    let recipes = RecipeSet::load_all()?;
    match command {
        RecipeCommand::Validate => {
            if json {
                print_json(&serde_json::json!({
                    "ok": true,
                    "built_in_recipes": recipes.len(),
                }))?;
            } else {
                println!("validated {} built-in recipes", recipes.len());
            }
            Ok(0)
        }
        RecipeCommand::List => {
            let ids = recipes
                .iter()
                .map(|recipe| recipe.recipe.id.as_str())
                .collect::<Vec<_>>();
            if json {
                print_json(&serde_json::json!({ "recipes": ids }))?;
            } else {
                for id in ids {
                    println!("{id}");
                }
            }
            Ok(0)
        }
    }
}

/// Warn (without failing) about requested roots that don't exist or aren't
/// directories, so a typo'd `--root` doesn't masquerade as "nothing to clean".
/// Warnings go to stderr to keep `--json` stdout clean.
fn warn_unscannable_roots(roots: &[PathBuf]) {
    for root in roots {
        match std::fs::metadata(root) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => eprintln!(
                "warning: root {} is not a directory; nothing will be scanned there",
                root.display()
            ),
            Err(_) => eprintln!(
                "warning: root {} does not exist or is not accessible; nothing will be scanned there",
                root.display()
            ),
        }
    }
}

fn scan_options(cli: &Cli, config: &CleantonConfig) -> ScanOptions {
    let roots = if cli.root.is_empty() {
        vec![config.general.default_root.clone()]
    } else {
        cli.root.clone()
    };

    ScanOptions {
        roots,
        max_depth: cli.max_depth.unwrap_or(config.scanning.max_depth),
        follow_symlinks: config.scanning.follow_symlinks || cli.follow_symlinks,
        respect_gitignore: config.scanning.respect_gitignore,
        exclude_patterns: {
            let mut patterns = config.scanning.exclude_patterns.clone();
            patterns.extend(cli.exclude.clone());
            patterns
        },
        exclude_cloud_roots: config.scanning.exclude_cloud_roots && !cli.include_cloud,
        exclude_external_volumes: config.scanning.exclude_external_volumes
            && !cli.include_external_volumes,
        protected_paths: config.safety.protected_paths.clone(),
        parallel_threads: config.scanning.parallel_threads,
        ..ScanOptions::default()
    }
}

/// Serialize `value` as a `schema_version`-stamped JSON object straight to a
/// buffered stdout.
///
/// Every payload the CLI prints is a JSON object, so we flatten the value's
/// fields next to `schema_version` and stream them with `to_writer`. This
/// deliberately avoids the previous `to_value` + `to_string_pretty` path, which
/// materialised the entire result as a `serde_json::Value` tree *and then* as a
/// single pretty-printed `String` before writing a byte — on a large scan that
/// buffered hundreds of megabytes twice and made the CLI appear to hang while it
/// thrashed memory.
fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    use std::io::Write as _;

    #[derive(serde::Serialize)]
    struct Versioned<'a, T: serde::Serialize> {
        schema_version: u64,
        #[serde(flatten)]
        data: &'a T,
    }

    let map_err = |err: std::io::Error| cleanton_common::CleantonError::Config(err.to_string());

    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::new(stdout.lock());
    serde_json::to_writer_pretty(
        &mut writer,
        &Versioned {
            schema_version: JSON_SCHEMA_VERSION,
            data: value,
        },
    )
    .map_err(|err| cleanton_common::CleantonError::Config(err.to_string()))?;
    writer.write_all(b"\n").map_err(map_err)?;
    writer.flush().map_err(map_err)?;
    Ok(())
}

/// True when an action originated from engine-side orphaned-app detection.
fn is_orphan_action(action: &CleanupAction) -> bool {
    action.recipe_id.0.contains("orphan")
}

/// A compact ML badge ("ML <label> <confidence>") when the annotation carries a
/// label + confidence, otherwise `None` (not-evaluated actions). Uses the
/// kebab-case `Display` text so it matches the TUI badge and the `[ML ...]`
/// reason suffix.
fn ml_badge(annotation: &ActionAnnotation) -> Option<String> {
    let label = annotation.ml_label?;
    let confidence = annotation.ml_confidence?;
    Some(format!("ML {label} {confidence:.2}"))
}

fn json_err(err: &serde_json::Error) -> CleantonError {
    CleantonError::Config(err.to_string())
}

/// Serialize a [`CleanupAction`], preserving every existing field, and merge in
/// the ML annotation fields so downstream JSON parsers keep working while
/// gaining `ml_label`, `ml_confidence`, `adjustment`, and `ml_note`.
fn action_value(
    action: &CleanupAction,
    annotation: Option<&ActionAnnotation>,
) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(action).map_err(|err| json_err(&err))?;
    if let serde_json::Value::Object(map) = &mut value {
        let (label, confidence, adjustment, note) = match annotation {
            Some(annotation) => (
                serde_json::to_value(annotation.ml_label).map_err(|err| json_err(&err))?,
                serde_json::to_value(annotation.ml_confidence).map_err(|err| json_err(&err))?,
                serde_json::to_value(annotation.adjustment).map_err(|err| json_err(&err))?,
                serde_json::Value::String(annotation.note.clone()),
            ),
            None => (
                serde_json::Value::Null,
                serde_json::Value::Null,
                serde_json::to_value(MlAdjustment::NotEvaluated).map_err(|err| json_err(&err))?,
                serde_json::Value::String(String::new()),
            ),
        };
        map.insert("ml_label".to_owned(), label);
        map.insert("ml_confidence".to_owned(), confidence);
        map.insert("adjustment".to_owned(), adjustment);
        map.insert("ml_note".to_owned(), note);
    }
    Ok(value)
}

/// Build the `plan`/`clean` JSON payload from the analyzed plan: `scan` and
/// `plan` (with annotated actions) are preserved, and a top-level `held` array
/// is added for the demoted candidates.
fn analyzed_json(scan: &ScanResult, analyzed: &AnalyzedPlan) -> Result<serde_json::Value> {
    let actions = analyzed
        .plan
        .actions
        .iter()
        .map(|action| action_value(action, analyzed.annotation(&action.target)))
        .collect::<Result<Vec<_>>>()?;
    let mut plan_value = serde_json::to_value(&analyzed.plan).map_err(|err| json_err(&err))?;
    if let serde_json::Value::Object(map) = &mut plan_value {
        map.insert("actions".to_owned(), serde_json::Value::Array(actions));
    }

    let held = analyzed
        .held
        .iter()
        .map(|annotated| action_value(&annotated.action, Some(&annotated.annotation)))
        .collect::<Result<Vec<_>>>()?;

    Ok(serde_json::json!({
        "scan": scan,
        "plan": plan_value,
        "held": held,
    }))
}

/// The full `plan` JSON payload: the analyzed plan/scan/held object plus the
/// root-independent `docker` analysis and review-only `suggestions`.
fn full_json(scan: &ScanResult, full: &AnalyzedFull) -> Result<serde_json::Value> {
    let mut value = analyzed_json(scan, &full.analyzed)?;
    if let serde_json::Value::Object(map) = &mut value {
        map.insert(
            "docker".to_owned(),
            serde_json::to_value(&full.docker).map_err(|err| json_err(&err))?,
        );
        map.insert(
            "suggestions".to_owned(),
            serde_json::to_value(&full.suggestions).map_err(|err| json_err(&err))?,
        );
    }
    Ok(value)
}

/// Cap on suggestion rows printed per subsection in the human summary.
const SUGGESTION_PRINT_LIMIT: usize = 15;

/// Print the Docker section: full breakdown when something is reclaimable,
/// otherwise a single honest line (root-independent — always evaluated).
fn print_docker_section(docker: &DockerAnalysis) {
    println!();
    if docker.total_reclaimable == 0 {
        println!("Docker: no reclaimable space (or Docker is not running)");
        return;
    }
    print_docker_analysis(docker);
    println!("  (clean with: cleanton docker clean --build-cache --dangling-images ...)");
}

/// Print the review-only Suggestions section (duplicates + large items). These
/// are never part of the cleanup plan; the CLI only surfaces them for review.
fn print_suggestions_section(suggestions: &Suggestions) {
    if suggestions.duplicates.is_empty() && suggestions.large_items.is_empty() {
        return;
    }
    println!();
    println!("Suggestions (review only, not part of the cleanup plan)");

    if !suggestions.duplicates.is_empty() {
        let sampled = if suggestions.truncated {
            " (sampled, budget reached)"
        } else {
            ""
        };
        println!(
            "  Duplicate files: {} set(s), {} reclaimable{}",
            suggestions.duplicates.len(),
            display::human_bytes(suggestions.duplicate_reclaimable),
            sampled
        );
        for set in suggestions.duplicates.iter().take(SUGGESTION_PRINT_LIMIT) {
            let name = set
                .paths
                .first()
                .and_then(|path| path.file_name())
                .map_or_else(
                    || "duplicate".to_owned(),
                    |n| n.to_string_lossy().into_owned(),
                );
            println!(
                "    - {} copies of {} ({} each), save {}",
                set.count,
                name,
                display::human_bytes(set.file_bytes),
                display::human_bytes(set.reclaimable_bytes)
            );
            if let Some(path) = set.paths.first() {
                println!("        e.g. {}", path.display());
            }
        }
        if suggestions.duplicates.len() > SUGGESTION_PRINT_LIMIT {
            println!(
                "    ... {} more duplicate set(s)",
                suggestions.duplicates.len() - SUGGESTION_PRINT_LIMIT
            );
        }
    }

    if !suggestions.large_items.is_empty() {
        println!("  Largest files & folders:");
        for item in suggestions.large_items.iter().take(SUGGESTION_PRINT_LIMIT) {
            let kind = if item.is_dir { " (folder)" } else { "" };
            println!(
                "    - {}  {}{}",
                display::human_bytes(item.bytes),
                item.path.display(),
                kind
            );
            // Re-clonable git repos (and approx-size folders) carry a note;
            // the advisory ML badge (display only) rides alongside it.
            if !item.note.is_empty() {
                println!("        {}", item.note);
            }
            if !item.ml_note.is_empty() {
                println!("        {}", item.ml_note);
            }
        }
        if suggestions.large_items.len() > SUGGESTION_PRINT_LIMIT {
            println!(
                "    ... {} more large item(s)",
                suggestions.large_items.len() - SUGGESTION_PRINT_LIMIT
            );
        }
    }
}

fn print_analyzed_summary(analyzed: &AnalyzedPlan, scan: Option<&ScanResult>) {
    let plan = &analyzed.plan;
    println!("Cleanup plan");
    println!("  actions: {}", plan.actions.len());
    println!(
        "  reclaimable: {}",
        display::human_bytes(plan.total_reclaimable)
    );
    println!("  scan duration: {:.2}s", plan.scan_duration.as_secs_f64());
    println!(
        "  analysis duration: {:.2}s",
        plan.analysis_duration.as_secs_f64()
    );
    if plan.incomplete_scan {
        println!("  status: incomplete scan; cleanup cannot execute");
    }

    let orphan_count = plan.actions.iter().filter(|a| is_orphan_action(a)).count();
    if orphan_count > 0 {
        println!(
            "  {ORPHAN_CATEGORY}: {orphan_count} candidate(s) (require explicit confirmation)"
        );
    }

    if let Some(scan) = scan
        && !scan.errors.is_empty()
    {
        println!("  warnings: {}", scan.errors.len());
        print_warning_details(&scan.errors);
    }

    // Present the plan grouped by recipe: a real home directory yields tens of
    // thousands of per-file actions, so a per-action listing is unusable. The
    // executable plan (`plan.actions`) is untouched — execution still trashes
    // every underlying file; this is purely how the human summary is rendered.
    let groups = plan.grouped();
    for group in groups.iter().take(GROUP_PRINT_LIMIT) {
        let category = if group.recipe_id.contains("orphan") {
            format!("  {{{ORPHAN_CATEGORY}}}")
        } else {
            String::new()
        };
        println!(
            "  - {}  {}{}  ({} items): {}",
            display::human_bytes(group.total_reclaimable),
            group.recipe_id,
            category,
            group.action_count,
            group.label,
        );
    }
    if groups.len() > GROUP_PRINT_LIMIT {
        println!(
            "  ... {} more recipe groups",
            groups.len() - GROUP_PRINT_LIMIT
        );
    }

    if !analyzed.held.is_empty() {
        println!();
        println!(
            "Held back (needs explicit confirmation): {}",
            analyzed.held.len()
        );
        let mut by_size = analyzed.held.iter().collect::<Vec<_>>();
        by_size.sort_by_key(|annotated| std::cmp::Reverse(annotated.action.reclaimable_bytes));
        for annotated in by_size.iter().take(25) {
            let badge = ml_badge(&annotated.annotation)
                .map(|badge| format!("  [{badge}]"))
                .unwrap_or_default();
            println!(
                "  - {} {}{}",
                display::human_bytes(annotated.action.reclaimable_bytes),
                annotated.action.target.display(),
                badge
            );
        }
        if analyzed.held.len() > 25 {
            println!("  ... {} more held items", analyzed.held.len() - 25);
        }
    }
}

fn print_warning_details(errors: &[ScanError]) {
    println!("  permission/skipped warnings:");
    for error in errors.iter().take(WARNING_PRINT_LIMIT) {
        println!("    - {}: {}", error.path.display(), error.message);
    }
    if errors.len() > WARNING_PRINT_LIMIT {
        println!(
            "    ... {} more warnings",
            errors.len() - WARNING_PRINT_LIMIT
        );
    }
}

fn print_execution_summary(result: &ExecutionResult) {
    println!("Execution complete");
    println!("  attempted: {}", result.attempted_actions);
    println!("  skipped: {}", result.skipped_actions);
    println!(
        "  moved to Trash: {}",
        display::human_bytes(result.moved_to_trash_bytes)
    );
    println!("  freed: {}", display::human_bytes(result.freed_bytes));
    if let Some(log_path) = &result.log_path {
        println!("  log: {}", log_path.display());
    }
}

fn print_docker_analysis(analysis: &DockerAnalysis) {
    println!("Docker analysis");
    println!(
        "  dangling images: {} ({})",
        analysis.dangling_images.len(),
        display::human_bytes(analysis.dangling_images.iter().map(|item| item.size).sum())
    );
    println!(
        "  stopped containers: {} ({})",
        analysis.stopped_containers.len(),
        display::human_bytes(
            analysis
                .stopped_containers
                .iter()
                .map(|item| item.size)
                .sum()
        )
    );
    println!(
        "  unused volumes: {} ({})",
        analysis.unused_volumes.len(),
        display::human_bytes(analysis.unused_volumes.iter().map(|item| item.size).sum())
    );
    println!(
        "  build cache: {}",
        display::human_bytes(analysis.build_cache.size)
    );
    println!(
        "  reclaimable inside Docker VM: {}",
        display::human_bytes(analysis.total_reclaimable)
    );
}

fn print_docker_cleanup_result(result: &DockerCleanupResult) {
    println!("Docker cleanup complete");
    println!(
        "  images freed inside Docker VM: {}",
        display::human_bytes(result.images_freed)
    );
    println!(
        "  containers freed inside Docker VM: {}",
        display::human_bytes(result.containers_freed)
    );
    println!(
        "  volumes freed inside Docker VM: {}",
        display::human_bytes(result.volumes_freed)
    );
    println!(
        "  build cache freed inside Docker VM: {}",
        display::human_bytes(result.build_cache_freed)
    );
    println!(
        "  total freed inside Docker VM: {}",
        display::human_bytes(result.total_freed)
    );
}

fn bool_label(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    // Log lines go to stderr so they can never corrupt `--json` stdout (e.g.
    // the antivirus loader warns about oversized files mid-scan).
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(test)]
mod tests {
    // Test-only: assertions index directly into fixed-shape fixtures and
    // `serde_json::Value` trees; clearer than chained `.get(...).unwrap()`.
    #![allow(clippy::indexing_slicing)]
    use super::*;

    fn config_for_scan_option_tests() -> CleantonConfig {
        CleantonConfig {
            general: cleanton_common::GeneralConfig {
                default_root: PathBuf::from("/tmp/default-root"),
                ..cleanton_common::GeneralConfig::default()
            },
            scanning: cleanton_common::ScanningConfig {
                max_depth: 7,
                follow_symlinks: false,
                respect_gitignore: true,
                parallel_threads: 2,
                exclude_patterns: vec!["configured".to_owned()],
                exclude_cloud_roots: true,
                exclude_external_volumes: true,
            },
            safety: cleanton_common::SafetyConfig {
                protected_paths: vec![PathBuf::from("/tmp/protected")],
                ..cleanton_common::SafetyConfig::default()
            },
            ..CleantonConfig::default()
        }
    }

    #[test]
    fn scan_options_preserve_config_defaults_without_flags() {
        let cli = Cli::parse_from(["cleanton", "plan"]);
        let config = config_for_scan_option_tests();

        let options = scan_options(&cli, &config);

        assert_eq!(options.roots, vec![PathBuf::from("/tmp/default-root")]);
        assert_eq!(options.max_depth, 7);
        assert!(!options.follow_symlinks);
        assert!(options.respect_gitignore);
        assert_eq!(options.parallel_threads, 2);
        assert_eq!(options.exclude_patterns, vec!["configured".to_owned()]);
        assert!(options.exclude_cloud_roots);
        assert!(options.exclude_external_volumes);
        assert_eq!(
            options.protected_paths,
            vec![PathBuf::from("/tmp/protected")]
        );
    }

    #[test]
    fn scan_options_apply_explicit_cli_overrides() {
        let cli = Cli::parse_from([
            "cleanton",
            "--root",
            "/tmp/scan-root",
            "--max-depth",
            "3",
            "--follow-symlinks",
            "--include-cloud",
            "--include-external-volumes",
            "--exclude",
            "node_modules",
            "--exclude",
            "*.tmp",
            "plan",
        ]);
        let config = config_for_scan_option_tests();

        let options = scan_options(&cli, &config);

        assert_eq!(options.roots, vec![PathBuf::from("/tmp/scan-root")]);
        assert_eq!(options.max_depth, 3);
        assert!(options.follow_symlinks);
        assert_eq!(
            options.exclude_patterns,
            vec![
                "configured".to_owned(),
                "node_modules".to_owned(),
                "*.tmp".to_owned()
            ]
        );
        assert!(!options.exclude_cloud_roots);
        assert!(!options.exclude_external_volumes);
    }

    fn empty_scan() -> ScanResult {
        ScanResult {
            entries: Vec::new(),
            project_roots: Vec::new(),
            total_files: 0,
            total_dirs: 0,
            logical_bytes: 0,
            allocated_bytes: 0,
            duration: std::time::Duration::ZERO,
            errors: Vec::new(),
            incomplete: false,
        }
    }

    #[test]
    fn analyzed_json_surfaces_ml_annotations_and_held() {
        use cleanton_engine::{AnalyzedPlan, AnnotatedAction};

        let plan: cleanton_common::CleanupPlan = serde_json::from_value(serde_json::json!({
            "actions": [{
                "target": "/Users/x/proj/cache/blob.bin",
                "logical_bytes": 4096,
                "reclaimable_bytes": 4096,
                "recipe_id": "permissive-cache",
                "action_type": "trash",
                "confidence": "high",
                "safety_level": "safe",
                "reason": "recipe candidate [ML safe-to-remove: 0.97]",
                "fingerprint": {
                    "file_kind": "file", "device_id": null, "inode": null,
                    "logical_bytes": 4096, "allocated_bytes": 4096, "modified": null
                }
            }],
            "total_reclaimable": 4096,
            "scan_duration": { "secs": 0, "nanos": 0 },
            "analysis_duration": { "secs": 0, "nanos": 0 },
            "incomplete_scan": false
        }))
        .expect("plan");

        let planned_action = serde_json::to_value(&plan.actions[0]).expect("action value");
        let annotations: Vec<AnnotatedAction> = serde_json::from_value(serde_json::json!([{
            "action": planned_action,
            "annotation": {
                "ml_label": "safe-to-remove",
                "ml_confidence": 0.97,
                "adjustment": "confirmed",
                "note": "ML agrees"
            }
        }]))
        .expect("annotations");

        let held: Vec<AnnotatedAction> = serde_json::from_value(serde_json::json!([{
            "action": {
                "target": "/Users/x/proj/cache/keep.bin",
                "logical_bytes": 2048,
                "reclaimable_bytes": 2048,
                "recipe_id": "permissive-cache",
                "action_type": "trash",
                "confidence": "medium",
                "safety_level": "safe",
                "reason": "recipe candidate [ML keep: 0.92]",
                "fingerprint": {
                    "file_kind": "file", "device_id": null, "inode": null,
                    "logical_bytes": 2048, "allocated_bytes": 2048, "modified": null
                }
            },
            "annotation": {
                "ml_label": "keep",
                "ml_confidence": 0.92,
                "adjustment": "demoted",
                "note": "demoted, held for explicit confirmation"
            }
        }]))
        .expect("held");

        let analyzed = AnalyzedPlan {
            plan,
            annotations,
            held,
            orphans: Vec::new(),
        };

        let value = analyzed_json(&empty_scan(), &analyzed).expect("analyzed json");

        // Per-action ML fields are present, and the existing fields survive.
        let action = &value["plan"]["actions"][0];
        assert_eq!(action["ml_label"], "safe-to-remove");
        assert_eq!(action["adjustment"], "confirmed");
        assert!(action["ml_confidence"].as_f64().is_some());
        assert_eq!(action["recipe_id"], "permissive-cache");
        assert_eq!(action["safety_level"], "safe");

        // Demoted candidates surface in the top-level `held` array, never in plan.
        let held = value["held"].as_array().expect("held array");
        assert_eq!(held.len(), 1);
        assert_eq!(held[0]["adjustment"], "demoted");
        assert_eq!(held[0]["ml_label"], "keep");
        assert!(
            value["plan"]["actions"]
                .as_array()
                .expect("actions array")
                .iter()
                .all(|a| a["adjustment"] != "demoted"),
            "demoted items must never appear in the executable plan"
        );
    }

    #[test]
    fn config_path_subcommand_parses_with_global_json() {
        let cli = Cli::parse_from(["cleanton", "--json", "config", "path"]);

        assert!(cli.json);
        assert!(matches!(
            cli.command,
            Some(Command::Config {
                command: Some(ConfigCommand::Path)
            })
        ));
    }
}
