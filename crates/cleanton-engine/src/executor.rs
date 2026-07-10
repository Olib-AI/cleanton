use std::{
    cmp::Reverse,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use chrono::{DateTime, Local};
use cleanton_common::{
    ActionType, CleantonConfig, CleantonError, CleanupAction, CleanupPlan, Confidence,
    ExecutionActionResult, ExecutionResult, ExecutionStatus, FileKind, MetadataFingerprint,
    ProtectedPaths, RecipeId, Result, SafetyLevel,
};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::EngineEvent;

const AGGRESSIVE_ACTION_MAX_BYTES: u64 = 5 * 1_073_741_824;

pub(crate) fn execute_plan(
    config: &CleantonConfig,
    plan: &CleanupPlan,
    event_tx: &mpsc::Sender<EngineEvent>,
) -> Result<ExecutionResult> {
    execute_plan_with_cancel(config, plan, event_tx, None)
}

/// Like [`execute_plan`], but stops promptly once `cancel` is set: the current
/// action finishes (an in-flight trash move is never left half-done), every
/// remaining action is recorded as `Skipped`, and the partial result — with its
/// execution log — is returned. Cancellation must actually stop destructive
/// work, not merely hide its outcome.
pub(crate) fn execute_plan_with_cancel(
    config: &CleantonConfig,
    plan: &CleanupPlan,
    event_tx: &mpsc::Sender<EngineEvent>,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<ExecutionResult> {
    validate_plan(config, plan)?;

    let started = Instant::now();
    let protected = ProtectedPaths::new(config.safety.protected_paths.clone());
    let mut result = ExecutionResult {
        attempted_actions: 0,
        moved_to_trash_bytes: 0,
        freed_bytes: 0,
        skipped_actions: 0,
        log_path: None,
        actions: Vec::new(),
    };

    for action in &plan.actions {
        if cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
            result.skipped_actions += 1;
            result.actions.push(action_result(
                action,
                ExecutionStatus::Skipped,
                0,
                0,
                "skipped: execution cancelled by user",
            ));
            continue;
        }
        result.attempted_actions += 1;
        let _ = event_tx.try_send(EngineEvent::ActionStarted {
            action: action.clone(),
        });

        let action_result = execute_action(action, &protected);
        match action_result.status {
            ExecutionStatus::MovedToTrash => {
                result.moved_to_trash_bytes = result
                    .moved_to_trash_bytes
                    .saturating_add(action_result.moved_to_trash_bytes);
                let _ = event_tx.try_send(EngineEvent::ActionCompleted {
                    action: action.clone(),
                    freed: 0,
                });
            }
            ExecutionStatus::Deleted => {
                result.freed_bytes = result.freed_bytes.saturating_add(action_result.freed_bytes);
                let _ = event_tx.try_send(EngineEvent::ActionCompleted {
                    action: action.clone(),
                    freed: action_result.freed_bytes,
                });
            }
            ExecutionStatus::Skipped => {
                result.skipped_actions += 1;
            }
            ExecutionStatus::Failed => {
                let _ = event_tx.try_send(EngineEvent::ActionFailed {
                    action: action.clone(),
                    error: action_result.message.clone(),
                });
            }
        }
        result.actions.push(action_result);
    }

    result.log_path = write_execution_log(config, started, &result)?;
    Ok(result)
}

/// Move a single user-reviewed path (a duplicate copy, large item, or
/// screenshot surfaced in Suggestions) to the Trash.
///
/// Suggestions are review-only and are never auto-removed; this runs only after
/// an explicit, per-item user confirmation in the UI. It builds a one-action,
/// freshly fingerprinted `Trash` plan and pushes it through the exact same
/// executor guards as a normal cleanup — protected-path refusal, metadata
/// revalidation, and Trash-by-default — so the safety model is unchanged.
pub(crate) fn trash_reviewed_path(
    config: &CleantonConfig,
    path: &Path,
    event_tx: &mpsc::Sender<EngineEvent>,
) -> Result<ExecutionResult> {
    let started = Instant::now();
    let metadata = fs::symlink_metadata(path).map_err(|source| CleantonError::io(path, source))?;
    let fingerprint = fingerprint_for_path(path, &metadata);
    let reclaimable = fingerprint.allocated_bytes;

    // Protection model for a *single, explicitly user-confirmed* removal. The
    // normal executor refuses everything under the user-data roots (~/Desktop,
    // ~/Documents, ...) precisely so recipes can never mass-act on personal
    // files. A suggestion the user hand-picked is different: we still refuse the
    // genuinely critical paths (system dirs, keychains, mail, .ssh, configured
    // protected paths), but permit a file that lives *inside* a user-data
    // content root. The root itself is never removable.
    let protected = ProtectedPaths::new(config.safety.protected_paths.clone());
    let within_user_data = cleanton_common::is_user_data_content_path(path)
        && !cleanton_common::is_user_data_content_root(path);
    if protected.is_protected(path) && !within_user_data {
        return Err(CleantonError::ExecutionRefused(format!(
            "refusing to remove a protected path: {}",
            path.display()
        )));
    }

    let action = CleanupAction {
        target: path.to_path_buf(),
        logical_bytes: fingerprint.logical_bytes,
        reclaimable_bytes: reclaimable,
        recipe_id: RecipeId("suggestion".to_owned()),
        category: "suggestions".to_owned(),
        action_type: ActionType::Trash,
        confidence: Confidence::High,
        safety_level: SafetyLevel::Cautious,
        reason: "user-confirmed suggestion removal".to_owned(),
        fingerprint,
    };
    let _ = event_tx.try_send(EngineEvent::ActionStarted {
        action: action.clone(),
    });

    let action_result = match trash::delete(path) {
        Ok(()) => {
            let _ = event_tx.try_send(EngineEvent::ActionCompleted {
                action: action.clone(),
                freed: 0,
            });
            action_result(
                &action,
                ExecutionStatus::MovedToTrash,
                reclaimable,
                0,
                "moved to Trash; bytes are not freed until Trash is emptied",
            )
        }
        Err(err) => {
            let _ = event_tx.try_send(EngineEvent::ActionFailed {
                action: action.clone(),
                error: format!("trash move failed: {err}"),
            });
            action_result(
                &action,
                ExecutionStatus::Failed,
                0,
                0,
                format!("trash move failed: {err}"),
            )
        }
    };

    let mut result = ExecutionResult {
        attempted_actions: 1,
        moved_to_trash_bytes: action_result.moved_to_trash_bytes,
        freed_bytes: 0,
        skipped_actions: 0,
        log_path: None,
        actions: vec![action_result],
    };
    result.log_path = write_execution_log(config, started, &result)?;
    Ok(result)
}

/// User-Library category directories an app uninstall is allowed to reach
/// into. Everything else — including Keychains, Mail, and Messages, which are
/// deliberately absent — is out of scope no matter what discovery proposed.
const UNINSTALL_LIBRARY_SCOPES: &[&str] = &[
    "Application Support",
    "Caches",
    "Preferences",
    "Saved Application State",
    "Logs",
    "WebKit",
    "HTTPStorages",
    "Cookies",
    "Containers",
    "Group Containers",
    "Application Scripts",
    "LaunchAgents",
];

/// The XDG-style home roots an uninstall may reach into (strict descendants
/// only, never the root itself). Paired with the bare-dotfolder rule and the
/// reserved-dotfolder denylist, this bounds what `HomeData` leftovers can be
/// trashed.
const UNINSTALL_HOME_XDG_ROOTS: &[&[&str]] = &[
    &[".cache"],
    &[".config"],
    &[".local", "share"],
    &[".local", "state"],
];

/// True when `path` is a home-directory app-data location an uninstall may
/// trash: a bare `~/.<app>` dotfolder (excluding reserved system dotfolders
/// like `.ssh`/`.config`) or a strict descendant of one of the
/// [`UNINSTALL_HOME_XDG_ROOTS`]. `trash_uninstall_paths` additionally enforces
/// `ProtectedPaths` here, so `~/.config/gcloud`, `~/.config/cleanton`, etc. are
/// still refused even though `~/.config/*` matches structurally.
fn is_home_app_data(path: &Path, home: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(home) else {
        return false;
    };
    let depth = rel.components().count();

    // A bare dotfolder directly under $HOME: exactly one component, dot-prefixed.
    if depth == 1
        && let Some(name) = path.file_name().and_then(|name| name.to_str())
        && let Some(key) = name.strip_prefix('.')
        && !crate::uninstall::is_reserved_home_key(&key.to_ascii_lowercase())
    {
        return true;
    }

    // A strict descendant of an XDG root.
    UNINSTALL_HOME_XDG_ROOTS.iter().any(|segments| {
        let mut root = home.to_path_buf();
        for segment in *segments {
            root.push(segment);
        }
        path != root && path.starts_with(&root)
    })
}

/// True when `path` is something a user-confirmed app uninstall may trash:
/// a `.app` bundle directly under `/Applications` (or one grouping folder
/// below it) or `~/Applications`; a strict descendant of one of the
/// [`UNINSTALL_LIBRARY_SCOPES`] under `~/Library`; or a home-directory
/// app-data location ([`is_home_app_data`]). Never a scope directory itself,
/// never anything under `/System`.
fn is_uninstall_scope(path: &Path, home: &Path) -> bool {
    if path.starts_with("/System") {
        return false;
    }

    // The app bundle itself.
    let is_app_bundle = path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("app"));
    if is_app_bundle {
        if let Some(parent) = path.parent() {
            if parent == Path::new("/Applications") || parent == home.join("Applications") {
                return true;
            }
            // One grouping folder below /Applications (e.g. /Applications/Utilities).
            if parent.parent() == Some(Path::new("/Applications")) {
                return true;
            }
        }
        return false;
    }

    // A strict descendant of an allowed ~/Library scope.
    let library = home.join("Library");
    let in_library = UNINSTALL_LIBRARY_SCOPES.iter().any(|scope| {
        let scope_dir = library.join(scope);
        path != scope_dir && path.starts_with(&scope_dir)
    });

    in_library || is_home_app_data(path, home)
}

/// Move the user-confirmed items of an app uninstall to the Trash.
///
/// Runs only after the UI's explicit per-app review and confirmation. Every
/// path must pass [`is_uninstall_scope`] — a stricter allow-list than the
/// normal executor, covering exactly the places `uninstall::find_leftovers`
/// proposes (app bundle + user-Library leftovers). This is what permits
/// trashing inside the otherwise-protected `/Applications`, `Containers`, and
/// `Group Containers` roots for the one hand-picked app. Paths a user
/// explicitly added to `protected_paths` in their config are still refused.
/// Out-of-scope or failing items are recorded (Skipped/Failed) and the rest
/// proceed; everything lands in one execution log.
pub(crate) fn trash_uninstall_paths(
    config: &CleantonConfig,
    paths: &[std::path::PathBuf],
    event_tx: &mpsc::Sender<EngineEvent>,
) -> Result<ExecutionResult> {
    let started = Instant::now();
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .filter(|home| !home.as_os_str().is_empty())
        .ok_or_else(|| {
            CleantonError::ExecutionRefused("cannot resolve $HOME for uninstall scope".to_owned())
        })?;
    // Only the user's *additional* configured protections are re-checked here:
    // the default set necessarily covers /Applications and Containers, which
    // the uninstall scope legitimately carves into.
    let defaults = ProtectedPaths::defaults();
    let configured = ProtectedPaths::new(config.safety.protected_paths.clone());

    let mut result = ExecutionResult {
        attempted_actions: 0,
        moved_to_trash_bytes: 0,
        freed_bytes: 0,
        skipped_actions: 0,
        log_path: None,
        actions: Vec::new(),
    };

    for path in paths {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            // Already gone (e.g. trashed with an earlier item): skip quietly.
            result.skipped_actions += 1;
            continue;
        };
        let fingerprint = fingerprint_for_path(path, &metadata);
        let reclaimable = fingerprint.allocated_bytes;
        let action = CleanupAction {
            target: path.clone(),
            logical_bytes: fingerprint.logical_bytes,
            reclaimable_bytes: reclaimable,
            recipe_id: RecipeId("app-uninstall".to_owned()),
            category: "apps".to_owned(),
            action_type: ActionType::Trash,
            confidence: Confidence::High,
            safety_level: SafetyLevel::Cautious,
            reason: "user-confirmed application uninstall".to_owned(),
            fingerprint,
        };

        // The default protected set necessarily covers /Applications and the
        // ~/Library subtrees an uninstall legitimately carves into, so defaults
        // are ignored *there*. Everywhere else — home dotfolders and XDG dirs —
        // the defaults are enforced, so `~/.ssh`, `~/.config/gcloud`,
        // `~/.config/cleanton`, and the user-data roots are refused even if
        // discovery somehow proposed them. Configured protections always win.
        let is_app_bundle = path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("app"));
        let carve_zone = is_app_bundle || path.starts_with(home.join("Library"));
        let protection_hit =
            configured.is_protected(path) || (!carve_zone && defaults.is_protected(path));
        // A bare `~/.<name>` that is a plain file is a config dotfile (`.zshrc`,
        // `.gitconfig`, …), never an app-data folder — refuse it regardless of
        // the app slug that produced it.
        let bare_dotfile = path.parent() == Some(home.as_path())
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with('.'))
            && !metadata.is_dir();
        if !is_uninstall_scope(path, &home) || protection_hit || bare_dotfile {
            result.attempted_actions += 1;
            result.skipped_actions += 1;
            result.actions.push(action_result(
                &action,
                ExecutionStatus::Skipped,
                0,
                0,
                "refused: outside the uninstall scope or explicitly protected",
            ));
            continue;
        }

        result.attempted_actions += 1;
        let _ = event_tx.try_send(EngineEvent::ActionStarted {
            action: action.clone(),
        });
        match trash::delete(path) {
            Ok(()) => {
                result.moved_to_trash_bytes =
                    result.moved_to_trash_bytes.saturating_add(reclaimable);
                let _ = event_tx.try_send(EngineEvent::ActionCompleted {
                    action: action.clone(),
                    freed: 0,
                });
                result.actions.push(action_result(
                    &action,
                    ExecutionStatus::MovedToTrash,
                    reclaimable,
                    0,
                    "moved to Trash; bytes are not freed until Trash is emptied",
                ));
            }
            Err(err) => {
                let _ = event_tx.try_send(EngineEvent::ActionFailed {
                    action: action.clone(),
                    error: format!("trash move failed: {err}"),
                });
                result.actions.push(action_result(
                    &action,
                    ExecutionStatus::Failed,
                    0,
                    0,
                    format!("trash move failed: {err}"),
                ));
            }
        }
    }

    result.log_path = write_execution_log(config, started, &result)?;
    Ok(result)
}

fn validate_plan(config: &CleantonConfig, plan: &CleanupPlan) -> Result<()> {
    // Staleness gate. A `created_at` in the future means the wall clock moved
    // backwards since the plan was built; the plan's fingerprints can no longer
    // be trusted as fresh, so refuse instead of silently bypassing the check.
    match std::time::SystemTime::now().duration_since(plan.created_at) {
        Ok(age) if age > Duration::from_mins(15) => {
            return Err(CleantonError::ExecutionRefused(format!(
                "plan is stale (created {} seconds ago, max age is 15 minutes)",
                age.as_secs()
            )));
        }
        Ok(_) => {}
        Err(_) => {
            return Err(CleantonError::ExecutionRefused(
                "plan creation time is in the future (system clock moved backwards); rescan and try again"
                    .to_owned(),
            ));
        }
    }

    if plan.incomplete_scan {
        return Err(CleantonError::ExecutionRefused(
            "plan was produced from an incomplete scan".to_owned(),
        ));
    }

    if plan.total_reclaimable
        > config
            .safety
            .max_single_run_gb
            .saturating_mul(1_073_741_824)
    {
        return Err(CleantonError::ExecutionRefused(format!(
            "plan exceeds max_single_run_gb ({})",
            config.safety.max_single_run_gb
        )));
    }

    let max_action_bytes = config
        .safety
        .max_single_action_gb
        .saturating_mul(1_073_741_824);
    if let Some(action) = plan
        .actions
        .iter()
        .find(|action| action.reclaimable_bytes > max_action_bytes)
    {
        return Err(CleantonError::ExecutionRefused(format!(
            "action exceeds max_single_action_gb: {}",
            action.target.display()
        )));
    }

    if let Some(action) = plan.actions.iter().find(|action| {
        action.action_type == ActionType::Delete && action.safety_level != SafetyLevel::Aggressive
    }) {
        return Err(CleantonError::ExecutionRefused(format!(
            "permanent delete requires aggressive safety level: {}",
            action.target.display()
        )));
    }

    if let Some(action) = plan.actions.iter().find(|action| {
        action.safety_level == SafetyLevel::Aggressive
            && action.reclaimable_bytes > AGGRESSIVE_ACTION_MAX_BYTES
    }) {
        return Err(CleantonError::ExecutionRefused(format!(
            "aggressive action exceeds 5 GB hard limit: {}",
            action.target.display()
        )));
    }

    Ok(())
}

fn execute_action(action: &CleanupAction, protected: &ProtectedPaths) -> ExecutionActionResult {
    if action.action_type != ActionType::Trash && action.action_type != ActionType::Delete {
        return action_result(
            action,
            ExecutionStatus::Skipped,
            0,
            0,
            "unsupported action type",
        );
    }

    if protected.is_protected(&action.target) {
        return action_result(
            action,
            ExecutionStatus::Skipped,
            0,
            0,
            "target is protected",
        );
    }

    match validate_metadata(action) {
        Ok(()) => {}
        Err(message) => {
            return action_result(action, ExecutionStatus::Skipped, 0, 0, message);
        }
    }

    if action.action_type == ActionType::Trash {
        match trash::delete(&action.target) {
            Ok(()) => action_result(
                action,
                ExecutionStatus::MovedToTrash,
                action.reclaimable_bytes,
                0,
                "moved to Trash; bytes are not freed until Trash is emptied",
            ),
            Err(err) => action_result(
                action,
                ExecutionStatus::Failed,
                0,
                0,
                format!("trash move failed: {err}"),
            ),
        }
    } else {
        // ActionType::Delete
        let target_metadata = fs::symlink_metadata(&action.target);
        let is_dir = target_metadata.as_ref().is_ok_and(fs::Metadata::is_dir);
        let is_symlink = target_metadata
            .as_ref()
            .is_ok_and(|m| m.file_type().is_symlink());

        let res = remove_execution_target(&action.target, is_dir, is_symlink);

        match res {
            Ok(()) => action_result(
                action,
                ExecutionStatus::Deleted,
                0,
                action.reclaimable_bytes,
                "permanently deleted",
            ),
            Err(err) => action_result(
                action,
                ExecutionStatus::Failed,
                0,
                0,
                format!("permanent deletion failed: {err}"),
            ),
        }
    }
}

#[allow(clippy::disallowed_methods)]
fn remove_execution_target(path: &Path, is_dir: bool, is_symlink: bool) -> std::io::Result<()> {
    if is_symlink || !is_dir {
        fs::remove_file(path)
    } else {
        fs::remove_dir_all(path)
    }
}

fn validate_metadata(action: &CleanupAction) -> std::result::Result<(), String> {
    let metadata = match fs::symlink_metadata(&action.target) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err("target no longer exists".to_owned());
        }
        Err(err) => {
            return Err(format!("metadata check failed: {err}"));
        }
    };

    let current = fingerprint_for_path(&action.target, &metadata);
    let expected = &action.fingerprint;

    if current.file_kind != expected.file_kind {
        return Err("target kind changed since scan".to_owned());
    }

    if expected.device_id.is_some()
        && current.device_id.is_some()
        && current.device_id != expected.device_id
    {
        return Err("target device changed since scan".to_owned());
    }

    if expected.inode.is_some() && current.inode.is_some() && current.inode != expected.inode {
        return Err("target inode changed since scan".to_owned());
    }

    if current.file_kind != FileKind::Directory && current.logical_bytes != expected.logical_bytes {
        return Err("target logical size changed since scan".to_owned());
    }

    if current.file_kind != FileKind::Directory
        && current.allocated_bytes != expected.allocated_bytes
    {
        return Err("target allocated size changed since scan".to_owned());
    }

    if expected.modified.is_some()
        && current.modified.is_some()
        && current.modified != expected.modified
    {
        return Err("target modified time changed since scan".to_owned());
    }

    Ok(())
}

fn fingerprint_for_path(_path: &Path, metadata: &fs::Metadata) -> MetadataFingerprint {
    let file_type = metadata.file_type();
    let file_kind = if file_type.is_dir() {
        FileKind::Directory
    } else if file_type.is_file() {
        FileKind::File
    } else if file_type.is_symlink() {
        FileKind::Symlink
    } else {
        FileKind::Other
    };

    #[cfg(unix)]
    let device_id = {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.dev())
    };
    #[cfg(not(unix))]
    let device_id = None;

    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.ino())
    };
    #[cfg(not(unix))]
    let inode = None;

    MetadataFingerprint {
        file_kind,
        device_id,
        inode,
        logical_bytes: metadata.len(),
        allocated_bytes: allocated_bytes(metadata),
        modified: metadata.modified().ok(),
    }
}

fn action_result(
    action: &CleanupAction,
    status: ExecutionStatus,
    moved_to_trash_bytes: u64,
    freed_bytes: u64,
    message: impl Into<String>,
) -> ExecutionActionResult {
    ExecutionActionResult {
        target: action.target.clone(),
        recipe_id: action.recipe_id.clone(),
        action_type: action.action_type,
        status,
        logical_bytes: action.logical_bytes,
        moved_to_trash_bytes,
        freed_bytes,
        message: message.into(),
    }
}

fn write_execution_log(
    config: &CleantonConfig,
    started: Instant,
    result: &ExecutionResult,
) -> Result<Option<PathBuf>> {
    let Some(config_dir) = CleantonConfig::config_dir() else {
        return Ok(None);
    };

    let log_dir = config_dir.join("logs");
    fs::create_dir_all(&log_dir).map_err(|source| CleantonError::io(&log_dir, source))?;

    let now: DateTime<Local> = Local::now();
    let log_path = log_dir.join(format!("{}.toml", now.format("%Y-%m-%d_%H-%M-%S")));
    let log = ExecutionLog {
        execution: ExecutionSummary {
            timestamp: now.to_rfc3339(),
            duration_millis: started.elapsed().as_millis(),
            attempted_actions: result.attempted_actions,
            moved_to_trash_bytes: result.moved_to_trash_bytes,
            freed_bytes: result.freed_bytes,
            skipped_actions: result.skipped_actions,
        },
        actions: result.actions.clone(),
    };
    let encoded =
        toml::to_string_pretty(&log).map_err(|err| CleantonError::Config(err.to_string()))?;
    fs::write(&log_path, encoded).map_err(|source| CleantonError::io(&log_path, source))?;

    let max_count = config.general.log_retention_count;
    let max_age =
        Duration::from_secs(u64::from(config.general.log_retention_days).saturating_mul(24 * 3600));
    let _ = rotate_logs(&log_dir, max_count, max_age);

    Ok(Some(log_path))
}

fn rotate_logs(
    log_dir: &Path,
    max_count: usize,
    max_age: std::time::Duration,
) -> std::io::Result<()> {
    let mut log_files = Vec::new();
    let entries = fs::read_dir(log_dir)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml")
            && let Ok(metadata) = entry.metadata()
            && let Ok(modified) = metadata.modified()
        {
            log_files.push((path, modified));
        }
    }

    log_files.sort_by_key(|item| Reverse(item.1)); // Newest first

    let system_now = std::time::SystemTime::now();

    for (i, (path, modified)) in log_files.iter().enumerate() {
        let age = system_now
            .duration_since(*modified)
            .unwrap_or(Duration::ZERO);
        if i >= max_count || age > max_age {
            let _ = remove_rotated_log_file(path);
        }
    }

    Ok(())
}

#[allow(clippy::disallowed_methods)]
fn remove_rotated_log_file(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path)
}

#[derive(Debug, Serialize)]
struct ExecutionLog {
    execution: ExecutionSummary,
    actions: Vec<ExecutionActionResult>,
}

#[derive(Debug, Serialize)]
struct ExecutionSummary {
    timestamp: String,
    duration_millis: u128,
    attempted_actions: u64,
    moved_to_trash_bytes: u64,
    freed_bytes: u64,
    skipped_actions: u64,
}

#[cfg(unix)]
fn allocated_bytes(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn allocated_bytes(metadata: &fs::Metadata) -> u64 {
    metadata.len()
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{Duration, SystemTime},
    };

    use cleanton_common::{Confidence, RecipeId, SafetyLevel};

    use super::*;

    fn test_action(target: PathBuf, fingerprint: MetadataFingerprint) -> CleanupAction {
        CleanupAction {
            target,
            logical_bytes: fingerprint.logical_bytes,
            reclaimable_bytes: fingerprint.allocated_bytes,
            recipe_id: RecipeId("test".to_owned()),
            category: String::new(),
            action_type: ActionType::Delete,
            confidence: Confidence::High,
            safety_level: SafetyLevel::Aggressive,
            reason: "test".to_owned(),
            fingerprint,
        }
    }

    #[tokio::test]
    async fn cancelled_execution_skips_remaining_actions_and_keeps_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file = temp.path().join("cancel-me.txt");
        std::fs::write(&file, b"payload").expect("write file");
        let metadata = std::fs::symlink_metadata(&file).expect("metadata");
        let fingerprint = fingerprint_for_path(&file, &metadata);

        let mut action = test_action(file.clone(), fingerprint);
        action.action_type = ActionType::Trash;
        action.safety_level = SafetyLevel::Safe;
        let plan = CleanupPlan {
            total_reclaimable: action.reclaimable_bytes,
            actions: vec![action],
            scan_duration: Duration::ZERO,
            analysis_duration: Duration::ZERO,
            incomplete_scan: false,
            created_at: SystemTime::now(),
        };

        let cancel = std::sync::atomic::AtomicBool::new(true);
        let (event_tx, _event_rx) = mpsc::channel(8);
        let result =
            execute_plan_with_cancel(&CleantonConfig::default(), &plan, &event_tx, Some(&cancel))
                .expect("cancelled execution still returns a (partial) result");

        assert_eq!(result.attempted_actions, 0);
        assert_eq!(result.skipped_actions, 1);
        assert!(
            result
                .actions
                .iter()
                .all(|a| a.status == ExecutionStatus::Skipped),
            "every action must be recorded as skipped"
        );
        assert!(file.exists(), "a cancelled action must not touch the file");
    }

    #[test]
    fn uninstall_scope_allows_app_bundles_and_library_leftovers_only() {
        let home = Path::new("/Users/dev");

        // Allowed: the app bundle and user-Library leftovers.
        for path in [
            "/Applications/Slack.app",
            "/Applications/Utilities/SomeTool.app",
            "/Users/dev/Applications/Beta.app",
            "/Users/dev/Library/Application Support/com.tiny.slacky",
            "/Users/dev/Library/Caches/com.tiny.slacky.helper",
            "/Users/dev/Library/Preferences/com.tiny.slacky.plist",
            "/Users/dev/Library/Containers/com.tiny.slacky",
            "/Users/dev/Library/Group Containers/ABCDE.com.tiny.slacky",
            "/Users/dev/Library/LaunchAgents/com.tiny.slacky.plist",
            // Home-directory app data (Ollama / LM Studio style). Discovery
            // proposes the whole `~/.ollama` folder as one item, so only the
            // dotfolder itself (not its descendants) needs to be in scope.
            "/Users/dev/.ollama",
            "/Users/dev/.cache/lm-studio",
            "/Users/dev/.config/ollama",
            "/Users/dev/.local/share/ollama",
            "/Users/dev/.local/state/ollama",
        ] {
            assert!(
                is_uninstall_scope(Path::new(path), home),
                "expected in-scope: {path}"
            );
        }

        // Refused: scope roots themselves, sensitive subtrees, system paths,
        // and anything outside the allow-list.
        for path in [
            "/Applications",
            "/Applications/Utilities",
            "/System/Applications/Safari.app",
            "/Applications/Deep/Nested/Tool.app",
            "/Users/dev/Library/Application Support",
            "/Users/dev/Library/Containers",
            "/Users/dev/Library/Keychains/login.keychain-db",
            "/Users/dev/Library/Messages/chat.db",
            "/Users/dev/Library/Mail/V10/whatever",
            "/Users/dev/Documents/report.pdf",
            "/Users/dev/.ssh/id_rsa",
            "/Library/LaunchDaemons/com.tiny.slacky.plist",
            "/usr/local/bin/tool",
            // Reserved home dotfolders and XDG roots themselves.
            "/Users/dev/.ssh",
            "/Users/dev/.config",
            "/Users/dev/.cache",
            "/Users/dev/.local/share",
            "/Users/dev/.gitconfig",
        ] {
            assert!(
                !is_uninstall_scope(Path::new(path), home),
                "expected out of scope: {path}"
            );
        }
    }

    #[tokio::test]
    async fn uninstall_refuses_out_of_scope_paths_and_keeps_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let outside = temp.path().join("not-an-app-location.txt");
        std::fs::write(&outside, b"payload").expect("write file");

        let (event_tx, _event_rx) = mpsc::channel(8);
        let result = trash_uninstall_paths(
            &CleantonConfig::default(),
            std::slice::from_ref(&outside),
            &event_tx,
        )
        .expect("result");

        assert_eq!(result.skipped_actions, 1);
        assert_eq!(result.moved_to_trash_bytes, 0);
        assert!(
            result
                .actions
                .iter()
                .all(|a| a.status == ExecutionStatus::Skipped),
            "out-of-scope items must be skipped, not trashed"
        );
        assert!(outside.exists(), "the file must be untouched");
    }

    #[test]
    fn incomplete_scan_plan_is_refused() {
        let plan = CleanupPlan {
            actions: Vec::new(),
            total_reclaimable: 0,
            scan_duration: Duration::ZERO,
            analysis_duration: Duration::ZERO,
            incomplete_scan: true,
            created_at: SystemTime::now(),
        };

        let err = validate_plan(&CleantonConfig::default(), &plan).expect_err("refused");
        assert!(err.to_string().contains("incomplete scan"));
    }

    #[test]
    fn stale_plan_is_refused() {
        let plan = CleanupPlan {
            actions: Vec::new(),
            total_reclaimable: 0,
            scan_duration: Duration::ZERO,
            analysis_duration: Duration::ZERO,
            incomplete_scan: false,
            created_at: SystemTime::now() - Duration::from_mins(20),
        };

        let err = validate_plan(&CleantonConfig::default(), &plan).expect_err("refused");
        assert!(err.to_string().contains("stale"));
    }

    #[test]
    fn oversized_plan_is_refused() {
        let oversized_bytes = 251_u64 * 1_073_741_824;
        let plan = CleanupPlan {
            actions: vec![CleanupAction {
                target: PathBuf::from("/tmp/cleanton-test-target"),
                logical_bytes: oversized_bytes,
                reclaimable_bytes: oversized_bytes,
                recipe_id: RecipeId("test".to_owned()),
                category: String::new(),
                action_type: ActionType::Trash,
                confidence: Confidence::High,
                safety_level: SafetyLevel::Safe,
                reason: "test".to_owned(),
                fingerprint: MetadataFingerprint {
                    file_kind: FileKind::Directory,
                    device_id: None,
                    inode: None,
                    logical_bytes: oversized_bytes,
                    allocated_bytes: oversized_bytes,
                    modified: None,
                },
            }],
            total_reclaimable: oversized_bytes,
            scan_duration: Duration::ZERO,
            analysis_duration: Duration::ZERO,
            incomplete_scan: false,
            created_at: SystemTime::now(),
        };

        let err = validate_plan(&CleantonConfig::default(), &plan).expect_err("refused");
        assert!(err.to_string().contains("max_single_run_gb"));
    }

    #[test]
    fn non_aggressive_delete_plan_is_refused() {
        let plan = CleanupPlan {
            actions: vec![CleanupAction {
                target: PathBuf::from("/tmp/cleanton-test-target"),
                logical_bytes: 1,
                reclaimable_bytes: 1,
                recipe_id: RecipeId("test".to_owned()),
                category: String::new(),
                action_type: ActionType::Delete,
                confidence: Confidence::High,
                safety_level: SafetyLevel::Safe,
                reason: "test".to_owned(),
                fingerprint: MetadataFingerprint {
                    file_kind: FileKind::File,
                    device_id: None,
                    inode: None,
                    logical_bytes: 1,
                    allocated_bytes: 1,
                    modified: None,
                },
            }],
            total_reclaimable: 1,
            scan_duration: Duration::ZERO,
            analysis_duration: Duration::ZERO,
            incomplete_scan: false,
            created_at: SystemTime::now(),
        };

        let err = validate_plan(&CleantonConfig::default(), &plan).expect_err("refused");
        assert!(
            err.to_string()
                .contains("permanent delete requires aggressive")
        );
    }

    #[test]
    fn oversized_aggressive_action_is_refused() {
        let oversized_bytes = AGGRESSIVE_ACTION_MAX_BYTES + 1;
        let plan = CleanupPlan {
            actions: vec![CleanupAction {
                target: PathBuf::from("/tmp/cleanton-test-target"),
                logical_bytes: oversized_bytes,
                reclaimable_bytes: oversized_bytes,
                recipe_id: RecipeId("test".to_owned()),
                category: String::new(),
                action_type: ActionType::Trash,
                confidence: Confidence::High,
                safety_level: SafetyLevel::Aggressive,
                reason: "test".to_owned(),
                fingerprint: MetadataFingerprint {
                    file_kind: FileKind::Directory,
                    device_id: None,
                    inode: None,
                    logical_bytes: oversized_bytes,
                    allocated_bytes: oversized_bytes,
                    modified: None,
                },
            }],
            total_reclaimable: oversized_bytes,
            scan_duration: Duration::ZERO,
            analysis_duration: Duration::ZERO,
            incomplete_scan: false,
            created_at: SystemTime::now(),
        };

        let err = validate_plan(&CleantonConfig::default(), &plan).expect_err("refused");
        assert!(err.to_string().contains("aggressive action exceeds 5 GB"));
    }

    #[test]
    fn test_permanent_deletion() {
        let workspace_dir = std::env::current_dir().expect("cwd");
        let temp = tempfile::Builder::new()
            .prefix("cleanton-test")
            .tempdir_in(&workspace_dir)
            .expect("tempdir");
        let file_path = temp.path().join("delete_me.txt");
        fs::write(&file_path, "delete me").expect("write file");

        let metadata = fs::metadata(&file_path).expect("metadata");
        let fingerprint = fingerprint_for_path(&file_path, &metadata);

        let action = CleanupAction {
            target: file_path.clone(),
            logical_bytes: 9,
            reclaimable_bytes: 9,
            recipe_id: RecipeId("test-delete".to_owned()),
            category: String::new(),
            action_type: ActionType::Delete,
            confidence: Confidence::High,
            safety_level: SafetyLevel::Aggressive,
            reason: "test".to_owned(),
            fingerprint,
        };

        let protected = ProtectedPaths::new(vec![]);
        let res = execute_action(&action, &protected);

        assert_eq!(res.status, ExecutionStatus::Deleted);
        assert_eq!(res.freed_bytes, 9);
        assert!(!file_path.exists());
    }

    #[test]
    fn test_symlink_deletion() {
        let workspace_dir = std::env::current_dir().expect("cwd");
        let temp = tempfile::Builder::new()
            .prefix("cleanton-test")
            .tempdir_in(&workspace_dir)
            .expect("tempdir");
        let file_path = temp.path().join("target.txt");
        fs::write(&file_path, "target").expect("write file");

        let symlink_path = temp.path().join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&file_path, &symlink_path).expect("symlink");
        #[cfg(not(unix))]
        return; // skip on non-unix

        let metadata = fs::symlink_metadata(&symlink_path).expect("metadata");
        let fingerprint = fingerprint_for_path(&symlink_path, &metadata);

        let action = CleanupAction {
            target: symlink_path.clone(),
            logical_bytes: 0,
            reclaimable_bytes: 0,
            recipe_id: RecipeId("test-symlink".to_owned()),
            category: String::new(),
            action_type: ActionType::Delete,
            confidence: Confidence::High,
            safety_level: SafetyLevel::Aggressive,
            reason: "test".to_owned(),
            fingerprint,
        };

        let protected = ProtectedPaths::new(vec![]);
        let res = execute_action(&action, &protected);

        assert_eq!(res.status, ExecutionStatus::Deleted);
        assert!(!symlink_path.exists());
        assert!(file_path.exists()); // target should still exist!
    }

    #[test]
    fn validate_metadata_refuses_logical_size_change() {
        let workspace_dir = std::env::current_dir().expect("cwd");
        let temp = tempfile::Builder::new()
            .prefix("cleanton-test")
            .tempdir_in(&workspace_dir)
            .expect("tempdir");
        let file_path = temp.path().join("changed-logical-size.txt");
        fs::write(&file_path, "original").expect("write file");

        let metadata = fs::symlink_metadata(&file_path).expect("metadata");
        let mut fingerprint = fingerprint_for_path(&file_path, &metadata);
        fingerprint.logical_bytes = fingerprint.logical_bytes.saturating_add(1);
        let action = test_action(file_path, fingerprint);

        let err = validate_metadata(&action).expect_err("size mismatch is refused");
        assert!(err.contains("logical size changed"));
    }

    #[test]
    fn validate_metadata_refuses_allocated_size_change() {
        let workspace_dir = std::env::current_dir().expect("cwd");
        let temp = tempfile::Builder::new()
            .prefix("cleanton-test")
            .tempdir_in(&workspace_dir)
            .expect("tempdir");
        let file_path = temp.path().join("changed-allocated-size.txt");
        fs::write(&file_path, "original").expect("write file");

        let metadata = fs::symlink_metadata(&file_path).expect("metadata");
        let mut fingerprint = fingerprint_for_path(&file_path, &metadata);
        fingerprint.allocated_bytes = fingerprint.allocated_bytes.saturating_add(512);
        let action = test_action(file_path, fingerprint);

        let err = validate_metadata(&action).expect_err("allocated mismatch is refused");
        assert!(err.contains("allocated size changed"));
    }

    #[test]
    fn validate_metadata_allows_directory_aggregate_size_fingerprint() {
        let workspace_dir = std::env::current_dir().expect("cwd");
        let temp = tempfile::Builder::new()
            .prefix("cleanton-test")
            .tempdir_in(&workspace_dir)
            .expect("tempdir");
        let dir_path = temp.path().join("target");
        fs::create_dir(&dir_path).expect("create dir");
        fs::write(dir_path.join("artifact.bin"), [1_u8; 8192]).expect("write artifact");

        let metadata = fs::symlink_metadata(&dir_path).expect("metadata");
        let mut fingerprint = fingerprint_for_path(&dir_path, &metadata);
        fingerprint.logical_bytes = 8192;
        fingerprint.allocated_bytes = 8192;
        let action = test_action(dir_path, fingerprint);

        validate_metadata(&action).expect("directory aggregate size should validate");
    }

    #[test]
    fn directory_delete_allows_aggregate_size_fingerprint() {
        let workspace_dir = std::env::current_dir().expect("cwd");
        let temp = tempfile::Builder::new()
            .prefix("cleanton-test")
            .tempdir_in(&workspace_dir)
            .expect("tempdir");
        let dir_path = temp.path().join("target");
        fs::create_dir(&dir_path).expect("create dir");
        fs::write(dir_path.join("artifact.bin"), [1_u8; 8192]).expect("write artifact");

        let metadata = fs::symlink_metadata(&dir_path).expect("metadata");
        let mut fingerprint = fingerprint_for_path(&dir_path, &metadata);
        fingerprint.logical_bytes = 8192;
        fingerprint.allocated_bytes = 8192;
        let action = test_action(dir_path.clone(), fingerprint);
        let protected = ProtectedPaths::new(vec![]);

        let res = execute_action(&action, &protected);

        assert_eq!(res.status, ExecutionStatus::Deleted);
        assert_eq!(res.freed_bytes, 8192);
        assert!(!dir_path.exists());
    }

    #[test]
    fn validate_metadata_refuses_modified_time_change_when_expected_has_one() {
        let workspace_dir = std::env::current_dir().expect("cwd");
        let temp = tempfile::Builder::new()
            .prefix("cleanton-test")
            .tempdir_in(&workspace_dir)
            .expect("tempdir");
        let file_path = temp.path().join("changed-modified-time.txt");
        fs::write(&file_path, "original").expect("write file");

        let metadata = fs::symlink_metadata(&file_path).expect("metadata");
        let mut fingerprint = fingerprint_for_path(&file_path, &metadata);
        fingerprint.modified = Some(SystemTime::UNIX_EPOCH);
        let action = test_action(file_path, fingerprint);

        let err = validate_metadata(&action).expect_err("modified mismatch is refused");
        assert!(err.contains("modified time changed"));
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn missing_target_is_skipped_not_failed() {
        let workspace_dir = std::env::current_dir().expect("cwd");
        let temp = tempfile::Builder::new()
            .prefix("cleanton-test")
            .tempdir_in(&workspace_dir)
            .expect("tempdir");
        let file_path = temp.path().join("missing-target.txt");
        fs::write(&file_path, "deleted before execution").expect("write file");

        let metadata = fs::symlink_metadata(&file_path).expect("metadata");
        let fingerprint = fingerprint_for_path(&file_path, &metadata);
        fs::remove_file(&file_path).expect("remove file");

        let action = test_action(file_path, fingerprint);
        let protected = ProtectedPaths::new(vec![]);
        let res = execute_action(&action, &protected);

        assert_eq!(res.status, ExecutionStatus::Skipped);
        assert!(res.message.contains("target no longer exists"));
    }

    #[tokio::test]
    async fn trash_reviewed_path_refuses_a_critical_protected_path() {
        // A system root must be refused before any trash attempt, even for an
        // explicitly user-confirmed suggestion removal.
        let (tx, _rx) = mpsc::channel(4);
        let err = trash_reviewed_path(&CleantonConfig::default(), Path::new("/usr/bin"), &tx)
            .expect_err("critical path must be refused");
        assert!(err.to_string().contains("protected"));
    }

    #[test]
    fn test_log_rotation_count() {
        let temp = tempfile::tempdir().expect("tempdir");
        let log_dir = temp.path();

        // Create 5 toml files with slight delays to ensure distinct mtimes
        for i in 1..=5 {
            let path = log_dir.join(format!("log_{i}.toml"));
            fs::write(&path, "log").expect("write log");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        // Run rotation keeping only 3 files
        let res = rotate_logs(log_dir, 3, Duration::from_hours(1));
        assert!(res.is_ok());

        // Count how many files are left
        let count = fs::read_dir(log_dir)
            .expect("read log dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "toml"))
            .count();

        assert_eq!(count, 3);
    }
}
