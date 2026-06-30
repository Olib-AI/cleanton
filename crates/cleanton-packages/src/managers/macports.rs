//! `MacPorts` ports.
//!
//! Inventory, outdated, and leaves are read-only and unprivileged. Mutations
//! (`uninstall`/`upgrade`/`clean`) require root, so they run through the same
//! `osascript ... with administrator privileges` prompt that
//! `cleanton-services` uses for launchd/brew elevation. The elevated command is
//! the `port` binary itself (run as root by the prompt) — never a `sudo` prefix.
//! If `port` is not on `PATH`, mutations return a non-OK [`ActionOutcome`]
//! explaining the manual `sudo port …` fallback.

use std::collections::{HashMap, HashSet};

use crate::managers::outcome;
use crate::process::{ADMIN_TIMEOUT, READ_TIMEOUT, run, run_admin, which};
use crate::types::{ActionOutcome, Inventory, ManagerKind, Package};

/// Conventional `MacPorts` prefix when `port` is installed but not yet on `PATH`.
const FALLBACK_PORT: &str = "/opt/local/bin/port";

pub(crate) fn detected() -> bool {
    which("port").is_some()
}

fn port_path() -> Option<String> {
    which("port")
        .and_then(|path| path.to_str().map(str::to_owned))
        .or_else(|| {
            if std::path::Path::new(FALLBACK_PORT).is_file() {
                Some(FALLBACK_PORT.to_owned())
            } else {
                None
            }
        })
}

pub(crate) async fn inventory() -> Inventory {
    if !detected() {
        return Inventory::missing(ManagerKind::MacPorts, "MacPorts not installed");
    }
    let Some(out) = run("port", ["-q", "installed"], READ_TIMEOUT).await else {
        return Inventory::degraded(ManagerKind::MacPorts, "`port installed` timed out");
    };

    let leaves = macports_leaves().await;

    // Prefer the active version per port name.
    let mut chosen: HashMap<String, (String, bool)> = HashMap::new();
    for line in out.stdout.lines() {
        let Some((name, version, active)) = parse_installed_line(line) else {
            continue;
        };
        let replace = match chosen.get(&name) {
            Some((_, existing_active)) => active && !existing_active,
            None => true,
        };
        if replace {
            chosen.insert(name, (version, active));
        }
    }

    let packages = chosen
        .into_iter()
        .map(|(name, (version, _active))| Package {
            manager: ManagerKind::MacPorts,
            size_bytes: 0,
            is_leaf: leaves.contains(&name),
            explicitly_installed: true,
            // Filled in by a separate, slower probe (see `outdated`).
            outdated_to: None,
            deps: Vec::new(),
            used_by: Vec::new(),
            version,
            name,
        })
        .collect();

    let note = Some(
        "MacPorts changes require administrator privileges (you will be prompted).".to_owned(),
    );
    Inventory::ready(ManagerKind::MacPorts, packages, note)
}

pub(crate) async fn uninstall(names: &[String]) -> ActionOutcome {
    if names.is_empty() {
        return ActionOutcome::failed("no packages specified");
    }
    let Some(port) = port_path() else {
        return ActionOutcome::failed(
            "MacPorts not found; run `sudo port uninstall <names>` in Terminal",
        );
    };
    let mut args: Vec<&str> = vec!["uninstall"];
    args.extend(names.iter().map(String::as_str));
    outcome(run_admin(&port, &args, ADMIN_TIMEOUT).await, 0)
}

pub(crate) async fn update(names: &[String]) -> ActionOutcome {
    let Some(port) = port_path() else {
        return ActionOutcome::failed(
            "MacPorts not found; run `sudo port upgrade outdated` in Terminal",
        );
    };
    let mut args: Vec<&str> = vec!["upgrade"];
    if names.is_empty() {
        args.push("outdated");
    } else {
        args.extend(names.iter().map(String::as_str));
    }
    outcome(run_admin(&port, &args, ADMIN_TIMEOUT).await, 0)
}

pub(crate) async fn clean_cache() -> ActionOutcome {
    let Some(port) = port_path() else {
        return ActionOutcome::failed(
            "MacPorts not found; run `sudo port clean --all installed` in Terminal",
        );
    };
    outcome(
        run_admin(&port, &["clean", "--all", "installed"], ADMIN_TIMEOUT).await,
        0,
    )
}

async fn macports_leaves() -> HashSet<String> {
    let mut set = HashSet::new();
    if let Some(out) = run("port", ["-q", "echo", "leaves"], READ_TIMEOUT).await
        && out.status_ok
    {
        for line in out.stdout.lines() {
            if let Some(name) = line.split_whitespace().next()
                && !name.is_empty()
            {
                set.insert(name.to_owned());
            }
        }
    }
    set
}

/// Update check (`port outdated`); runs off the inventory's fast path for
/// consistency with the other managers.
pub(crate) async fn outdated() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(out) = run("port", ["outdated"], READ_TIMEOUT).await else {
        return map;
    };
    for line in out.stdout.lines() {
        if let Some((name, latest)) = parse_outdated_line(line) {
            map.insert(name, latest);
        }
    }
    map
}

/// Parses `name @1.2.3_0 (active)` (with leading whitespace) into
/// `(name, version, active)`.
fn parse_installed_line(line: &str) -> Option<(String, String, bool)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut tokens = trimmed.split_whitespace();
    let name = tokens.next()?.to_owned();
    let raw_version = tokens.next().unwrap_or("");
    let version = raw_version.trim_start_matches('@').to_owned();
    let active = trimmed.contains("(active)");
    Some((name, version, active))
}

/// Parses `name  1.0 < 1.1` into `(name, latest)`.
fn parse_outdated_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if !trimmed.contains('<') {
        return None;
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    let name = (*tokens.first()?).to_owned();
    let lt_index = tokens.iter().position(|token| *token == "<")?;
    let latest = tokens.get(lt_index.saturating_add(1))?;
    Some((name, (*latest).to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_installed_lines() {
        assert_eq!(
            parse_installed_line("  gettext @0.21_0 (active)"),
            Some(("gettext".to_owned(), "0.21_0".to_owned(), true))
        );
        assert_eq!(
            parse_installed_line("  zlib @1.3_0"),
            Some(("zlib".to_owned(), "1.3_0".to_owned(), false))
        );
        assert_eq!(parse_installed_line("   "), None);
    }

    #[test]
    fn parses_outdated_lines() {
        assert_eq!(
            parse_outdated_line("curl                           8.1.0_0 < 8.2.0_0"),
            Some(("curl".to_owned(), "8.2.0_0".to_owned()))
        );
        assert_eq!(
            parse_outdated_line("The following installed ports are outdated:"),
            None
        );
    }
}
