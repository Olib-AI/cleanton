//! Homebrew formulae and casks.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::managers::{outcome, parse_freed};
use crate::process::{ACTION_TIMEOUT, NETWORK_READ_TIMEOUT, READ_TIMEOUT, run, which};
use crate::types::{ActionOutcome, Inventory, ManagerKind, Package};

#[derive(Debug, Default, Deserialize)]
struct BrewInfoV2 {
    #[serde(default)]
    formulae: Vec<BrewFormula>,
    #[serde(default)]
    casks: Vec<BrewCask>,
}

#[derive(Debug, Default, Deserialize)]
struct BrewFormula {
    name: String,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    installed: Vec<BrewInstalled>,
}

#[derive(Debug, Default, Deserialize)]
struct BrewInstalled {
    #[serde(default)]
    version: String,
    #[serde(default)]
    installed_on_request: bool,
}

#[derive(Debug, Default, Deserialize)]
struct BrewCask {
    token: String,
    #[serde(default)]
    installed: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct BrewOutdated {
    #[serde(default)]
    formulae: Vec<BrewOutdatedItem>,
    #[serde(default)]
    casks: Vec<BrewOutdatedItem>,
}

#[derive(Debug, Default, Deserialize)]
struct BrewOutdatedItem {
    name: String,
    #[serde(default)]
    current_version: String,
}

/// `true` when the `brew` binary is on `PATH`.
pub(crate) fn detected() -> bool {
    which("brew").is_some()
}

/// Read-only inventory of installed formulae with deps, leaves, sizes, outdated.
pub(crate) async fn inventory_formulae() -> Inventory {
    if !detected() {
        return Inventory::missing(ManagerKind::Homebrew, "Homebrew not installed");
    }
    let Some(info) = run("brew", ["info", "--json=v2", "--installed"], READ_TIMEOUT).await else {
        return Inventory::degraded(ManagerKind::Homebrew, "`brew info` timed out");
    };

    let parsed: BrewInfoV2 = match serde_json::from_str(&info.stdout) {
        Ok(value) => value,
        Err(err) => {
            return Inventory::degraded(
                ManagerKind::Homebrew,
                format!("could not parse `brew info` JSON: {err}"),
            );
        }
    };

    let leaves = brew_leaves().await;
    let sizes = match brew_path("--cellar").await {
        Some(cellar) => du_sizes(&cellar).await,
        None => HashMap::new(),
    };

    let packages = parsed
        .formulae
        .into_iter()
        .map(|formula| {
            let first = formula.installed.into_iter().next().unwrap_or_default();
            Package {
                manager: ManagerKind::Homebrew,
                size_bytes: sizes.get(&formula.name).copied().unwrap_or(0),
                is_leaf: leaves.contains(&formula.name),
                explicitly_installed: first.installed_on_request,
                // Filled in by a separate, slower network probe (see `outdated`).
                outdated_to: None,
                deps: formula.dependencies,
                used_by: Vec::new(),
                version: first.version,
                name: formula.name,
            }
        })
        .collect();

    Inventory::ready(ManagerKind::Homebrew, packages, None)
}

/// Read-only inventory of installed casks (no dependency graph).
pub(crate) async fn inventory_casks() -> Inventory {
    if !detected() {
        return Inventory::missing(ManagerKind::HomebrewCask, "Homebrew not installed");
    }
    let Some(info) = run(
        "brew",
        ["info", "--json=v2", "--installed", "--cask"],
        READ_TIMEOUT,
    )
    .await
    else {
        return Inventory::degraded(ManagerKind::HomebrewCask, "`brew info --cask` timed out");
    };

    let parsed: BrewInfoV2 = match serde_json::from_str(&info.stdout) {
        Ok(value) => value,
        Err(err) => {
            return Inventory::degraded(
                ManagerKind::HomebrewCask,
                format!("could not parse `brew info --cask` JSON: {err}"),
            );
        }
    };

    let sizes = match brew_path("--caskroom").await {
        Some(caskroom) => du_sizes(&caskroom).await,
        None => HashMap::new(),
    };

    let packages = parsed
        .casks
        .into_iter()
        .map(|cask| Package {
            manager: ManagerKind::HomebrewCask,
            size_bytes: sizes.get(&cask.token).copied().unwrap_or(0),
            is_leaf: true,
            explicitly_installed: true,
            // Filled in by a separate, slower network probe (see `outdated`).
            outdated_to: None,
            deps: Vec::new(),
            used_by: Vec::new(),
            version: cask.installed.unwrap_or_default(),
            name: cask.token,
        })
        .collect();

    Inventory::ready(ManagerKind::HomebrewCask, packages, None)
}

/// `brew uninstall [--cask] <names...>` (dependency-aware; never `--ignore-dependencies`).
///
/// Casks MUST be uninstalled with `--cask`. Without it Homebrew treats the
/// token as a formula name and refuses to remove the `.app` bundle, which is
/// the "remove an app and it is still there" bug. The `.app` bundle is what
/// the user actually sees, so the flag is the whole point of this path.
pub(crate) async fn uninstall(cask: bool, names: &[String]) -> ActionOutcome {
    if names.is_empty() {
        return ActionOutcome::failed("no packages specified");
    }
    outcome(run("brew", uninstall_args(cask, names), ACTION_TIMEOUT).await, 0)
}

/// Pure argument builder for [`uninstall`], split out so the `--cask` flag is
/// unit-tested without ever shelling out to `brew`.
fn uninstall_args<'a>(cask: bool, names: &'a [String]) -> Vec<&'a str> {
    let mut args: Vec<&str> = vec!["uninstall"];
    if cask {
        args.push("--cask");
    }
    args.extend(names.iter().map(String::as_str));
    args
}

/// `brew upgrade [names...]` (empty `names` upgrades everything).
pub(crate) async fn update(names: &[String]) -> ActionOutcome {
    let mut args: Vec<&str> = vec!["upgrade"];
    args.extend(names.iter().map(String::as_str));
    outcome(run("brew", args, ACTION_TIMEOUT).await, 0)
}

/// `brew cleanup -s`; freed bytes parsed from the notice when present.
pub(crate) async fn clean_cache() -> ActionOutcome {
    let result = run("brew", ["cleanup", "-s"], ACTION_TIMEOUT).await;
    let freed = result.as_ref().map_or(0, |out| parse_freed(&out.stdout));
    outcome(result, freed)
}

async fn brew_leaves() -> HashSet<String> {
    let mut set = HashSet::new();
    if let Some(out) = run("brew", ["leaves"], READ_TIMEOUT).await
        && out.status_ok
    {
        for line in out.stdout.lines() {
            let name = line.trim();
            if !name.is_empty() {
                set.insert(name.to_owned());
            }
        }
    }
    set
}

/// Network-bound update check (`brew outdated`); runs off the inventory's fast
/// path. Pass `cask = true` for casks, `false` for formulae.
pub(crate) async fn outdated(cask: bool) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let args: &[&str] = if cask {
        &["outdated", "--json=v2", "--cask"]
    } else {
        &["outdated", "--json=v2"]
    };
    let Some(out) = run("brew", args.iter().copied(), NETWORK_READ_TIMEOUT).await else {
        return map;
    };
    let Ok(parsed) = serde_json::from_str::<BrewOutdated>(&out.stdout) else {
        return map;
    };
    let items = if cask { parsed.casks } else { parsed.formulae };
    for item in items {
        if !item.current_version.is_empty() {
            map.insert(item.name, item.current_version);
        }
    }
    map
}

async fn brew_path(flag: &str) -> Option<PathBuf> {
    let out = run("brew", [flag], READ_TIMEOUT).await?;
    if !out.status_ok {
        return None;
    }
    let path = out.stdout.trim();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// One `du -sk <child...>` over the immediate children of `root`, mapping each
/// child's basename to its size in bytes. A single invocation, not one per dir.
async fn du_sizes(root: &Path) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return map;
    };
    let mut children: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    if children.is_empty() {
        return map;
    }
    children.sort();

    let mut args: Vec<OsString> = Vec::with_capacity(children.len().saturating_add(1));
    args.push(OsString::from("-sk"));
    for child in &children {
        args.push(child.clone().into_os_string());
    }

    let Some(out) = run("du", args, READ_TIMEOUT).await else {
        return map;
    };
    for line in out.stdout.lines() {
        // du output is `<KiB>\t<path>`; split on the tab to tolerate spaces.
        let Some((kib_str, path_str)) = line.split_once('\t') else {
            continue;
        };
        let Ok(kib) = kib_str.trim().parse::<u64>() else {
            continue;
        };
        if let Some(base) = Path::new(path_str)
            .file_name()
            .and_then(|name| name.to_str())
        {
            map.insert(base.to_owned(), kib.saturating_mul(1024));
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::uninstall_args;

    #[test]
    fn cask_uninstall_includes_the_cask_flag() {
        // Regression: removing a cask (an .app) must pass --cask, otherwise
        // Homebrew treats the token as a formula and leaves the bundle in place.
        let names = vec!["firefox".to_owned(), "slack".to_owned()];
        assert_eq!(
            uninstall_args(true, &names),
            vec!["uninstall", "--cask", "firefox", "slack"]
        );
    }

    #[test]
    fn formula_uninstall_omits_the_cask_flag() {
        let names = vec!["git".to_owned()];
        assert_eq!(uninstall_args(false, &names), vec!["uninstall", "git"]);
    }
}
