//! Python packages visible to `pip3` (fallback `pip`).

use std::collections::HashMap;

use serde::Deserialize;

use crate::managers::outcome;
use crate::process::{ACTION_TIMEOUT, NETWORK_READ_TIMEOUT, READ_TIMEOUT, run, which};
use crate::types::{ActionOutcome, Inventory, ManagerKind, Package};

#[derive(Debug, Default, Deserialize)]
struct PipPackage {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

#[derive(Debug, Default, Deserialize)]
struct PipOutdated {
    #[serde(default)]
    name: String,
    #[serde(default)]
    latest_version: String,
}

/// Returns the pip executable to use, preferring `pip3`.
fn pip_binary() -> Option<&'static str> {
    if which("pip3").is_some() {
        Some("pip3")
    } else if which("pip").is_some() {
        Some("pip")
    } else {
        None
    }
}

pub(crate) fn detected() -> bool {
    pip_binary().is_some()
}

pub(crate) async fn inventory() -> Inventory {
    let Some(bin) = pip_binary() else {
        return Inventory::missing(ManagerKind::Pip, "pip not installed");
    };
    let Some(out) = run(bin, ["list", "--format=json"], READ_TIMEOUT).await else {
        return Inventory::degraded(ManagerKind::Pip, "`pip list` timed out");
    };
    let parsed: Vec<PipPackage> = match serde_json::from_str(&out.stdout) {
        Ok(value) => value,
        Err(err) => {
            return Inventory::degraded(
                ManagerKind::Pip,
                format!("could not parse `pip list` JSON: {err}"),
            );
        }
    };

    let packages = parsed
        .into_iter()
        .filter(|pkg| !pkg.name.is_empty())
        .map(|pkg| Package {
            manager: ManagerKind::Pip,
            size_bytes: 0,
            is_leaf: true,
            explicitly_installed: true,
            // `outdated_to` is filled in by a separate, slower network probe
            // (see `outdated`) so the inventory list can render immediately.
            outdated_to: None,
            deps: Vec::new(),
            used_by: Vec::new(),
            version: pkg.version,
            name: pkg.name,
        })
        .collect();

    Inventory::ready(ManagerKind::Pip, packages, None)
}

pub(crate) async fn uninstall(names: &[String]) -> ActionOutcome {
    let Some(bin) = pip_binary() else {
        return ActionOutcome::failed("pip not installed");
    };
    if names.is_empty() {
        return ActionOutcome::failed("no packages specified");
    }
    let mut args: Vec<&str> = vec!["uninstall", "-y"];
    args.extend(names.iter().map(String::as_str));
    outcome(run(bin, args, ACTION_TIMEOUT).await, 0)
}

pub(crate) async fn update(names: &[String]) -> ActionOutcome {
    let Some(bin) = pip_binary() else {
        return ActionOutcome::failed("pip not installed");
    };
    if names.is_empty() {
        return ActionOutcome::failed(
            "pip cannot upgrade all packages safely; specify package names",
        );
    }
    let mut args: Vec<&str> = vec!["install", "--upgrade"];
    args.extend(names.iter().map(String::as_str));
    outcome(run(bin, args, ACTION_TIMEOUT).await, 0)
}

pub(crate) async fn clean_cache() -> ActionOutcome {
    let Some(bin) = pip_binary() else {
        return ActionOutcome::failed("pip not installed");
    };
    outcome(run(bin, ["cache", "purge"], ACTION_TIMEOUT).await, 0)
}

/// Network-bound update check (`pip list --outdated`); slow because it queries
/// `PyPI` for every installed package, so it runs off the inventory's fast path.
pub(crate) async fn outdated() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(bin) = pip_binary() else {
        return map;
    };
    let Some(out) = run(
        bin,
        ["list", "--outdated", "--format=json"],
        NETWORK_READ_TIMEOUT,
    )
    .await
    else {
        return map;
    };
    let Ok(parsed) = serde_json::from_str::<Vec<PipOutdated>>(&out.stdout) else {
        return map;
    };
    for entry in parsed {
        if !entry.name.is_empty() && !entry.latest_version.is_empty() {
            map.insert(entry.name, entry.latest_version);
        }
    }
    map
}
