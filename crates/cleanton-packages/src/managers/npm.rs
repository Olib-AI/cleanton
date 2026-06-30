//! Globally installed npm packages.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::managers::outcome;
use crate::process::{ACTION_TIMEOUT, NETWORK_READ_TIMEOUT, READ_TIMEOUT, run, which};
use crate::types::{ActionOutcome, Inventory, ManagerKind, Package};

#[derive(Debug, Default, Deserialize)]
struct NpmList {
    #[serde(default)]
    dependencies: HashMap<String, NpmDep>,
}

#[derive(Debug, Default, Deserialize)]
struct NpmDep {
    #[serde(default)]
    version: String,
}

#[derive(Debug, Default, Deserialize)]
struct NpmOutdatedEntry {
    #[serde(default)]
    latest: String,
}

pub(crate) fn detected() -> bool {
    which("npm").is_some()
}

pub(crate) async fn inventory() -> Inventory {
    if !detected() {
        return Inventory::missing(ManagerKind::Npm, "npm not installed");
    }
    // `npm ls` exits non-zero on peer-dep warnings, so parse stdout regardless.
    let Some(out) = run("npm", ["ls", "-g", "--depth=0", "--json"], READ_TIMEOUT).await else {
        return Inventory::degraded(ManagerKind::Npm, "`npm ls -g` timed out");
    };
    let parsed: NpmList = match serde_json::from_str(&out.stdout) {
        Ok(value) => value,
        Err(err) => {
            return Inventory::degraded(
                ManagerKind::Npm,
                format!("could not parse `npm ls` JSON: {err}"),
            );
        }
    };

    let sizes = npm_sizes().await;

    let packages = parsed
        .dependencies
        .into_iter()
        .map(|(name, dep)| Package {
            manager: ManagerKind::Npm,
            size_bytes: sizes.get(&name).copied().unwrap_or(0),
            is_leaf: true,
            explicitly_installed: true,
            // Filled in by a separate, slower network probe (see `outdated`).
            outdated_to: None,
            deps: Vec::new(),
            used_by: Vec::new(),
            version: dep.version,
            name,
        })
        .collect();

    Inventory::ready(ManagerKind::Npm, packages, None)
}

pub(crate) async fn uninstall(names: &[String]) -> ActionOutcome {
    if names.is_empty() {
        return ActionOutcome::failed("no packages specified");
    }
    let mut args: Vec<&str> = vec!["uninstall", "-g"];
    args.extend(names.iter().map(String::as_str));
    outcome(run("npm", args, ACTION_TIMEOUT).await, 0)
}

pub(crate) async fn update(names: &[String]) -> ActionOutcome {
    if names.is_empty() {
        return outcome(run("npm", ["update", "-g"], ACTION_TIMEOUT).await, 0);
    }
    // Upgrade each named package to @latest; stop reporting on the first failure.
    let mut last = ActionOutcome::failed("no packages specified");
    for name in names {
        let spec = format!("{name}@latest");
        last = outcome(
            run("npm", ["install", "-g", spec.as_str()], ACTION_TIMEOUT).await,
            0,
        );
        if !last.ok {
            return last;
        }
    }
    last
}

pub(crate) async fn clean_cache() -> ActionOutcome {
    outcome(
        run("npm", ["cache", "clean", "--force"], ACTION_TIMEOUT).await,
        0,
    )
}

/// Network-bound update check (`npm outdated -g`); runs off the inventory's
/// fast path since it queries the registry per package.
pub(crate) async fn outdated() -> HashMap<String, String> {
    let mut map = HashMap::new();
    // `npm outdated` exits non-zero when anything is outdated; parse anyway.
    let Some(out) = run("npm", ["outdated", "-g", "--json"], NETWORK_READ_TIMEOUT).await else {
        return map;
    };
    let Ok(parsed) = serde_json::from_str::<HashMap<String, NpmOutdatedEntry>>(&out.stdout) else {
        return map;
    };
    for (name, entry) in parsed {
        if !entry.latest.is_empty() {
            map.insert(name, entry.latest);
        }
    }
    map
}

async fn npm_sizes() -> HashMap<String, u64> {
    let Some(root) = npm_root().await else {
        return HashMap::new();
    };
    du_children(&root).await
}

async fn npm_root() -> Option<PathBuf> {
    let out = run("npm", ["root", "-g"], READ_TIMEOUT).await?;
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

async fn du_children(root: &Path) -> HashMap<String, u64> {
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
