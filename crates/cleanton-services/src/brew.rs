use cleanton_common::{CleantonError, Result};
use serde::Deserialize;
use std::path::PathBuf;

use crate::reviewed_process;

#[derive(Debug, Clone, Deserialize)]
pub struct BrewServiceInfo {
    pub name: String,
    pub status: String,
    pub user: Option<String>,
    pub file: Option<PathBuf>,
    pub exit_code: Option<i32>,
}

pub fn list_brew_services() -> Result<Vec<BrewServiceInfo>> {
    let Ok(output) = reviewed_process::output("brew", ["services", "list", "--json"]) else {
        // brew is probably not installed, return empty list
        return Ok(Vec::new());
    };

    if !output.status.success() {
        // If brew exists but subcommand fails, return empty list
        return Ok(Vec::new());
    }

    let services: Vec<BrewServiceInfo> = serde_json::from_slice(&output.stdout).map_err(|err| {
        CleantonError::Config(format!("Failed to parse brew services JSON: {err}"))
    })?;

    Ok(services)
}

pub fn run_brew_command(name: &str, cmd: &str, run_as_root: bool) -> Result<()> {
    if run_as_root {
        return Err(CleantonError::RootPrivilegesRequired(format!(
            "Root privileges required to run 'brew services {cmd} {name}'. Cleanton does not elevate implicitly and does not use global sudo/root execution."
        )));
    }

    let status = reviewed_process::status("brew", ["services", cmd, name])
        .map_err(|e| CleantonError::io("brew", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(CleantonError::Execution {
            path: PathBuf::from(name),
            message: format!("brew services {cmd} failed with status {status}"),
        })
    }
}
