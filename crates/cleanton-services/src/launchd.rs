use plist::Value;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::reviewed_process;
use crate::safety;
use crate::types::{ServiceStatus, ServiceType};
use cleanton_common::{CleantonError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchdMutation {
    Bootstrap,
    Bootout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevationCommand {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug)]
pub struct ParsedPlist {
    pub label: String,
    pub program: Option<PathBuf>,
    pub program_arguments: Vec<String>,
    pub run_at_load: bool,
}

#[must_use]
pub fn get_current_uid() -> u32 {
    let output = reviewed_process::output("id", ["-u"]);
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Ok(uid) = stdout.trim().parse::<u32>() {
            return uid;
        }
    }
    501
}

pub fn parse_plist(path: &Path) -> Result<ParsedPlist> {
    let plist_val = plist::Value::from_file(path)
        .map_err(|err| CleantonError::io(path, std::io::Error::other(err.to_string())))?;

    let dict = plist_val.as_dictionary().ok_or_else(|| {
        CleantonError::io(
            path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Root of plist is not a dictionary",
            ),
        )
    })?;

    let label = dict
        .get("Label")
        .and_then(|v| v.as_string())
        .map(std::string::ToString::to_string)
        .or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .map(std::string::ToString::to_string)
        })
        .ok_or_else(|| {
            CleantonError::io(
                path,
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Missing 'Label' in plist"),
            )
        })?;

    let program = dict
        .get("Program")
        .and_then(|v| v.as_string())
        .map(PathBuf::from);

    let program_arguments = if let Some(args_val) = dict.get("ProgramArguments") {
        if let Some(arr) = args_val.as_array() {
            arr.iter()
                .filter_map(|v| v.as_string().map(std::string::ToString::to_string))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let run_at_load = dict
        .get("RunAtLoad")
        .and_then(plist::Value::as_boolean)
        .unwrap_or(false);

    Ok(ParsedPlist {
        label,
        program,
        program_arguments,
        run_at_load,
    })
}

#[must_use]
pub fn get_launchd_pids() -> HashMap<String, u32> {
    let mut pids = HashMap::new();
    let Ok(output) = reviewed_process::output("launchctl", ["list"]) else {
        return pids;
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let [pid_str, _, label, ..] = parts.as_slice()
            && *pid_str != "-"
            && let Ok(pid) = pid_str.parse::<u32>()
        {
            pids.insert((*label).to_string(), pid);
        }
    }
    pids
}

#[must_use]
pub fn get_launchd_status<S: BuildHasher>(
    label: &str,
    service_type: ServiceType,
    proc_stats: &HashMap<u32, (f32, u64), S>,
) -> ServiceStatus {
    let is_daemon = service_type == ServiceType::SystemLaunchDaemon;

    // Fast path: launchctl list
    let pids = get_launchd_pids();
    if let Some(&pid) = pids.get(label) {
        let (cpu, mem) = proc_stats
            .get(&pid)
            .map_or((None, None), |&(c, m)| (Some(c), Some(m)));
        return ServiceStatus::Running {
            pid,
            cpu_percent: cpu,
            memory_bytes: mem,
        };
    }

    // fallback / system daemons or other domains
    let uid = get_current_uid();
    let domain = if is_daemon {
        "system".to_string()
    } else {
        format!("gui/{uid}")
    };

    let print_target = format!("{domain}/{label}");
    let output = match reviewed_process::output("launchctl", ["print", print_target.as_str()]) {
        Ok(out) => out,
        Err(err) => return ServiceStatus::Error(err.to_string()),
    };

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut pid_opt = None;
        for line in stdout.lines() {
            let line_trimmed = line.trim();
            if line_trimmed.starts_with("pid =")
                && let Some(pid_str) = line_trimmed.split('=').nth(1)
                && let Ok(pid) = pid_str.trim().parse::<u32>()
            {
                pid_opt = Some(pid);
                break;
            }
        }

        if let Some(pid) = pid_opt {
            let (cpu, mem) = proc_stats
                .get(&pid)
                .map_or((None, None), |&(c, m)| (Some(c), Some(m)));
            ServiceStatus::Running {
                pid,
                cpu_percent: cpu,
                memory_bytes: mem,
            }
        } else {
            ServiceStatus::Loaded
        }
    } else {
        ServiceStatus::Stopped
    }
}

pub fn check_write_privileges(plist_path: &Path) -> Result<()> {
    safety::check_plist_write_safety(plist_path, plist_owner_uid(plist_path))
}

#[must_use]
pub fn elevated_run_at_load_command_preview(
    plist_path: &Path,
    run_at_load_val: bool,
) -> ElevationCommand {
    reviewed_process::elevated_plutil_command(&run_at_load_args(plist_path, run_at_load_val)).into()
}

pub fn set_run_at_load(plist_path: &Path, run_at_load_val: bool) -> Result<()> {
    check_write_privileges(plist_path)?;

    let plist_val = plist::Value::from_file(plist_path)
        .map_err(|err| CleantonError::io(plist_path, std::io::Error::other(err.to_string())))?;

    let mut dict = plist_val
        .as_dictionary()
        .ok_or_else(|| {
            CleantonError::io(
                plist_path,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Root of plist is not a dictionary",
                ),
            )
        })?
        .clone();

    dict.insert("RunAtLoad".to_string(), Value::Boolean(run_at_load_val));

    let updated_plist = Value::Dictionary(dict);
    plist::to_file_xml(plist_path, &updated_plist)
        .map_err(|err| CleantonError::io(plist_path, std::io::Error::other(err.to_string())))?;

    Ok(())
}

pub fn set_run_at_load_elevated(plist_path: &Path, run_at_load_val: bool) -> Result<()> {
    safety::check_elevated_plist_write_safety(plist_path, plist_owner_uid(plist_path))?;
    check_targeted_elevation_allowed(plist_path)?;

    let command =
        reviewed_process::elevated_plutil_command(&run_at_load_args(plist_path, run_at_load_val));
    let status = reviewed_process::reviewed_status(&command)
        .map_err(|e| CleantonError::io(plist_path, e))?;

    if status.success() {
        Ok(())
    } else {
        Err(CleantonError::Execution {
            path: plist_path.to_path_buf(),
            message: format!("elevated plutil RunAtLoad update exited with status {status}"),
        })
    }
}

pub fn bootstrap_service(plist_path: &Path, service_type: ServiceType) -> Result<()> {
    safety::check_launchd_mutation_safety(plist_path, service_type, plist_owner_uid(plist_path))?;

    let is_daemon = service_type == ServiceType::SystemLaunchDaemon;
    let uid = get_current_uid();
    let domain = if is_daemon {
        if uid != 0 {
            return Err(CleantonError::RootPrivilegesRequired(
                "Root privileges required to bootstrap a system-wide LaunchDaemon".to_string(),
            ));
        }
        "system".to_string()
    } else {
        format!("gui/{uid}")
    };

    let status = reviewed_process::status(
        "launchctl",
        [
            "bootstrap",
            domain.as_str(),
            plist_path.to_str().unwrap_or(""),
        ],
    )
    .map_err(|e| CleantonError::io(plist_path, e))?;

    if status.success() {
        Ok(())
    } else {
        Err(CleantonError::Execution {
            path: plist_path.to_path_buf(),
            message: format!("launchctl bootstrap exited with status {status}"),
        })
    }
}

#[must_use]
pub fn elevated_launchctl_command_preview(
    plist_path: &Path,
    service_type: ServiceType,
    mutation: LaunchdMutation,
) -> ElevationCommand {
    reviewed_process::elevated_launchctl_command(&launchctl_mutation_args(
        plist_path,
        service_type,
        mutation,
    ))
    .into()
}

pub fn bootstrap_service_elevated(plist_path: &Path, service_type: ServiceType) -> Result<()> {
    run_elevated_launchctl_mutation(plist_path, service_type, LaunchdMutation::Bootstrap)
}

pub fn bootout_service(plist_path: &Path, service_type: ServiceType) -> Result<()> {
    safety::check_launchd_mutation_safety(plist_path, service_type, plist_owner_uid(plist_path))?;

    let is_daemon = service_type == ServiceType::SystemLaunchDaemon;
    let uid = get_current_uid();
    let domain = if is_daemon {
        if uid != 0 {
            return Err(CleantonError::RootPrivilegesRequired(
                "Root privileges required to bootout a system-wide LaunchDaemon".to_string(),
            ));
        }
        "system".to_string()
    } else {
        format!("gui/{uid}")
    };

    let status = reviewed_process::status(
        "launchctl",
        [
            "bootout",
            domain.as_str(),
            plist_path.to_str().unwrap_or(""),
        ],
    )
    .map_err(|e| CleantonError::io(plist_path, e))?;

    if status.success() {
        Ok(())
    } else {
        Err(CleantonError::Execution {
            path: plist_path.to_path_buf(),
            message: format!("launchctl bootout exited with status {status}"),
        })
    }
}

pub fn bootout_service_elevated(plist_path: &Path, service_type: ServiceType) -> Result<()> {
    run_elevated_launchctl_mutation(plist_path, service_type, LaunchdMutation::Bootout)
}

fn plist_owner_uid(plist_path: &Path) -> Option<u32> {
    std::fs::metadata(plist_path)
        .ok()
        .map(|metadata| metadata.uid())
}

fn run_elevated_launchctl_mutation(
    plist_path: &Path,
    service_type: ServiceType,
    mutation: LaunchdMutation,
) -> Result<()> {
    safety::check_elevated_launchd_mutation_safety(
        plist_path,
        service_type,
        plist_owner_uid(plist_path),
    )?;
    check_targeted_elevation_allowed(plist_path)?;

    let command = reviewed_process::elevated_launchctl_command(&launchctl_mutation_args(
        plist_path,
        service_type,
        mutation,
    ));
    let status = reviewed_process::reviewed_status(&command)
        .map_err(|e| CleantonError::io(plist_path, e))?;

    if status.success() {
        Ok(())
    } else {
        Err(CleantonError::Execution {
            path: plist_path.to_path_buf(),
            message: format!(
                "elevated launchctl {} exited with status {status}",
                mutation.as_str()
            ),
        })
    }
}

fn launchctl_mutation_args(
    plist_path: &Path,
    service_type: ServiceType,
    mutation: LaunchdMutation,
) -> Vec<String> {
    vec![
        mutation.as_str().to_string(),
        launchd_domain(service_type),
        plist_path.to_string_lossy().into_owned(),
    ]
}

fn run_at_load_args(plist_path: &Path, run_at_load_val: bool) -> Vec<String> {
    vec![
        "-replace".to_string(),
        "RunAtLoad".to_string(),
        "-bool".to_string(),
        run_at_load_val.to_string(),
        plist_path.to_string_lossy().into_owned(),
    ]
}

fn launchd_domain(service_type: ServiceType) -> String {
    if service_type == ServiceType::SystemLaunchDaemon {
        "system".to_string()
    } else {
        format!("gui/{}", get_current_uid())
    }
}

fn check_targeted_elevation_allowed(path: &Path) -> Result<()> {
    if get_current_uid() == 0 {
        return Err(CleantonError::ExecutionRefused(format!(
            "Refusing to mutate service '{}' from a globally-root process. Cleanton requires targeted macOS administrator elevation instead of global sudo/root execution.",
            path.display()
        )));
    }

    Ok(())
}

impl LaunchdMutation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Bootout => "bootout",
        }
    }
}

impl From<reviewed_process::ReviewedCommand> for ElevationCommand {
    fn from(command: reviewed_process::ReviewedCommand) -> Self {
        Self {
            program: command.program,
            args: command.args,
        }
    }
}

#[must_use]
pub fn get_all_processes_stats() -> HashMap<u32, (f32, u64)> {
    let mut stats = HashMap::new();
    let Ok(output) = reviewed_process::output("ps", ["-ax", "-o", "pid,%cpu,%mem,rss"]) else {
        return stats;
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let [pid_field, cpu_field, _, rss_field, ..] = parts.as_slice() {
            let pid: u32 = match pid_field.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let cpu: f32 = cpu_field.parse().unwrap_or(0.0);
            let rss_kb: u64 = rss_field.parse().unwrap_or(0);
            let mem_bytes = rss_kb * 1024;
            stats.insert(pid, (cpu, mem_bytes));
        }
    }
    stats
}
