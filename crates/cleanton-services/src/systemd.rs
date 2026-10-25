use std::collections::HashMap;
use std::hash::BuildHasher;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use cleanton_common::{CleantonError, Result};

use crate::reviewed_process;
use crate::types::{Service, ServiceStatus, ServiceType};

#[derive(Debug, Default)]
struct ParsedUnit {
    description: Option<String>,
    program: Option<PathBuf>,
    program_arguments: Vec<String>,
    wanted_by: Vec<String>,
}

/// Discover user-owned systemd `.service` units under `~/.config/systemd/user`
/// and resolve their live state in a single `systemctl --user show` batch call.
#[must_use]
pub fn list_user_services<S: BuildHasher>(
    proc_stats: &HashMap<u32, (f32, u64), S>,
) -> Vec<Service> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let user_dir = home.join(".config/systemd/user");
    list_user_services_in_dir(&user_dir, proc_stats)
}

#[must_use]
pub fn list_user_services_in_dir<S: BuildHasher>(
    user_dir: &Path,
    proc_stats: &HashMap<u32, (f32, u64), S>,
) -> Vec<Service> {
    let Ok(entries) = std::fs::read_dir(user_dir) else {
        return Vec::new();
    };

    let mut units: Vec<(String, PathBuf, ParsedUnit, Option<u32>, bool)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("service") || !path.is_file() {
            continue;
        }
        let Some(unit_id) = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_owned)
        else {
            continue;
        };
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let parsed = parse_unit_file(&contents);
        let owner_uid = std::fs::metadata(&path).ok().map(|m| m.uid());
        let enabled = is_unit_enabled_on_disk(user_dir, &unit_id, &parsed.wanted_by);
        units.push((unit_id, path, parsed, owner_uid, enabled));
    }

    if units.is_empty() {
        return Vec::new();
    }

    let unit_ids: Vec<&str> = units.iter().map(|(id, ..)| id.as_str()).collect();
    let live_states = query_systemctl_states(&unit_ids);

    units
        .into_iter()
        .map(|(unit_id, path, parsed, user_id, enabled)| {
            let status = live_states.get(&unit_id).map_or(ServiceStatus::Stopped, |st| {
                match (st.active_state.as_str(), st.main_pid) {
                    ("active" | "activating" | "reloading", Some(pid)) if pid > 0 => {
                        let (cpu, mem) = proc_stats
                            .get(&pid)
                            .map_or((None, None), |&(c, m)| (Some(c), Some(m)));
                        ServiceStatus::Running {
                            pid,
                            cpu_percent: cpu,
                            memory_bytes: mem,
                        }
                    }
                    ("active", None) => ServiceStatus::Loaded,
                    ("failed", _) => ServiceStatus::Error("failed".to_owned()),
                    _ => ServiceStatus::Stopped,
                }
            });
            let short_name = parsed.description.unwrap_or_else(|| {
                unit_id
                    .strip_suffix(".service")
                    .unwrap_or(&unit_id)
                    .to_owned()
            });
            Service {
                id: unit_id.clone(),
                name: short_name,
                service_type: ServiceType::SystemdUserService,
                status,
                plist_path: path,
                program: parsed.program,
                program_arguments: parsed.program_arguments,
                run_at_load: enabled,
                label: unit_id,
                user_id,
            }
        })
        .collect()
}

pub fn run_systemctl_user_action(unit_id: &str, verb: &str, unit_path: &Path) -> Result<()> {
    let output = reviewed_process::output("systemctl", ["--user", verb, unit_id])
        .map_err(|err| CleantonError::io(unit_path, err))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err(CleantonError::Execution {
            path: unit_path.to_path_buf(),
            message: if stderr.is_empty() {
                format!("systemctl --user {verb} {unit_id} exited with {}", output.status)
            } else {
                format!("systemctl --user {verb} {unit_id} failed: {stderr}")
            },
        })
    }
}

#[derive(Debug, Default)]
struct UnitLiveState {
    active_state: String,
    main_pid: Option<u32>,
}

fn query_systemctl_states(unit_ids: &[&str]) -> HashMap<String, UnitLiveState> {
    let mut states = HashMap::new();
    if unit_ids.is_empty() {
        return states;
    }
    let mut args = vec![
        "--user",
        "show",
        "--property=Id,ActiveState,MainPID",
        "--",
    ];
    args.extend_from_slice(unit_ids);
    let Ok(output) = reviewed_process::output("systemctl", args) else {
        return states;
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_systemctl_show_output(&stdout, &mut states);
    states
}

fn parse_systemctl_show_output(stdout: &str, out: &mut HashMap<String, UnitLiveState>) {
    let mut current_id = String::new();
    let mut current = UnitLiveState::default();
    for line in stdout.lines().chain(std::iter::once("")) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !current_id.is_empty() {
                out.insert(
                    std::mem::take(&mut current_id),
                    std::mem::take(&mut current),
                );
            }
            continue;
        }
        if let Some(val) = trimmed.strip_prefix("Id=") {
            current_id = val.to_owned();
        } else if let Some(val) = trimmed.strip_prefix("ActiveState=") {
            current.active_state = val.to_owned();
        } else if let Some(val) = trimmed.strip_prefix("MainPID=")
            && let Ok(pid) = val.parse::<u32>()
            && pid > 0
        {
            current.main_pid = Some(pid);
        }
    }
}

fn is_unit_enabled_on_disk(user_dir: &Path, unit_id: &str, wanted_by: &[String]) -> bool {
    for target in wanted_by
        .iter()
        .map(String::as_str)
        .chain(["default.target", "graphical-session.target"])
    {
        if user_dir
            .join(format!("{target}.wants"))
            .join(unit_id)
            .symlink_metadata()
            .is_ok()
        {
            return true;
        }
    }
    false
}

fn parse_unit_file(contents: &str) -> ParsedUnit {
    let mut parsed = ParsedUnit::default();
    let mut section = "";
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line;
            continue;
        }
        let Some((key, raw_val)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let val = raw_val.trim();
        match (section, key) {
            ("[Unit]", "Description") if !val.is_empty() => {
                parsed.description = Some(val.to_owned());
            }
            ("[Service]", "ExecStart") if parsed.program.is_none() && !val.is_empty() => {
                let cleaned = val.trim_start_matches(['-', '@', '+', '!', ':']);
                let args: Vec<String> = cleaned
                    .split_whitespace()
                    .map(|part| part.trim_matches(['"', '\'']).to_owned())
                    .filter(|part| !part.is_empty())
                    .collect();
                if let Some(first) = args.first() {
                    parsed.program = Some(PathBuf::from(first));
                }
                parsed.program_arguments = args;
            }
            ("[Install]", "WantedBy") if !val.is_empty() => {
                parsed
                    .wanted_by
                    .extend(val.split_whitespace().map(str::to_owned));
            }
            _ => {}
        }
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_systemd_unit_and_wants_enablement() {
        let temp = tempfile::tempdir().expect("tempdir");
        let wants = temp.path().join("default.target.wants");
        std::fs::create_dir_all(&wants).expect("wants dir");
        let unit_path = temp.path().join("redis-local.service");
        std::fs::write(
            &unit_path,
            "[Unit]\nDescription=Local Redis Cache\n[Service]\nExecStart=/usr/bin/redis-server --port 6379\n[Install]\nWantedBy=default.target\n",
        )
        .expect("write unit");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&unit_path, wants.join("redis-local.service"))
            .expect("symlink wants");

        let services = list_user_services_in_dir(temp.path(), &HashMap::new());
        assert_eq!(services.len(), 1);
        let svc = services.first().expect("service");
        assert_eq!(svc.id, "redis-local.service");
        assert_eq!(svc.name, "Local Redis Cache");
        assert_eq!(svc.service_type, ServiceType::SystemdUserService);
        assert_eq!(svc.program, Some(PathBuf::from("/usr/bin/redis-server")));
        assert!(svc.run_at_load);
    }

    #[test]
    fn parses_systemctl_show_blocks() {
        let sample = "Id=foo.service\nActiveState=active\nMainPID=4242\n\nId=bar.service\nActiveState=inactive\nMainPID=0\n";
        let mut out = HashMap::new();
        parse_systemctl_show_output(sample, &mut out);
        assert_eq!(out.get("foo.service").and_then(|s| s.main_pid), Some(4242));
        assert_eq!(
            out.get("bar.service").map(|s| s.active_state.as_str()),
            Some("inactive")
        );
    }
}
