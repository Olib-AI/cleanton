use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{Service, ServiceStatus, ServiceType};
use crate::{brew, launchd, reviewed_plist_delete, safety};
use cleanton_common::{CleantonConfig, CleantonError};

#[derive(Debug)]
pub struct ServiceManager {
    #[allow(dead_code)]
    config: CleantonConfig,
    #[allow(dead_code)]
    safety_blocklist: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServiceElevation {
    #[default]
    None,
    TargetedAdministrator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServiceMutationOptions {
    pub elevation: ServiceElevation,
}

impl ServiceMutationOptions {
    #[must_use]
    pub const fn without_elevation() -> Self {
        Self {
            elevation: ServiceElevation::None,
        }
    }

    #[must_use]
    pub const fn elevated() -> Self {
        Self {
            elevation: ServiceElevation::TargetedAdministrator,
        }
    }

    const fn requests_elevation(self) -> bool {
        matches!(self.elevation, ServiceElevation::TargetedAdministrator)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceAction {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
}

impl ServiceManager {
    #[must_use]
    pub fn new(config: CleantonConfig) -> Self {
        Self {
            config,
            safety_blocklist: Vec::new(),
        }
    }

    /// List all background services (launchd and brew services)
    #[allow(clippy::too_many_lines, clippy::unused_async)]
    pub async fn list_services(&self) -> Result<Vec<Service>, CleantonError> {
        let mut services = Vec::new();
        let proc_stats = launchd::get_all_processes_stats();

        // 1. Get Brew services first
        let brew_list = brew::list_brew_services().unwrap_or_default();
        let mut brew_plist_paths = std::collections::HashSet::new();
        for bs in &brew_list {
            if let Some(ref path) = bs.file {
                if let Ok(canon) = path.canonicalize() {
                    brew_plist_paths.insert(canon);
                } else {
                    brew_plist_paths.insert(path.clone());
                }
            }
        }

        // 2. Scan all standard launchd locations
        let roots = service_roots();
        for (st_type, root_dir) in roots {
            let Ok(entries) = std::fs::read_dir(&root_dir) else {
                continue;
            };

            for entry in entries {
                let Ok(entry) = entry else {
                    continue;
                };

                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("plist") {
                    continue;
                }

                // Parse plist
                let Ok(parsed) = launchd::parse_plist(&path) else {
                    continue;
                };

                // Check if it's managed by Brew
                let is_brew = brew_plist_paths.contains(&path)
                    || path
                        .canonicalize()
                        .is_ok_and(|p| brew_plist_paths.contains(&p))
                    || parsed.label.starts_with("homebrew.mxcl.");

                let final_type = if is_brew {
                    ServiceType::BrewService
                } else {
                    st_type
                };

                let user_id = std::fs::metadata(&path).ok().map(|m| m.uid());

                // Determine name
                let name = if is_brew {
                    // Try to find the brew name
                    brew_list
                        .iter()
                        .find(|bs| {
                            bs.file
                                .as_ref()
                                .is_some_and(|f| f.file_name() == path.file_name())
                                || parsed.label.ends_with(&bs.name)
                        })
                        .map_or_else(
                            || {
                                parsed
                                    .label
                                    .strip_prefix("homebrew.mxcl.")
                                    .unwrap_or(&parsed.label)
                                    .to_string()
                            },
                            |bs| bs.name.clone(),
                        )
                } else {
                    parsed.label.clone()
                };

                // Get status
                let status = launchd::get_launchd_status(&parsed.label, final_type, &proc_stats);

                services.push(Service {
                    id: parsed.label.clone(),
                    name,
                    service_type: final_type,
                    status,
                    plist_path: path,
                    program: parsed.program,
                    program_arguments: parsed.program_arguments,
                    run_at_load: parsed.run_at_load,
                    label: parsed.label,
                    user_id,
                });
            }
        }

        // Add any BrewService from brew services list that wasn't found in directories
        for bs in brew_list {
            if services
                .iter()
                .any(|s| s.name == bs.name || s.id == format!("homebrew.mxcl.{}", bs.name))
            {
                continue;
            }

            let plist_path = bs.file.clone().unwrap_or_default();
            let (label, program, program_arguments, run_at_load) =
                if !plist_path.as_os_str().is_empty() && plist_path.exists() {
                    if let Ok(parsed) = launchd::parse_plist(&plist_path) {
                        (
                            parsed.label,
                            parsed.program,
                            parsed.program_arguments,
                            parsed.run_at_load,
                        )
                    } else {
                        (
                            format!("homebrew.mxcl.{}", bs.name),
                            None,
                            Vec::new(),
                            false,
                        )
                    }
                } else {
                    (
                        format!("homebrew.mxcl.{}", bs.name),
                        None,
                        Vec::new(),
                        false,
                    )
                };

            let user_id = if !plist_path.as_os_str().is_empty() && plist_path.exists() {
                std::fs::metadata(&plist_path).ok().map(|m| m.uid())
            } else {
                None
            };

            let status = launchd::get_launchd_status(&label, ServiceType::BrewService, &proc_stats);

            services.push(Service {
                id: label.clone(),
                name: bs.name,
                service_type: ServiceType::BrewService,
                status,
                plist_path,
                program,
                program_arguments,
                run_at_load,
                label,
                user_id,
            });
        }

        services.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(services)
    }

    /// Check status of a specific service
    pub async fn get_status(&self, service_id: &str) -> Result<ServiceStatus, CleantonError> {
        let services = self.list_services().await?;
        if let Some(service) = services.iter().find(|s| s.id == service_id) {
            Ok(service.status.clone())
        } else {
            Err(service_not_found(service_id))
        }
    }

    /// Start a service
    pub async fn start_service(&self, service_id: &str) -> Result<(), CleantonError> {
        self.start_service_with_options(service_id, ServiceMutationOptions::default())
            .await
    }

    pub async fn start_service_elevated(&self, service_id: &str) -> Result<(), CleantonError> {
        self.start_service_with_options(service_id, ServiceMutationOptions::elevated())
            .await
    }

    pub async fn start_service_with_options(
        &self,
        service_id: &str,
        options: ServiceMutationOptions,
    ) -> Result<(), CleantonError> {
        self.mutate_service(service_id, ServiceAction::Start, options)
            .await
    }

    /// Stop a service
    pub async fn stop_service(&self, service_id: &str) -> Result<(), CleantonError> {
        self.stop_service_with_options(service_id, ServiceMutationOptions::default())
            .await
    }

    pub async fn stop_service_elevated(&self, service_id: &str) -> Result<(), CleantonError> {
        self.stop_service_with_options(service_id, ServiceMutationOptions::elevated())
            .await
    }

    pub async fn stop_service_with_options(
        &self,
        service_id: &str,
        options: ServiceMutationOptions,
    ) -> Result<(), CleantonError> {
        self.mutate_service(service_id, ServiceAction::Stop, options)
            .await
    }

    /// Restart a service
    pub async fn restart_service(&self, service_id: &str) -> Result<(), CleantonError> {
        self.restart_service_with_options(service_id, ServiceMutationOptions::default())
            .await
    }

    pub async fn restart_service_elevated(&self, service_id: &str) -> Result<(), CleantonError> {
        self.restart_service_with_options(service_id, ServiceMutationOptions::elevated())
            .await
    }

    pub async fn restart_service_with_options(
        &self,
        service_id: &str,
        options: ServiceMutationOptions,
    ) -> Result<(), CleantonError> {
        self.mutate_service(service_id, ServiceAction::Restart, options)
            .await
    }

    /// Enable a service (set `run_at_load` = true or bootstrap)
    pub async fn enable_service(&self, service_id: &str) -> Result<(), CleantonError> {
        self.enable_service_with_options(service_id, ServiceMutationOptions::default())
            .await
    }

    pub async fn enable_service_elevated(&self, service_id: &str) -> Result<(), CleantonError> {
        self.enable_service_with_options(service_id, ServiceMutationOptions::elevated())
            .await
    }

    pub async fn enable_service_with_options(
        &self,
        service_id: &str,
        options: ServiceMutationOptions,
    ) -> Result<(), CleantonError> {
        self.mutate_service(service_id, ServiceAction::Enable, options)
            .await
    }

    /// Disable a service (set `run_at_load` = false or bootout)
    pub async fn disable_service(&self, service_id: &str) -> Result<(), CleantonError> {
        self.disable_service_with_options(service_id, ServiceMutationOptions::default())
            .await
    }

    pub async fn disable_service_elevated(&self, service_id: &str) -> Result<(), CleantonError> {
        self.disable_service_with_options(service_id, ServiceMutationOptions::elevated())
            .await
    }

    pub async fn disable_service_with_options(
        &self,
        service_id: &str,
        options: ServiceMutationOptions,
    ) -> Result<(), CleantonError> {
        self.mutate_service(service_id, ServiceAction::Disable, options)
            .await
    }

    async fn mutate_service(
        &self,
        service_id: &str,
        action: ServiceAction,
        options: ServiceMutationOptions,
    ) -> Result<(), CleantonError> {
        let services = self.list_services().await?;
        let service = services
            .iter()
            .find(|s| s.id == service_id)
            .ok_or_else(|| service_not_found(service_id))?;

        safety::check_service_mutation_safety_with_elevation(
            &service.id,
            &service.plist_path,
            service.service_type,
            service.user_id,
            options.requests_elevation(),
        )?;

        let requires_elevation = should_run_as_root(service);
        let use_elevation = requires_elevation && options.requests_elevation();

        if service.service_type == ServiceType::BrewService {
            if use_elevation {
                return Err(CleantonError::ExecutionRefused(format!(
                    "Elevated Homebrew service mutation for '{}' is not supported. User Homebrew services continue to run without elevation.",
                    service.name
                )));
            }

            brew::run_brew_command(&service.name, action.brew_command(), false)?;
            return Ok(());
        }

        if use_elevation {
            run_launchd_action_elevated(service, action)
        } else {
            run_launchd_action(service, action)
        }
    }

    /// Delete orphaned launch agent plist file (if executable is missing)
    pub async fn delete_orphaned_plist(&self, service_id: &str) -> Result<(), CleantonError> {
        self.delete_orphaned_plist_with_options(service_id, ServiceMutationOptions::default())
            .await
    }

    pub async fn delete_orphaned_plist_elevated(
        &self,
        service_id: &str,
    ) -> Result<(), CleantonError> {
        self.delete_orphaned_plist_with_options(service_id, ServiceMutationOptions::elevated())
            .await
    }

    pub async fn delete_orphaned_plist_with_options(
        &self,
        service_id: &str,
        options: ServiceMutationOptions,
    ) -> Result<(), CleantonError> {
        let services = self.list_services().await?;
        let service = services
            .iter()
            .find(|s| s.id == service_id)
            .ok_or_else(|| service_not_found(service_id))?;

        safety::check_service_mutation_safety_with_elevation(
            &service.id,
            &service.plist_path,
            service.service_type,
            service.user_id,
            options.requests_elevation(),
        )?;

        let mut is_orphaned = true;
        if let Some(ref prog) = service.program {
            if prog.exists() {
                is_orphaned = false;
            }
        } else if let Some(first_arg) = service.program_arguments.first() {
            let prog_path = PathBuf::from(first_arg);
            if prog_path.exists() {
                is_orphaned = false;
            }
        }

        if !is_orphaned {
            return Err(CleantonError::ExecutionRefused(format!(
                "Service '{service_id}' is not orphaned: its executable exists."
            )));
        }

        let requires_elevation = should_run_as_root(service);
        let use_elevation = requires_elevation && options.requests_elevation();

        if !use_elevation {
            launchd::check_write_privileges(&service.plist_path)?;
        }

        backup_service_plist(&service.plist_path)?;

        if use_elevation {
            let _ = launchd::bootout_service_elevated(&service.plist_path, service.service_type);
            reviewed_plist_delete::remove_service_plist_elevated(&service.plist_path)
                .map_err(|e| CleantonError::io(&service.plist_path, e))?;
        } else {
            let _ = launchd::bootout_service(&service.plist_path, service.service_type);

            reviewed_plist_delete::remove_service_plist(&service.plist_path)
                .map_err(|e| CleantonError::io(&service.plist_path, e))?;
        }

        Ok(())
    }
}

impl ServiceAction {
    const fn brew_command(self) -> &'static str {
        match self {
            Self::Start | Self::Enable => "start",
            Self::Stop | Self::Disable => "stop",
            Self::Restart => "restart",
        }
    }
}

fn run_launchd_action(service: &Service, action: ServiceAction) -> Result<(), CleantonError> {
    match action {
        ServiceAction::Start => {
            launchd::bootstrap_service(&service.plist_path, service.service_type)?;
        }
        ServiceAction::Stop => {
            launchd::bootout_service(&service.plist_path, service.service_type)?;
        }
        ServiceAction::Restart => {
            let _ = launchd::bootout_service(&service.plist_path, service.service_type);
            launchd::bootstrap_service(&service.plist_path, service.service_type)?;
        }
        ServiceAction::Enable => {
            launchd::set_run_at_load(&service.plist_path, true)?;
            launchd::bootstrap_service(&service.plist_path, service.service_type)?;
        }
        ServiceAction::Disable => {
            launchd::set_run_at_load(&service.plist_path, false)?;
            launchd::bootout_service(&service.plist_path, service.service_type)?;
        }
    }

    Ok(())
}

fn run_launchd_action_elevated(
    service: &Service,
    action: ServiceAction,
) -> Result<(), CleantonError> {
    match action {
        ServiceAction::Start => {
            launchd::bootstrap_service_elevated(&service.plist_path, service.service_type)?;
        }
        ServiceAction::Stop => {
            launchd::bootout_service_elevated(&service.plist_path, service.service_type)?;
        }
        ServiceAction::Restart => {
            let _ = launchd::bootout_service_elevated(&service.plist_path, service.service_type);
            launchd::bootstrap_service_elevated(&service.plist_path, service.service_type)?;
        }
        ServiceAction::Enable => {
            launchd::set_run_at_load_elevated(&service.plist_path, true)?;
            launchd::bootstrap_service_elevated(&service.plist_path, service.service_type)?;
        }
        ServiceAction::Disable => {
            launchd::set_run_at_load_elevated(&service.plist_path, false)?;
            launchd::bootout_service_elevated(&service.plist_path, service.service_type)?;
        }
    }

    Ok(())
}

fn service_not_found(service_id: &str) -> CleantonError {
    CleantonError::Execution {
        path: PathBuf::from(service_id),
        message: format!("Service '{service_id}' not found."),
    }
}

fn should_run_as_root(service: &Service) -> bool {
    safety::privileged_mutation_reason(service.service_type, &service.plist_path, service.user_id)
        .is_some()
}

fn backup_service_plist(plist_path: &Path) -> Result<PathBuf, CleantonError> {
    let backup_dir = CleantonConfig::config_dir()
        .ok_or_else(|| {
            CleantonError::Config(
                "Cannot delete service plist because Cleanton config directory is unavailable"
                    .to_string(),
            )
        })?
        .join("backups")
        .join("services");

    std::fs::create_dir_all(&backup_dir).map_err(|err| CleantonError::io(&backup_dir, err))?;

    let source_name = plist_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("service.plist");
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    for attempt in 0..1_000_u16 {
        let backup_name = if attempt == 0 {
            format!("{timestamp_ms}-{source_name}")
        } else {
            format!("{timestamp_ms}-{attempt}-{source_name}")
        };
        let backup_path = backup_dir.join(backup_name);
        if backup_path.exists() {
            continue;
        }

        std::fs::copy(plist_path, &backup_path)
            .map_err(|err| CleantonError::io(plist_path, err))?;
        return Ok(backup_path);
    }

    Err(CleantonError::ExecutionRefused(format!(
        "Could not create a unique backup for service plist '{}'.",
        plist_path.display()
    )))
}

fn service_roots() -> Vec<(ServiceType, PathBuf)> {
    let mut roots = vec![
        (
            ServiceType::SystemLaunchAgent,
            PathBuf::from("/System/Library/LaunchAgents"),
        ),
        (
            ServiceType::SystemLaunchDaemon,
            PathBuf::from("/System/Library/LaunchDaemons"),
        ),
        (
            ServiceType::SystemLaunchAgent,
            PathBuf::from("/Library/LaunchAgents"),
        ),
        (
            ServiceType::SystemLaunchDaemon,
            PathBuf::from("/Library/LaunchDaemons"),
        ),
    ];

    if let Some(home) = std::env::var_os("HOME") {
        roots.push((
            ServiceType::UserLaunchAgent,
            PathBuf::from(home).join("Library/LaunchAgents"),
        ));
    }

    roots
}
