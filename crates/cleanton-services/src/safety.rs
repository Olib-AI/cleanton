use crate::types::ServiceType;
use cleanton_common::{CleantonError, Result};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedMutationReason {
    SystemLaunchDomain,
    RootOwnedPlist,
}

#[must_use]
pub fn is_protected(label: &str, plist_path: &Path) -> bool {
    label.starts_with("com.apple.")
        || plist_path.starts_with("/System/Library")
        || plist_path.starts_with("/Library/Apple")
}

pub fn check_mutation_safety(label: &str, plist_path: &Path) -> Result<()> {
    if is_protected(label, plist_path) {
        Err(CleantonError::ExecutionRefused(format!(
            "Mutation rejected: Service '{label}' is system-protected."
        )))
    } else {
        Ok(())
    }
}

#[must_use]
pub fn privileged_mutation_reason(
    service_type: ServiceType,
    plist_path: &Path,
    owner_uid: Option<u32>,
) -> Option<PrivilegedMutationReason> {
    if service_type == ServiceType::SystemLaunchDaemon
        || plist_path.starts_with("/Library/LaunchDaemons")
        || plist_path.starts_with("/System/Library/LaunchDaemons")
    {
        Some(PrivilegedMutationReason::SystemLaunchDomain)
    } else if owner_uid == Some(0) {
        Some(PrivilegedMutationReason::RootOwnedPlist)
    } else {
        None
    }
}

pub fn check_service_mutation_safety(
    label: &str,
    plist_path: &Path,
    service_type: ServiceType,
    owner_uid: Option<u32>,
) -> Result<()> {
    check_service_mutation_safety_with_elevation(label, plist_path, service_type, owner_uid, false)
}

pub fn check_service_mutation_safety_with_elevation(
    label: &str,
    plist_path: &Path,
    service_type: ServiceType,
    owner_uid: Option<u32>,
    elevation_requested: bool,
) -> Result<()> {
    check_mutation_safety(label, plist_path)?;

    if let Some(reason) = privileged_mutation_reason(service_type, plist_path, owner_uid)
        && !elevation_requested
    {
        Err(privileged_mutation_error(label, plist_path, reason))
    } else {
        Ok(())
    }
}

pub fn check_plist_write_safety(plist_path: &Path, owner_uid: Option<u32>) -> Result<()> {
    check_plist_write_safety_with_elevation(plist_path, owner_uid, false)
}

pub fn check_elevated_plist_write_safety(plist_path: &Path, owner_uid: Option<u32>) -> Result<()> {
    check_plist_write_safety_with_elevation(plist_path, owner_uid, true)
}

pub fn check_plist_write_safety_with_elevation(
    plist_path: &Path,
    owner_uid: Option<u32>,
    elevation_requested: bool,
) -> Result<()> {
    let label = plist_safety_label(plist_path);
    check_mutation_safety(&label, plist_path)?;

    if let Some(reason) =
        privileged_mutation_reason(ServiceType::UserLaunchAgent, plist_path, owner_uid)
        && !elevation_requested
    {
        Err(privileged_mutation_error(&label, plist_path, reason))
    } else {
        Ok(())
    }
}

pub fn check_launchd_mutation_safety(
    plist_path: &Path,
    service_type: ServiceType,
    owner_uid: Option<u32>,
) -> Result<()> {
    check_launchd_mutation_safety_with_elevation(plist_path, service_type, owner_uid, false)
}

pub fn check_elevated_launchd_mutation_safety(
    plist_path: &Path,
    service_type: ServiceType,
    owner_uid: Option<u32>,
) -> Result<()> {
    check_launchd_mutation_safety_with_elevation(plist_path, service_type, owner_uid, true)
}

pub fn check_launchd_mutation_safety_with_elevation(
    plist_path: &Path,
    service_type: ServiceType,
    owner_uid: Option<u32>,
    elevation_requested: bool,
) -> Result<()> {
    let label = plist_safety_label(plist_path);
    check_service_mutation_safety_with_elevation(
        &label,
        plist_path,
        service_type,
        owner_uid,
        elevation_requested,
    )
}

fn privileged_mutation_error(
    label: &str,
    plist_path: &Path,
    reason: PrivilegedMutationReason,
) -> CleantonError {
    let reason_message = match reason {
        PrivilegedMutationReason::SystemLaunchDomain => "system launchd domain",
        PrivilegedMutationReason::RootOwnedPlist => "root-owned service plist",
    };

    CleantonError::RootPrivilegesRequired(format!(
        "Service '{label}' requires targeted administrator elevation to mutate {reason_message} at {}. Cleanton does not elevate implicitly and does not use global sudo/root execution.",
        plist_path.display()
    ))
}

fn plist_safety_label(plist_path: &Path) -> String {
    plist_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("service plist")
        .to_string()
}
