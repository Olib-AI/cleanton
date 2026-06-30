// Integration-test crate: fixed-shape fixtures make direct indexing into expected
// results clearer; `indexing_slicing` has no per-test clippy.toml exemption.
#![allow(clippy::indexing_slicing)]

use cleanton_common::{CleantonConfig, CleantonError};
use cleanton_services::launchd::{
    LaunchdMutation, bootstrap_service, elevated_launchctl_command_preview,
    elevated_run_at_load_command_preview, get_launchd_pids, parse_plist,
};
use cleanton_services::safety::{
    PrivilegedMutationReason, check_elevated_launchd_mutation_safety, check_mutation_safety,
    check_service_mutation_safety, check_service_mutation_safety_with_elevation, is_protected,
    privileged_mutation_reason,
};
use cleanton_services::{ServiceElevation, ServiceManager, ServiceMutationOptions, ServiceType};
use std::fs;
use std::path::PathBuf;

#[test]
fn test_is_protected() {
    assert!(is_protected(
        "com.apple.syslogd",
        &PathBuf::from("/System/Library/LaunchDaemons/com.apple.syslogd.plist")
    ));
    assert!(is_protected(
        "com.apple.anything",
        &PathBuf::from("/Library/LaunchDaemons/com.apple.anything.plist")
    ));
    assert!(is_protected(
        "something",
        &PathBuf::from("/System/Library/LaunchAgents/something.plist")
    ));
    assert!(!is_protected(
        "com.google.chrome",
        &PathBuf::from("/Library/LaunchAgents/com.google.chrome.plist")
    ));
    assert!(!is_protected(
        "my.service",
        &PathBuf::from("/Users/user/Library/LaunchAgents/my.service.plist")
    ));
}

#[test]
fn test_check_mutation_safety() {
    let res = check_mutation_safety(
        "com.apple.syslogd",
        &PathBuf::from("/System/Library/LaunchDaemons/com.apple.syslogd.plist"),
    );
    assert!(matches!(res, Err(CleantonError::ExecutionRefused(_))));

    let res = check_mutation_safety(
        "my.service",
        &PathBuf::from("/Users/user/Library/LaunchAgents/my.service.plist"),
    );
    assert!(res.is_ok());
}

#[test]
fn test_privileged_mutation_reason() {
    assert_eq!(
        privileged_mutation_reason(
            ServiceType::SystemLaunchDaemon,
            &PathBuf::from("/tmp/com.example.daemon.plist"),
            Some(501),
        ),
        Some(PrivilegedMutationReason::SystemLaunchDomain)
    );
    assert_eq!(
        privileged_mutation_reason(
            ServiceType::UserLaunchAgent,
            &PathBuf::from("/Library/LaunchDaemons/com.example.daemon.plist"),
            Some(501),
        ),
        Some(PrivilegedMutationReason::SystemLaunchDomain)
    );
    assert_eq!(
        privileged_mutation_reason(
            ServiceType::UserLaunchAgent,
            &PathBuf::from("/Users/user/Library/LaunchAgents/root-owned.plist"),
            Some(0),
        ),
        Some(PrivilegedMutationReason::RootOwnedPlist)
    );
    assert_eq!(
        privileged_mutation_reason(
            ServiceType::BrewService,
            &PathBuf::from("/Users/user/Library/LaunchAgents/homebrew.mxcl.redis.plist"),
            Some(501),
        ),
        None
    );
}

#[test]
fn test_check_service_mutation_safety_refuses_privileged_services() {
    let system_domain = check_service_mutation_safety(
        "com.example.daemon",
        &PathBuf::from("/Library/LaunchDaemons/com.example.daemon.plist"),
        ServiceType::SystemLaunchDaemon,
        Some(501),
    );
    assert!(matches!(
        system_domain,
        Err(CleantonError::RootPrivilegesRequired(_) | CleantonError::ExecutionRefused(_))
    ));

    let root_owned = check_service_mutation_safety(
        "com.example.agent",
        &PathBuf::from("/Users/user/Library/LaunchAgents/com.example.agent.plist"),
        ServiceType::UserLaunchAgent,
        Some(0),
    );
    assert!(matches!(
        root_owned,
        Err(CleantonError::RootPrivilegesRequired(_) | CleantonError::ExecutionRefused(_))
    ));

    let user_brew = check_service_mutation_safety(
        "homebrew.mxcl.redis",
        &PathBuf::from("/Users/user/Library/LaunchAgents/homebrew.mxcl.redis.plist"),
        ServiceType::BrewService,
        Some(501),
    );
    assert!(user_brew.is_ok());
}

#[test]
fn test_elevated_policy_requires_explicit_elevation_and_keeps_protected_immutable() {
    let system_domain_path = PathBuf::from("/Library/LaunchDaemons/com.example.daemon.plist");

    let without_elevation = check_service_mutation_safety_with_elevation(
        "com.example.daemon",
        &system_domain_path,
        ServiceType::SystemLaunchDaemon,
        Some(501),
        false,
    );
    assert!(matches!(
        without_elevation,
        Err(CleantonError::RootPrivilegesRequired(_))
    ));

    let with_elevation = check_service_mutation_safety_with_elevation(
        "com.example.daemon",
        &system_domain_path,
        ServiceType::SystemLaunchDaemon,
        Some(501),
        true,
    );
    assert!(with_elevation.is_ok());

    let protected_by_label = check_service_mutation_safety_with_elevation(
        "com.apple.anything",
        &PathBuf::from("/Library/LaunchDaemons/com.apple.anything.plist"),
        ServiceType::SystemLaunchDaemon,
        Some(501),
        true,
    );
    assert!(matches!(
        protected_by_label,
        Err(CleantonError::ExecutionRefused(_))
    ));

    let protected_by_system_path = check_service_mutation_safety_with_elevation(
        "org.example.system",
        &PathBuf::from("/System/Library/LaunchDaemons/org.example.system.plist"),
        ServiceType::SystemLaunchDaemon,
        Some(501),
        true,
    );
    assert!(matches!(
        protected_by_system_path,
        Err(CleantonError::ExecutionRefused(_))
    ));

    let protected_low_level_launchd = check_elevated_launchd_mutation_safety(
        &PathBuf::from("/Library/LaunchDaemons/com.apple.low-level.plist"),
        ServiceType::SystemLaunchDaemon,
        Some(501),
    );
    assert!(matches!(
        protected_low_level_launchd,
        Err(CleantonError::ExecutionRefused(_))
    ));
}

#[test]
fn test_service_mutation_options_make_elevation_explicit() {
    assert_eq!(
        ServiceMutationOptions::default().elevation,
        ServiceElevation::None
    );
    assert_eq!(
        ServiceMutationOptions::without_elevation().elevation,
        ServiceElevation::None
    );
    assert_eq!(
        ServiceMutationOptions::elevated().elevation,
        ServiceElevation::TargetedAdministrator
    );
}

#[test]
fn test_elevated_launchctl_command_construction_is_targeted_and_quoted() {
    let command = elevated_launchctl_command_preview(
        &PathBuf::from("/Library/LaunchDaemons/com.example O'Hara.plist"),
        ServiceType::SystemLaunchDaemon,
        LaunchdMutation::Bootstrap,
    );

    assert_eq!(command.program, "osascript");
    assert_eq!(command.args.len(), 2);
    assert_eq!(command.args[0], "-e");

    let script = &command.args[1];
    assert!(script.contains("with administrator privileges"));
    assert!(script.contains("'/bin/launchctl'"));
    assert!(script.contains("'bootstrap'"));
    assert!(script.contains("'system'"));
    assert!(script.contains("O'\\\\''Hara.plist"));
    assert!(!script.contains("sudo"));
}

#[test]
fn test_elevated_run_at_load_command_uses_plutil_without_sudo() {
    let command = elevated_run_at_load_command_preview(
        &PathBuf::from("/Library/LaunchDaemons/com.example.daemon.plist"),
        true,
    );

    assert_eq!(command.program, "osascript");
    assert_eq!(command.args.len(), 2);

    let script = &command.args[1];
    assert!(script.contains("with administrator privileges"));
    assert!(script.contains("'/usr/bin/plutil'"));
    assert!(script.contains("'-replace'"));
    assert!(script.contains("'RunAtLoad'"));
    assert!(script.contains("'-bool'"));
    assert!(script.contains("'true'"));
    assert!(!script.contains("sudo"));
}

#[test]
fn test_launchd_system_domain_mutation_refuses_without_real_service() {
    let res = bootstrap_service(
        &PathBuf::from("/Library/LaunchDaemons/com.example.nonexistent.plist"),
        ServiceType::SystemLaunchDaemon,
    );

    assert!(matches!(
        res,
        Err(CleantonError::RootPrivilegesRequired(_) | CleantonError::ExecutionRefused(_))
    ));
}

#[test]
fn test_parse_plist_valid() {
    let temp_dir = tempfile::tempdir().unwrap();
    let plist_path = temp_dir.path().join("test.plist");

    let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.testservice</string>
    <key>Program</key>
    <string>/usr/bin/true</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/true</string>
        <string>--arg</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"#;

    fs::write(&plist_path, content).unwrap();

    let parsed = parse_plist(&plist_path).unwrap();
    assert_eq!(parsed.label, "com.example.testservice");
    assert_eq!(parsed.program, Some(PathBuf::from("/usr/bin/true")));
    assert_eq!(
        parsed.program_arguments,
        vec!["/usr/bin/true".to_string(), "--arg".to_string()]
    );
    assert!(parsed.run_at_load);
}

#[test]
fn test_parse_plist_minimal() {
    let temp_dir = tempfile::tempdir().unwrap();
    let plist_path = temp_dir.path().join("minimal.plist");

    let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.minimal</string>
</dict>
</plist>"#;

    fs::write(&plist_path, content).unwrap();

    let parsed = parse_plist(&plist_path).unwrap();
    assert_eq!(parsed.label, "com.example.minimal");
    assert_eq!(parsed.program, None);
    assert!(parsed.program_arguments.is_empty());
    assert!(!parsed.run_at_load);
}

#[test]
fn test_get_launchd_pids() {
    let pids = get_launchd_pids();
    // It should at least run successfully (the system has launchd)
    println!("Found {} launchd pids", pids.len());
}

#[tokio::test]
async fn test_service_manager_list_and_non_root_mutations() {
    let config = CleantonConfig::default();
    let manager = ServiceManager::new(config);

    // List should work and run without errors on macOS
    let services_res = manager.list_services().await;
    assert!(services_res.is_ok());

    let services = services_res.unwrap();
    println!("Listed {} services", services.len());

    // Try to mutate a protected service if one is found
    if let Some(sys_service) = services.iter().find(|s| s.id.starts_with("com.apple.")) {
        let res = manager.stop_service(&sys_service.id).await;
        assert!(matches!(res, Err(CleantonError::ExecutionRefused(_))));
    }

    // Try to mutate a system-wide service (LaunchDaemon) as non-root (unless running as root)
    let uid = cleanton_services::launchd::get_current_uid();
    if uid != 0
        && let Some(daemon) = services.iter().find(|s| {
            s.service_type == ServiceType::SystemLaunchDaemon && !s.id.starts_with("com.apple.")
        })
    {
        let res = manager.stop_service(&daemon.id).await;
        assert!(matches!(res, Err(CleantonError::RootPrivilegesRequired(_))));
    }
}
