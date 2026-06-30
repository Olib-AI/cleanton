use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
    pub id: String,                // e.g. "com.redis.redis-server"
    pub name: String,              // e.g. "redis-server" or "redis"
    pub service_type: ServiceType, // UserLaunchAgent | SystemLaunchAgent | SystemLaunchDaemon | BrewService
    pub status: ServiceStatus,     // Running | Stopped | Loaded | Error
    pub plist_path: PathBuf,       // Path to the service .plist file
    pub program: Option<PathBuf>,  // Executable path
    pub program_arguments: Vec<String>,
    pub run_at_load: bool, // Does it start on boot?
    pub label: String,
    pub user_id: Option<u32>, // User ID owner
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDiscovery {
    pub services: Vec<Service>,
    pub errors: Vec<ServiceDiscoveryError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceDiscoveryError {
    pub path: PathBuf,
    pub severity: cleanton_common::Severity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    UserLaunchAgent,    // ~/Library/LaunchAgents
    SystemLaunchAgent,  // /Library/LaunchAgents
    SystemLaunchDaemon, // /Library/LaunchDaemons
    BrewService,        // Managed by brew services
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceStatus {
    Running {
        pid: u32,
        cpu_percent: Option<f32>,
        memory_bytes: Option<u64>,
    },
    Stopped,
    Loaded,
    Error(String),
}

// Custom Eq implementation because f32 in Running can prevent deriving Eq
impl Eq for ServiceStatus {}

impl PartialEq for ServiceStatus {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                ServiceStatus::Running {
                    pid: p1,
                    cpu_percent: c1,
                    memory_bytes: m1,
                },
                ServiceStatus::Running {
                    pid: p2,
                    cpu_percent: c2,
                    memory_bytes: m2,
                },
            ) => {
                p1 == p2
                    && m1 == m2
                    && match (c1, c2) {
                        (Some(f1), Some(f2)) => (f1 - f2).abs() < f32::EPSILON,
                        (None, None) => true,
                        _ => false,
                    }
            }
            (ServiceStatus::Stopped, ServiceStatus::Stopped)
            | (ServiceStatus::Loaded, ServiceStatus::Loaded) => true,
            (ServiceStatus::Error(s1), ServiceStatus::Error(s2)) => s1 == s2,
            _ => false,
        }
    }
}
