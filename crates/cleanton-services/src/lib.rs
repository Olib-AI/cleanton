pub mod brew;
pub mod launchd;
pub mod manager;
mod reviewed_plist_delete;
mod reviewed_process;
pub mod safety;
pub mod systemd;
pub mod types;

pub use manager::{ServiceElevation, ServiceManager, ServiceMutationOptions};
pub use safety::{check_mutation_safety, is_protected};
pub use types::{Service, ServiceDiscovery, ServiceDiscoveryError, ServiceStatus, ServiceType};
