//! Cleanton package-manager facade.
//!
//! Inspects four macOS package managers (Homebrew formulae, Homebrew casks,
//! global npm, pip, `MacPorts`), computes a Homebrew keep-set removal plan, scans
//! codebases for package usage, and exposes gated mutating actions. All
//! external-tool execution is timeout-bounded and isolated in
//! [`mod@process`], mirroring `cleanton-services::reviewed_process`.
//!
//! Read-only operations ([`PackageManagers::inventory`], [`scan_usage`],
//! [`plan_removal`]) never mutate the system. Mutating operations
//! ([`PackageManagers::uninstall`], [`PackageManagers::update`],
//! [`PackageManagers::clean_cache`]) shell out to the managers' own tooling and,
//! for `MacPorts`, prompt for administrator privileges.

#![forbid(unsafe_code)]

mod managers;
mod plan;
mod process;
mod types;
mod usage;

pub use plan::plan_removal;
pub use types::{ActionOutcome, Inventory, ManagerKind, Package, RemovalPlan};
pub use usage::scan_usage;

/// Entry point for detecting, inspecting, and mutating OS package managers.
#[derive(Debug)]
pub struct PackageManagers;

impl PackageManagers {
    /// Returns the managers whose binary is present on `PATH`.
    ///
    /// Homebrew and Homebrew Cask are both reported when `brew` is present,
    /// since casks are managed by the same binary.
    #[must_use]
    pub fn detect() -> Vec<ManagerKind> {
        let mut found = Vec::new();
        if managers::homebrew::detected() {
            found.push(ManagerKind::Homebrew);
            found.push(ManagerKind::HomebrewCask);
        }
        if managers::npm::detected() {
            found.push(ManagerKind::Npm);
        }
        if managers::pip::detected() {
            found.push(ManagerKind::Pip);
        }
        if managers::macports::detected() {
            found.push(ManagerKind::MacPorts);
        }
        found
    }

    /// Read-only inventory for `kind`: packages with sizes, deps, leaf flags,
    /// and outdated targets. Returns an unavailable [`Inventory`] when the
    /// manager binary is absent; never mutates the system.
    pub async fn inventory(kind: ManagerKind) -> Inventory {
        match kind {
            ManagerKind::Homebrew => managers::homebrew::inventory_formulae().await,
            ManagerKind::HomebrewCask => managers::homebrew::inventory_casks().await,
            ManagerKind::Npm => managers::npm::inventory().await,
            ManagerKind::Pip => managers::pip::inventory().await,
            ManagerKind::MacPorts => managers::macports::inventory().await,
        }
    }

    /// Network-bound check for available updates, keyed by package name → latest
    /// version. Kept separate from [`PackageManagers::inventory`] because it
    /// queries a remote index per package and can run far longer than the
    /// inventory probe (notably `pip list --outdated`); callers fetch it in the
    /// background so the package list renders immediately. Returns an empty map
    /// on timeout or error.
    pub async fn outdated(kind: ManagerKind) -> std::collections::HashMap<String, String> {
        match kind {
            ManagerKind::Homebrew => managers::homebrew::outdated(false).await,
            ManagerKind::HomebrewCask => managers::homebrew::outdated(true).await,
            ManagerKind::Npm => managers::npm::outdated().await,
            ManagerKind::Pip => managers::pip::outdated().await,
            ManagerKind::MacPorts => managers::macports::outdated().await,
        }
    }

    /// Uninstalls `names` via the manager's dependency-aware uninstaller.
    /// `MacPorts` prompts for administrator privileges. Homebrew casks are
    /// uninstalled with `--cask` so the `.app` bundle is actually removed.
    pub async fn uninstall(kind: ManagerKind, names: &[String]) -> ActionOutcome {
        match kind {
            ManagerKind::Homebrew => managers::homebrew::uninstall(false, names).await,
            ManagerKind::HomebrewCask => managers::homebrew::uninstall(true, names).await,
            ManagerKind::Npm => managers::npm::uninstall(names).await,
            ManagerKind::Pip => managers::pip::uninstall(names).await,
            ManagerKind::MacPorts => managers::macports::uninstall(names).await,
        }
    }

    /// Updates `names` (empty `names` updates everything, where the manager
    /// supports it). `MacPorts` prompts for administrator privileges.
    pub async fn update(kind: ManagerKind, names: &[String]) -> ActionOutcome {
        match kind {
            ManagerKind::Homebrew | ManagerKind::HomebrewCask => {
                managers::homebrew::update(names).await
            }
            ManagerKind::Npm => managers::npm::update(names).await,
            ManagerKind::Pip => managers::pip::update(names).await,
            ManagerKind::MacPorts => managers::macports::update(names).await,
        }
    }

    /// Cleans the manager's download/build cache, reporting freed bytes when the
    /// tool exposes them. `MacPorts` prompts for administrator privileges.
    pub async fn clean_cache(kind: ManagerKind) -> ActionOutcome {
        match kind {
            ManagerKind::Homebrew | ManagerKind::HomebrewCask => {
                managers::homebrew::clean_cache().await
            }
            ManagerKind::Npm => managers::npm::clean_cache().await,
            ManagerKind::Pip => managers::pip::clean_cache().await,
            ManagerKind::MacPorts => managers::macports::clean_cache().await,
        }
    }
}
