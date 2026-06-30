//! Plain data types shared across the package-manager facade.
//!
//! Every type derives `Serialize`/`Deserialize` so the Slint app and the CLI
//! can ferry inventories and plans across thread/IPC boundaries unchanged.

use serde::{Deserialize, Serialize};

/// The OS package managers Cleanton can inspect on macOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ManagerKind {
    /// Homebrew formulae (the dependency-graph-rich manager).
    Homebrew,
    /// Homebrew casks (GUI apps / binaries; no dependency graph).
    HomebrewCask,
    /// Globally installed npm packages.
    Npm,
    /// Python packages visible to `pip3`/`pip`.
    Pip,
    /// `MacPorts` ports.
    MacPorts,
}

impl ManagerKind {
    /// Stable machine identifier (safe for config keys and JSON tags).
    #[must_use]
    pub const fn id(&self) -> &'static str {
        match self {
            Self::Homebrew => "homebrew",
            Self::HomebrewCask => "homebrew-cask",
            Self::Npm => "npm",
            Self::Pip => "pip",
            Self::MacPorts => "macports",
        }
    }

    /// Human-facing label for the Packages tab.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Homebrew => "Homebrew",
            Self::HomebrewCask => "Homebrew Cask",
            Self::Npm => "npm (global)",
            Self::Pip => "pip",
            Self::MacPorts => "MacPorts",
        }
    }
}

/// A single installed package as reported by its manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// Which manager owns this package.
    pub manager: ManagerKind,
    /// Package / formula / port name.
    pub name: String,
    /// Installed version string (empty if the manager did not report one).
    pub version: String,
    /// On-disk size in bytes; `0` when the manager cannot report it.
    pub size_bytes: u64,
    /// `true` when nothing else installed depends on this package. Defaults to
    /// `true` for managers without a dependency graph.
    pub is_leaf: bool,
    /// `true` when the user installed this on purpose (Homebrew
    /// `installed_on_request`); `true` for managers that lack the distinction.
    pub explicitly_installed: bool,
    /// New version available, if the package is outdated.
    pub outdated_to: Option<String>,
    /// Direct dependency names (Homebrew formulae only; empty otherwise).
    pub deps: Vec<String>,
    /// Project paths referencing this package; filled in by [`crate::scan_usage`].
    pub used_by: Vec<String>,
}

/// The full result of inspecting one manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    /// Which manager this inventory describes.
    pub manager: ManagerKind,
    /// `true` when the manager binary is present on `PATH`.
    pub available: bool,
    /// Installed packages (empty when unavailable or on a read error).
    pub packages: Vec<Package>,
    /// Optional human note (e.g. "Homebrew not installed" or a sudo notice).
    pub note: Option<String>,
}

impl Inventory {
    /// Manager binary not found.
    #[must_use]
    pub(crate) fn missing(manager: ManagerKind, note: impl Into<String>) -> Self {
        Self {
            manager,
            available: false,
            packages: Vec::new(),
            note: Some(note.into()),
        }
    }

    /// Binary present and inventory read successfully.
    #[must_use]
    pub(crate) fn ready(
        manager: ManagerKind,
        packages: Vec<Package>,
        note: Option<String>,
    ) -> Self {
        Self {
            manager,
            available: true,
            packages,
            note,
        }
    }

    /// Binary present but the read failed or returned nothing parseable.
    #[must_use]
    pub(crate) fn degraded(manager: ManagerKind, note: impl Into<String>) -> Self {
        Self {
            manager,
            available: true,
            packages: Vec::new(),
            note: Some(note.into()),
        }
    }
}

/// A Homebrew "keep-set" removal plan computed by [`crate::plan_removal`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalPlan {
    /// The user-chosen keep set (sorted).
    pub keep: Vec<String>,
    /// Installed packages not in the dependency closure of `keep` (sorted).
    pub removable: Vec<String>,
    /// Packages retained only because a kept package needs them (sorted).
    pub kept_as_dependency: Vec<String>,
    /// Sum of `size_bytes` over `removable`.
    pub reclaimable_bytes: u64,
    /// `removable` ordered dependents-before-dependencies for safe uninstall.
    pub uninstall_order: Vec<String>,
}

/// Result of a mutating action (uninstall / update / cache clean).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionOutcome {
    /// Whether the underlying command reported success.
    pub ok: bool,
    /// Human-readable summary (trimmed stdout/stderr or an explanation).
    pub message: String,
    /// Bytes reclaimed, when the tool reports it (else `0`).
    pub freed_bytes: u64,
}

impl ActionOutcome {
    #[must_use]
    pub(crate) fn failed(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            freed_bytes: 0,
        }
    }
}
