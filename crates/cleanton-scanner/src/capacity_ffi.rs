//! Isolated `unsafe` FFI surface for macOS volume capacity and case-sensitivity queries.
//!
//! This is the ONLY module in `cleanton-scanner` permitted to use `unsafe`. The workspace
//! sets `unsafe_code = "deny"`; this file downgrades that locally with the file-level
//! `#![allow(unsafe_code)]` below so the few required libc syscalls (`statfs`, `pathconf`)
//! can be called. Every `unsafe` block carries a `// SAFETY:` comment. The rest of the
//! crate consumes only the safe Rust API exported here (`volume_capacity`,
//! `is_case_sensitive`, `VolumeCapacity`).
//!
//! ## Honesty note on "available for important usage"
//!
//! Finder's "Available" figure comes from Foundation's
//! `URLResourceValues.volumeAvailableCapacityForImportantUsageKey`, which folds in
//! *purgeable* space (reclaimable caches, evictable local snapshots, re-downloadable
//! content). That value is only reachable through Foundation / `NSURL` and is **not**
//! derivable from `statfs` alone. To keep the `unsafe` surface minimal we use `statfs`
//! and therefore report [`VolumeCapacity::available_for_important_usage_bytes`] as the
//! syscall-level user-available space (`f_bavail`), which is a *conservative lower bound*:
//! the true Finder figure is this value **plus purgeable space**. See
//! [`VolumeCapacity::purgeable_estimate_bytes`] for the limitation on the purgeable number.
#![allow(unsafe_code)]

use std::path::Path;

use cleanton_common::{CleantonError, Result};
use serde::{Deserialize, Serialize};

/// Capacity figures for the filesystem that contains a given path.
///
/// All values are in bytes. Derived from a single `statfs(2)` call. Because raw `statfs`
/// cannot see APFS purgeable space, the "important usage" and "purgeable" fields are
/// documented approximations rather than the exact figures Finder shows — see the module
/// docs and the per-field documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeCapacity {
    /// Total size of the volume (`f_blocks * f_bsize`).
    pub total_bytes: u64,
    /// Raw free space including the superuser reserve (`f_bfree * f_bsize`).
    pub free_bytes: u64,
    /// Space available to the current (non-superuser) user (`f_bavail * f_bsize`).
    pub available_bytes: u64,
    /// Best-effort "available for important usage" figure.
    ///
    /// Equal to [`Self::available_bytes`]. This is a **conservative lower bound** on
    /// Finder's "Available" number: the precise value additionally counts purgeable
    /// space and is only obtainable via Foundation's
    /// `volumeAvailableCapacityForImportantUsageKey`, which is out of reach from a
    /// libc-only FFI surface.
    pub available_for_important_usage_bytes: u64,
    /// Used space (`total_bytes - free_bytes`).
    pub used_bytes: u64,
    /// Rough estimate of purgeable / reserved space (`free_bytes - available_bytes`).
    ///
    /// **Limitation:** from `statfs` this difference is the superuser block reserve, not
    /// the APFS purgeable pool Finder reports. It is surfaced as a non-negative proxy so
    /// callers have *a* number; an accurate purgeable figure requires the Foundation
    /// URL-resource keys (see module docs). On many APFS volumes this is `0`.
    pub purgeable_estimate_bytes: u64,
    /// Fundamental filesystem block size (`f_bsize`).
    pub block_size: u64,
}

impl VolumeCapacity {
    /// Builds a [`VolumeCapacity`] from raw `statfs` block counts. Kept separate from the
    /// FFI call so the (overflow-safe) arithmetic can be unit-tested without a syscall.
    #[must_use]
    fn from_statfs_fields(block_size: u64, blocks: u64, bfree: u64, bavail: u64) -> Self {
        let total_bytes = blocks.saturating_mul(block_size);
        let free_bytes = bfree.saturating_mul(block_size);
        let available_bytes = bavail.saturating_mul(block_size);
        Self {
            total_bytes,
            free_bytes,
            available_bytes,
            available_for_important_usage_bytes: available_bytes,
            used_bytes: total_bytes.saturating_sub(free_bytes),
            purgeable_estimate_bytes: free_bytes.saturating_sub(available_bytes),
            block_size,
        }
    }
}

/// Reports capacity for the volume containing `path`.
///
/// # Errors
///
/// Returns [`CleantonError::Io`] if the path cannot be converted to a C string (interior
/// NUL byte) or if the underlying `statfs(2)` call fails (e.g. the path does not exist or
/// is not accessible). On non-Unix targets this always returns an error.
#[cfg(unix)]
pub fn volume_capacity(path: &Path) -> Result<VolumeCapacity> {
    use std::os::unix::ffi::OsStrExt;

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        CleantonError::io(
            path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path contains an interior NUL byte",
            ),
        )
    })?;

    // SAFETY: `statfs` is a plain-old-data struct; an all-zero bit pattern is a valid,
    // fully-initialized instance that the kernel will overwrite on success.
    let mut stat_buf: libc::statfs = unsafe { std::mem::zeroed() };

    // SAFETY: `c_path` is a valid NUL-terminated C string that outlives the call, and
    // `&mut stat_buf` points to a properly aligned, writable `statfs` the kernel may fully
    // populate. The return value is checked below before any field is read.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &raw mut stat_buf) };
    if rc != 0 {
        return Err(CleantonError::io(path, std::io::Error::last_os_error()));
    }

    #[cfg(target_os = "macos")]
    let bsize = u64::from(stat_buf.f_bsize);
    #[cfg(not(target_os = "macos"))]
    let bsize = u64::try_from(stat_buf.f_bsize).unwrap_or(0);

    Ok(VolumeCapacity::from_statfs_fields(
        bsize,
        stat_buf.f_blocks,
        stat_buf.f_bfree,
        stat_buf.f_bavail,
    ))
}

#[cfg(not(unix))]
pub fn volume_capacity(path: &Path) -> Result<VolumeCapacity> {
    Err(CleantonError::Scan(format!(
        "volume capacity queries are only supported on Unix targets (path: {})",
        path.display()
    )))
}

/// Returns `true` if the filesystem containing `path` is case-sensitive.
///
/// Uses `pathconf(_PC_CASE_SENSITIVE)` on macOS. Default APFS volumes are case-insensitive and
/// return `false`. On any error (or non-Apple target) this conservatively returns `false`
/// (case-insensitive), which drives the safer case-insensitive protected-path comparison.
#[cfg(target_os = "macos")]
#[must_use]
pub fn is_case_sensitive(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };

    // SAFETY: `c_path` is a valid NUL-terminated C string that outlives the call;
    // `_PC_CASE_SENSITIVE` is a documented configuration name. `pathconf` returns the
    // configured value (1 = case-sensitive, 0 = case-insensitive) or -1 on error, none of
    // which can produce undefined behavior here.
    let value = unsafe { libc::pathconf(c_path.as_ptr(), libc::_PC_CASE_SENSITIVE) };
    value > 0
}

#[cfg(not(target_os = "macos"))]
#[must_use]
pub fn is_case_sensitive(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_statfs_fields_computes_derived_values() {
        // 1000 blocks total, 400 free, 300 available, 4 KiB blocks.
        let cap = VolumeCapacity::from_statfs_fields(4096, 1000, 400, 300);
        assert_eq!(cap.total_bytes, 1000 * 4096);
        assert_eq!(cap.free_bytes, 400 * 4096);
        assert_eq!(cap.available_bytes, 300 * 4096);
        assert_eq!(cap.available_for_important_usage_bytes, 300 * 4096);
        assert_eq!(cap.used_bytes, 600 * 4096);
        assert_eq!(cap.purgeable_estimate_bytes, 100 * 4096);
        assert_eq!(cap.block_size, 4096);
    }

    #[test]
    fn from_statfs_fields_saturates_instead_of_overflowing() {
        let cap = VolumeCapacity::from_statfs_fields(u64::MAX, u64::MAX, 0, 0);
        assert_eq!(cap.total_bytes, u64::MAX);
        assert_eq!(cap.used_bytes, u64::MAX);
        assert_eq!(cap.purgeable_estimate_bytes, 0);
    }

    #[cfg(unix)]
    #[test]
    fn volume_capacity_reports_plausible_total_for_root() {
        let cap = volume_capacity(Path::new("/")).expect("root volume capacity");
        assert!(
            cap.total_bytes > 0,
            "root volume should report non-zero total"
        );
        assert!(cap.block_size > 0, "block size should be non-zero");
        assert!(
            cap.available_bytes <= cap.total_bytes,
            "available ({}) must not exceed total ({})",
            cap.available_bytes,
            cap.total_bytes
        );
        assert!(
            cap.available_for_important_usage_bytes <= cap.total_bytes,
            "important-usage available must not exceed total"
        );
        assert_eq!(cap.used_bytes, cap.total_bytes - cap.free_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn volume_capacity_errors_on_missing_path() {
        let result = volume_capacity(Path::new("/definitely-missing-cleanton-volume-xyz"));
        assert!(result.is_err(), "missing path should produce an error");
    }

    #[cfg(unix)]
    #[test]
    fn is_case_sensitive_runs_without_panicking() {
        // We don't assert the value (volume-dependent); we only require it not to panic.
        let _ = is_case_sensitive(Path::new("/"));
        let _ = is_case_sensitive(Path::new("/definitely-missing-cleanton-volume-xyz"));
    }
}

/// System memory usage snapshot (total / available bytes + used fraction).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemoryUsage {
    /// Total physical memory in bytes.
    pub total_bytes: u64,
    /// Memory available to applications in bytes (best effort).
    pub available_bytes: u64,
    /// Used fraction in `0.0..=1.0`.
    pub used_fraction: f64,
}

/// Read memory usage without spawning a subprocess: `sysconf(3)` page
/// counts on Linux; on macOS the total comes from `sysconf` and the
/// available figure (free + inactive pages) from `host_statistics64`.
/// `None` when the values are unavailable.
#[must_use]
pub fn memory_usage() -> Option<MemoryUsage> {
    // SAFETY: sysconf with a valid name returns -1 on error and has no
    // memory-safety requirements; results are checked before use.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    // SAFETY: same as above.
    let phys_pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    if page_size <= 0 || phys_pages <= 0 {
        return None;
    }
    let page = u64::try_from(page_size).ok()?;
    let total_bytes = u64::try_from(phys_pages).ok()?.saturating_mul(page);
    if total_bytes == 0 {
        return None;
    }
    let available_bytes = available_bytes(page)?;
    let used = total_bytes.saturating_sub(available_bytes);
    #[allow(clippy::cast_precision_loss)]
    let used_fraction = used as f64 / total_bytes as f64;
    Some(MemoryUsage {
        total_bytes,
        available_bytes,
        used_fraction,
    })
}

#[cfg(target_os = "linux")]
fn available_bytes(page: u64) -> Option<u64> {
    // SAFETY: sysconf with a valid name returns -1 on error and has no
    // memory-safety requirements; the result is checked before use.
    let avail_pages = unsafe { libc::sysconf(libc::_SC_AVPHYS_PAGES) };
    if avail_pages < 0 {
        return None;
    }
    Some(u64::try_from(avail_pages).ok()?.saturating_mul(page))
}

#[cfg(target_os = "macos")]
#[allow(deprecated)] // libc::mach_host_self: the mach2 alternative is not a dependency.
fn available_bytes(page: u64) -> Option<u64> {
    let mut stats: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
    let mut count = u32::try_from(
        std::mem::size_of::<libc::vm_statistics64>() / std::mem::size_of::<libc::integer_t>(),
    )
    .ok()?;
    // SAFETY: mach_host_self returns a valid host port for this process;
    // stats is a zeroed vm_statistics64 and count describes its size in
    // integer_t units, as host_statistics64 requires. The return code is
    // checked before any field is read.
    let rc = unsafe {
        libc::host_statistics64(
            libc::mach_host_self(),
            libc::HOST_VM_INFO64,
            &raw mut stats as libc::host_info_t,
            &raw mut count,
        )
    };
    if rc != libc::KERN_SUCCESS {
        return None;
    }
    let available_pages =
        u64::from(stats.free_count).saturating_add(u64::from(stats.inactive_count));
    Some(available_pages.saturating_mul(page))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn available_bytes(_page: u64) -> Option<u64> {
    None
}
