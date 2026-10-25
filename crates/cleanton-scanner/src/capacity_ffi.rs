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

    #[test]
    fn parses_linux_mem_available_from_proc_meminfo() {
        let sample = "MemTotal:       32768000 kB\nMemFree:         1024000 kB\nMemAvailable:   24576000 kB\n";
        assert_eq!(parse_linux_mem_available(sample), Some(24_576_000 * 1024));
        assert_eq!(parse_linux_mem_available("MemTotal: 1000 kB\n"), None);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn memory_helpers_report_valid_ranges() {
        let mem = memory_usage().expect("memory usage available on unix CI");
        assert!(mem.total_bytes > 0);
        assert!(mem.available_bytes <= mem.total_bytes);
        assert!((0.0..=1.0).contains(&mem.used_fraction));
        let _ = top_memory_processes(5);
        let _ = reclaim_process_memory();
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
    let available_bytes = available_bytes(page)?.min(total_bytes);
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
    // Prefer `/proc/meminfo` `MemAvailable:` so reclaimable kernel page cache and
    // buffers are counted as available memory instead of reporting false pressure
    // when Linux caches filesystem reads in free RAM.
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo")
        && let Some(bytes) = parse_linux_mem_available(&meminfo)
    {
        return Some(bytes);
    }

    // SAFETY: sysconf with a valid name returns -1 on error and has no
    // memory-safety requirements; the result is checked before use.
    let avail_pages = unsafe { libc::sysconf(libc::_SC_AVPHYS_PAGES) };
    if avail_pages < 0 {
        return None;
    }
    Some(u64::try_from(avail_pages).ok()?.saturating_mul(page))
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_mem_available(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb_str = rest.split_whitespace().next()?;
            let kb = kb_str.parse::<u64>().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

#[cfg(target_os = "macos")]
#[allow(deprecated)] // libc::mach_host_self: the mach2 alternative is not a dependency.
fn available_bytes(page: u64) -> Option<u64> {
    // SAFETY: `vm_statistics64` is a plain-old-data Mach struct of integer counters
    // for which an all-zero bit pattern is valid.
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
    let available_pages = u64::from(stats.free_count)
        .saturating_add(u64::from(stats.inactive_count))
        .saturating_add(u64::from(stats.speculative_count));
    Some(available_pages.saturating_mul(page))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn available_bytes(_page: u64) -> Option<u64> {
    None
}

/// Snapshot of one user-owned process's resident memory usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessMemorySample {
    pub pid: u32,
    pub name: String,
    pub rss_bytes: u64,
}

/// Return up to `limit` user-owned processes with the largest resident set size (`RSS`),
/// excluding the current Cleanton process. Pure read-only inspection; never signals or
/// mutates any process.
#[must_use]
pub fn top_memory_processes(limit: usize) -> Vec<ProcessMemorySample> {
    if limit == 0 {
        return Vec::new();
    }
    let mut samples = collect_user_process_memory();
    samples.sort_by(|a, b| {
        b.rss_bytes
            .cmp(&a.rss_bytes)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.pid.cmp(&b.pid))
    });
    samples.truncate(limit);
    samples
}

#[cfg(target_os = "linux")]
fn collect_user_process_memory() -> Vec<ProcessMemorySample> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: `geteuid` has no preconditions and cannot cause undefined behavior.
    let current_uid = unsafe { libc::geteuid() };
    // SAFETY: `sysconf(_SC_PAGESIZE)` has no preconditions; negative values are rejected.
    let page_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let Ok(page_size) = u64::try_from(page_raw) else {
        return Vec::new();
    };
    if page_size == 0 {
        return Vec::new();
    }
    let self_pid = std::process::id();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut samples = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        let proc_dir = entry.path();
        let Ok(meta) = std::fs::metadata(&proc_dir) else {
            continue;
        };
        if meta.uid() != current_uid {
            continue;
        }
        let Ok(statm) = std::fs::read_to_string(proc_dir.join("statm")) else {
            continue;
        };
        let Some(resident_pages) = statm
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u64>().ok())
        else {
            continue;
        };
        let rss_bytes = resident_pages.saturating_mul(page_size);
        if rss_bytes == 0 {
            continue;
        }
        let Ok(comm) = std::fs::read_to_string(proc_dir.join("comm")) else {
            continue;
        };
        let name = comm.trim().to_owned();
        if name.is_empty() {
            continue;
        }
        samples.push(ProcessMemorySample {
            pid,
            name,
            rss_bytes,
        });
    }
    samples
}

#[cfg(target_os = "macos")]
fn collect_user_process_memory() -> Vec<ProcessMemorySample> {
    const PROC_ALL_PIDS: libc::c_uint = 1;
    const MAX_PIDS: usize = 4096;

    unsafe extern "C" {
        fn proc_listpids(
            kind: libc::c_uint,
            typeinfo: u32,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
        fn proc_pid_rusage(
            pid: libc::c_int,
            flavor: libc::c_int,
            buffer: *mut libc::rusage_info_v2,
        ) -> libc::c_int;
        fn proc_name(pid: libc::c_int, buffer: *mut libc::c_void, buffersize: u32) -> libc::c_int;
    }

    let mut pids = vec![0_i32; MAX_PIDS];
    let byte_len = pids.len().saturating_mul(std::mem::size_of::<i32>());
    let Ok(buf_size) = libc::c_int::try_from(byte_len) else {
        return Vec::new();
    };
    // SAFETY: `pids` is an allocated buffer of `buf_size` bytes that outlives the call.
    // `proc_listpids` writes at most `buf_size` bytes and returns bytes written or <= 0 on error.
    let bytes_written = unsafe {
        proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast::<libc::c_void>(),
            buf_size,
        )
    };
    if bytes_written <= 0 {
        return Vec::new();
    }
    let count = usize::try_from(bytes_written)
        .unwrap_or(0)
        .checked_div(std::mem::size_of::<i32>())
        .unwrap_or(0)
        .min(pids.len());

    let self_pid = std::process::id();
    let mut samples = Vec::new();
    for &raw_pid in pids.iter().take(count) {
        if raw_pid <= 0 {
            continue;
        }
        let Ok(pid) = u32::try_from(raw_pid) else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        // SAFETY: `rusage_info_v2` is a plain-old-data C struct of integer counters;
        // zero initialization is valid and `proc_pid_rusage` only populates it for processes
        // accessible to the current user (returning non-zero for root/other-user processes).
        let mut usage: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
        // SAFETY: `usage` is a valid `rusage_info_v2` matching `RUSAGE_INFO_V2`.
        let rc = unsafe { proc_pid_rusage(raw_pid, libc::RUSAGE_INFO_V2, &raw mut usage) };
        if rc != 0 || usage.ri_phys_footprint == 0 {
            continue;
        }
        let mut name_buf = [0_u8; 256];
        let Ok(name_cap) = u32::try_from(name_buf.len()) else {
            continue;
        };
        // SAFETY: `name_buf` is a valid mutable byte buffer of length `name_cap`.
        let name_len = unsafe {
            proc_name(
                raw_pid,
                name_buf.as_mut_ptr().cast::<libc::c_void>(),
                name_cap,
            )
        };
        if name_len <= 0 {
            continue;
        }
        let valid_len = usize::try_from(name_len).unwrap_or(0).min(name_buf.len());
        let name = String::from_utf8_lossy(name_buf.get(..valid_len).unwrap_or(&[]))
            .trim_end_matches('\0')
            .trim()
            .to_owned();
        if name.is_empty() {
            continue;
        }
        samples.push(ProcessMemorySample {
            pid,
            name,
            rss_bytes: usage.ri_phys_footprint,
        });
    }
    samples
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn collect_user_process_memory() -> Vec<ProcessMemorySample> {
    Vec::new()
}

/// Ask the C/system allocator to return unused free heap pages back to the OS kernel.
/// Safe to invoke after dropping large scan results or when memory pressure is high.
#[must_use]
pub fn reclaim_process_memory() -> bool {
    reclaim_process_memory_impl()
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn reclaim_process_memory_impl() -> bool {
    unsafe extern "C" {
        fn malloc_trim(pad: libc::size_t) -> libc::c_int;
    }
    // SAFETY: `malloc_trim(0)` is thread-safe in glibc and releases unused top-of-heap
    // and arena pages back to the kernel without invalidating any live allocations.
    unsafe { malloc_trim(0) != 0 }
}

#[cfg(target_os = "macos")]
fn reclaim_process_memory_impl() -> bool {
    unsafe extern "C" {
        fn malloc_zone_pressure_relief(zone: *mut libc::c_void, goal: libc::size_t)
        -> libc::size_t;
    }
    // SAFETY: Passing a null zone pointer instructs libsystem_malloc to relieve unused
    // cached pages across all malloc zones; `goal = 0` requests maximal safe relief.
    unsafe { malloc_zone_pressure_relief(std::ptr::null_mut(), 0) > 0 }
}

#[cfg(not(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")))]
fn reclaim_process_memory_impl() -> bool {
    false
}
