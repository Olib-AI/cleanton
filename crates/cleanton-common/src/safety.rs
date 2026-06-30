use std::path::{Path, PathBuf};

use crate::paths::{
    comparison_candidates, expand_tilde, normalize_for_case_insensitive_comparison,
    normalize_for_comparison,
};

pub const HARDCODED_PROTECTED: &[&str] = &[
    "/System",
    "/Library",
    "/usr",
    "/bin",
    "/sbin",
    "/private",
    "/etc",
    "/var",
    "/Applications",
];

pub const USER_PROTECTED: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".config/cleanton",
    ".kube",
    ".docker/config.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "Library/Keychains",
    "Library/Mail",
    "Library/Messages",
    "Library/Containers",
    "Library/Group Containers",
    "Desktop",
    "Documents",
    "Downloads",
    "Pictures",
    "Music",
    "Movies",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPaths {
    hardcoded: Vec<PathBuf>,
    user_scoped: Vec<PathBuf>,
    user_configured: Vec<PathBuf>,
    // Precomputed once at construction: the firmlink/Unicode-normalized protected
    // roots (case-preserved) and their case-folded forms. Comparing against these
    // means `is_protected` does no per-call candidate rebuilding or filesystem
    // syscalls for the roots — essential when the scanner checks hundreds of
    // thousands of paths (otherwise each call recomputed ~40 roots, each with a
    // `canonicalize` syscall, melting the CPU on large scans).
    normalized_roots: Vec<PathBuf>,
    casefolded_roots: Vec<PathBuf>,
}

impl ProtectedPaths {
    #[must_use]
    pub fn new(user_configured: impl IntoIterator<Item = PathBuf>) -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let user_scoped = home.map_or_else(Vec::new, |home| {
            USER_PROTECTED
                .iter()
                .map(|path| home.join(path))
                .collect::<Vec<_>>()
        });
        let hardcoded = HARDCODED_PROTECTED
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let user_configured = user_configured
            .into_iter()
            .map(|path| expand_tilde(&path))
            .collect::<Vec<_>>();

        // Resolve each root's candidate forms (including its `canonicalize`d form,
        // to catch symlinked roots) once, then store the normalized prefixes.
        let mut normalized_roots = Vec::new();
        for root in hardcoded
            .iter()
            .chain(user_scoped.iter())
            .chain(user_configured.iter())
        {
            for candidate in comparison_candidates(root) {
                let normalized = normalize_for_comparison(&candidate);
                if !normalized_roots.contains(&normalized) {
                    normalized_roots.push(normalized);
                }
            }
        }
        let casefolded_roots = normalized_roots
            .iter()
            .map(|root| normalize_for_case_insensitive_comparison(root))
            .collect();

        Self {
            hardcoded,
            user_scoped,
            user_configured,
            normalized_roots,
            casefolded_roots,
        }
    }

    #[must_use]
    pub fn defaults() -> Self {
        Self::new([])
    }

    /// Rigorous check: resolves arbitrary symlinks in `path` (via `canonicalize`)
    /// before comparing against the protected roots. Use this on the few paths a
    /// destructive action will actually touch (executor/planner).
    #[must_use]
    pub fn is_protected(&self, path: &Path) -> bool {
        comparison_candidates(path)
            .iter()
            .any(|candidate| self.matches_normalized_root(candidate))
    }

    /// Filesystem-free check for hot bulk paths (e.g. scanner pruning, which runs
    /// on every walked entry). Compares the firmlink/Unicode/case-normalized form
    /// of `path` against the precomputed roots without any `canonicalize` syscall.
    /// It does not resolve arbitrary symlinks — entries from a scan are already
    /// real paths, and the executor re-checks rigorously before deleting.
    #[must_use]
    pub fn is_protected_fast(&self, path: &Path) -> bool {
        self.matches_normalized_root(path)
    }

    #[must_use]
    pub fn has_protected_ancestor(&self, path: &Path) -> bool {
        self.is_protected(path)
    }

    /// Compare an already-resolved candidate path against the precomputed roots.
    /// Always also compares case-folded (the safe over-protecting direction),
    /// which avoids the previous per-comparison filesystem case-sensitivity probe.
    fn matches_normalized_root(&self, candidate: &Path) -> bool {
        let normalized = normalize_for_comparison(candidate);
        if self
            .normalized_roots
            .iter()
            .any(|root| starts_with_or_equal(&normalized, root))
        {
            return true;
        }
        let folded = normalize_for_case_insensitive_comparison(&normalized);
        self.casefolded_roots
            .iter()
            .any(|root| starts_with_or_equal(&folded, root))
    }
}

/// Component-wise prefix test: `/Systems` is not a descendant of `/System`.
fn starts_with_or_equal(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

impl Default for ProtectedPaths {
    fn default() -> Self {
        Self::defaults()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn hardcoded_paths_are_protected() {
        let protected = ProtectedPaths::defaults();
        for path in HARDCODED_PROTECTED {
            assert!(protected.is_protected(Path::new(path)), "{path}");
            assert!(
                protected.is_protected(&Path::new(path).join("nested")),
                "{path}"
            );
        }
    }

    #[test]
    fn boundary_checks_reject_lookalikes() {
        let protected = ProtectedPaths::defaults();
        assert!(!protected.is_protected(Path::new("/Applications-old")));
        assert!(!protected.is_protected(Path::new("/Users/example/Documents-old")));
    }

    #[test]
    fn user_configured_paths_are_protected() {
        let protected = ProtectedPaths::new([PathBuf::from("/Users/alice/critical")]);
        assert!(protected.is_protected(Path::new("/Users/alice/critical/cache")));
    }

    #[test]
    fn case_and_unicode_are_normalized() {
        let protected = ProtectedPaths::new([PathBuf::from("/Users/alice/Cafe\u{301}")]);
        assert!(protected.is_protected(Path::new("/users/alice/caf\u{e9}/tmp")));
    }

    // --- Bypass-resistance corpus -------------------------------------------
    //
    // These tests prove a protected path cannot be reached by spelling it in an
    // alternate-but-equivalent form. They use only hardcoded system roots and
    // explicit `user_configured` entries so they never depend on `$HOME` or on
    // files existing on the test machine: every assertion is deterministic on
    // case-sensitive, case-insensitive, macOS, and Linux runners alike.

    // (a) Case variation must not bypass protection.
    #[test]
    fn case_variations_of_system_roots_are_protected() {
        let protected = ProtectedPaths::defaults();
        for path in [
            "/System",
            "/SYSTEM",
            "/system",
            "/sYsTeM/Library",
            "/Library",
            "/LIBRARY",
            "/library/Frameworks",
            "/USR/bin",
            "/Bin",
            "/Applications",
            "/APPLICATIONS/Safari.app",
        ] {
            assert!(protected.is_protected(Path::new(path)), "{path}");
        }
    }

    // (b) Unicode NFC vs NFD of a protected path with combining characters.
    #[test]
    fn unicode_nfc_and_nfd_forms_are_equivalent_both_directions() {
        // é encoded as a single codepoint (NFC) vs `e` + COMBINING ACUTE (NFD).
        let nfc = "/Users/alice/Caf\u{e9}";
        let nfd = "/Users/alice/Cafe\u{301}";

        // Protected stored as NFC; target spelled NFD must still be caught.
        let stored_composed = ProtectedPaths::new([PathBuf::from(nfc)]);
        assert!(stored_composed.is_protected(Path::new(&format!("{nfd}/cache"))));

        // ...and the reverse: protected stored NFD, target spelled NFC.
        let stored_decomposed = ProtectedPaths::new([PathBuf::from(nfd)]);
        assert!(stored_decomposed.is_protected(Path::new(&format!("{nfc}/cache"))));
    }

    // (c) Firmlink form: `/var/...` vs `/private/var/...`, both protected, both
    // directions, including the case-folded alias that the ordering fix closed.
    #[test]
    fn firmlink_forms_are_protected_both_directions() {
        let protected = ProtectedPaths::defaults();
        // Alias spelling and canonical spelling of the same locations.
        for path in [
            "/var/folders/zz/cleanton-cache",
            "/private/var/folders/zz/cleanton-cache",
            "/etc/passwd",
            "/private/etc/passwd",
            "/tmp/scratch",
            "/private/tmp/scratch",
            // Case-folded alias must not slip past (regression for the
            // firmlink-after-folding ordering fix).
            "/VAR/folders/zz/x",
            "/Private/Var/folders/zz/x",
        ] {
            assert!(protected.is_protected(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn firmlink_equivalence_resolves_for_user_configured_roots() {
        // Protection written against the canonical `/private/var` form must
        // catch a target addressed through the `/var` alias.
        let via_private = ProtectedPaths::new([PathBuf::from("/private/var/myapp/state")]);
        assert!(via_private.is_protected(Path::new("/var/myapp/state/db")));

        // ...and protection written against the `/var` alias must catch the
        // canonical `/private/var` target.
        let via_alias = ProtectedPaths::new([PathBuf::from("/var/other/state")]);
        assert!(via_alias.is_protected(Path::new("/private/var/other/state/db")));
    }

    // (d) Trailing slash, `.` and `..` normalization.
    #[test]
    fn dot_and_trailing_slash_normalization_cannot_bypass() {
        let protected = ProtectedPaths::defaults();
        for path in [
            "/System/",
            "/System/./Library",
            "/System/Library/../Frameworks",
            "/var/../var/folders/zz/x",
            "/private/./var/folders/zz/x",
            "/usr//local//bin",
        ] {
            assert!(protected.is_protected(Path::new(path)), "{path}");
        }

        // `..` that genuinely escapes a protected root must NOT be protected.
        assert!(!protected.is_protected(Path::new("/System/../opt/cache")));
        assert!(!protected.is_protected(Path::new("/var/folders/../../opt/cache")));
    }

    // (e) Lookalike near-misses must NOT be falsely protected (boundary
    // correctness — a shared string prefix is not containment).
    #[test]
    fn lookalike_paths_are_not_falsely_protected() {
        let protected = ProtectedPaths::defaults();
        for path in [
            "/Systems",
            "/SystemUpgrade",
            "/Libraryx",
            "/usr-local",
            "/binary",
            "/sbinx",
            "/etcd/data",
            "/variable/log",
            "/VARIABLE/log",
            "/tmpfoo",
            "/private-data/cache",
            "/Applications-old/Thing.app",
        ] {
            assert!(!protected.is_protected(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn symlink_alias_to_protected_path_is_protected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let protected_dir = temp.path().join("protected");
        std::fs::create_dir(&protected_dir).expect("protected dir");
        let alias = temp.path().join("alias");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&protected_dir, &alias).expect("symlink");
        #[cfg(not(unix))]
        return;

        let protected = ProtectedPaths::new([protected_dir.join("cache")]);
        std::fs::create_dir(protected_dir.join("cache")).expect("cache dir");
        assert!(protected.is_protected(&alias.join("cache").join("artifact")));
    }
}
