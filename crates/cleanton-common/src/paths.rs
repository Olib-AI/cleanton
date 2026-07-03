use std::{
    collections::HashSet,
    env,
    ffi::OsString,
    fs,
    path::{Component, Path, PathBuf},
};

use unicode_normalization::UnicodeNormalization;

/// macOS APFS firmlink / synthesized-symlink equivalences.
///
/// Each entry maps an `(alias, canonical)` top-level form that the operating
/// system presents as the *same* on-disk location. macOS synthesizes the
/// symlinks `/var` → `/private/var`, `/etc` → `/private/etc`, and
/// `/tmp` → `/private/tmp` at boot (see `doc/PLATFORM.md` §4.3). Any path
/// underneath an alias (e.g. `/var/folders/...`) is covered transitively by the
/// prefix rewrite, so it needs no dedicated entry.
///
/// The table is static and string-only on purpose: protected-path comparison
/// must work even for paths that do not exist on disk (a deletion target that
/// was just removed, a denied directory, a crafted bypass), so it must never
/// depend on a filesystem `readlink`/`canonicalize` call to establish the
/// equivalence.
pub const FIRMLINK_ALIASES: &[(&str, &str)] = &[
    ("/var", "/private/var"),
    ("/etc", "/private/etc"),
    ("/tmp", "/private/tmp"),
];

/// Rewrite a path's leading macOS firmlink alias to its canonical
/// `/private/...` form so that the alias and canonical spellings compare equal.
///
/// This is a pure string transform over [`FIRMLINK_ALIASES`]; it performs no
/// filesystem access and leaves non-firmlink paths untouched. Comparison is
/// component-aware: `/var` and `/var/folders` are rewritten, but a lookalike
/// such as `/variable` (which merely *starts with* the bytes of `/var`) is not.
#[must_use]
pub fn firmlink_canonical(path: &Path) -> PathBuf {
    PathBuf::from(normalize_firmlink_aliases(
        &path.as_os_str().to_string_lossy(),
    ))
}

#[must_use]
pub fn expand_tilde(path: &Path) -> PathBuf {
    let raw = path.as_os_str().to_string_lossy();
    if raw == "~" {
        return home_dir().unwrap_or_else(|| path.to_path_buf());
    }

    if let Some(rest) = raw.strip_prefix("~/")
        && let Some(home) = home_dir()
    {
        return home.join(rest);
    }

    path.to_path_buf()
}

#[must_use]
pub fn normalize_for_comparison(path: &Path) -> PathBuf {
    normalize_for_comparison_with_case(path, CaseMode::Preserve)
}

#[must_use]
pub fn normalize_for_case_insensitive_comparison(path: &Path) -> PathBuf {
    normalize_for_comparison_with_case(path, CaseMode::Fold)
}

fn normalize_for_comparison_with_case(path: &Path, case_mode: CaseMode) -> PathBuf {
    let expanded = expand_tilde(path);
    let mut cleaned = PathBuf::new();

    for component in expanded.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                cleaned.pop();
            }
            other => cleaned.push(other.as_os_str()),
        }
    }

    let normalized = cleaned
        .as_os_str()
        .to_string_lossy()
        .nfc()
        .collect::<String>();
    // Case-fold *before* firmlink rewriting. The firmlink table is spelled in
    // canonical lowercase, so applying it after folding lets an upper/mixed-case
    // alias (e.g. `/VAR/...` on a case-insensitive volume) canonicalize to the
    // same `/private/var/...` form as the protected root. Doing it the other way
    // round would leave `/VAR/...` un-rewritten while the `/var` root *was*
    // rewritten — an asymmetry a caller could exploit to dodge protection.
    match case_mode {
        CaseMode::Preserve => PathBuf::from(normalize_firmlink_aliases(&normalized)),
        CaseMode::Fold => PathBuf::from(normalize_firmlink_aliases(&normalized.to_lowercase())),
    }
}

#[must_use]
pub fn is_same_or_descendant(path: &Path, ancestor: &Path) -> bool {
    let path = normalize_for_comparison(path);
    let ancestor = normalize_for_comparison(ancestor);
    if path == ancestor || path.starts_with(&ancestor) {
        return true;
    }

    if should_compare_case_insensitive(&path, &ancestor) {
        let path = normalize_for_case_insensitive_comparison(&path);
        let ancestor = normalize_for_case_insensitive_comparison(&ancestor);
        path == ancestor || path.starts_with(ancestor)
    } else {
        false
    }
}

#[must_use]
pub fn comparison_candidates(path: &Path) -> Vec<PathBuf> {
    let base = expand_tilde(path);
    let mut candidates = vec![base.clone()];

    if let Ok(canonical) = fs::canonicalize(&base) {
        candidates.push(canonical);
    } else if let Some(parent) = base.parent()
        && let Ok(canonical_parent) = fs::canonicalize(parent)
        && let Some(name) = base.file_name()
    {
        candidates.push(canonical_parent.join(name));
    }

    candidates
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

/// Common macOS locations where developer CLIs live (`brew`, `npm`, a
/// Homebrew/pyenv `python3`, `MacPorts` `port`, ...).
///
/// A `.app` bundle launched from Finder or by `launchd` inherits only the
/// minimal `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`) — none of these dev
/// locations — so `brew`/`npm` fail to resolve and `python3` falls back to the
/// system `/usr/bin` copy instead of the user's Homebrew/pyenv one. These dirs
/// are prepended ahead of the inherited `PATH` so resolution matches a login
/// shell. Non-existent entries are harmless: callers stat before use.
fn common_tool_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = home_dir() {
        dirs.push(home.join(".local/bin"));
        dirs.push(home.join(".pyenv/shims"));
        dirs.push(home.join(".cargo/bin"));
    }
    for dir in [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/opt/local/bin",
        "/opt/local/sbin",
    ] {
        dirs.push(PathBuf::from(dir));
    }
    dirs
}

/// The process `PATH` with [`common_tool_dirs`] prepended (de-duplicated,
/// original order preserved for the inherited entries).
///
/// Pass this as the child's `PATH` when spawning developer tools so a
/// GUI-launched app resolves them the same way the user's terminal would.
#[must_use]
pub fn augmented_path() -> OsString {
    let mut seen = HashSet::new();
    let mut dirs: Vec<PathBuf> = Vec::new();
    for dir in common_tool_dirs() {
        if seen.insert(dir.clone()) {
            dirs.push(dir);
        }
    }
    if let Some(existing) = env::var_os("PATH") {
        for dir in env::split_paths(&existing) {
            if seen.insert(dir.clone()) {
                dirs.push(dir);
            }
        }
    }
    env::join_paths(&dirs).unwrap_or_else(|_| env::var_os("PATH").unwrap_or_default())
}

/// First executable match for `bin` on the [`augmented_path`], if any.
///
/// Used both to detect a tool's presence and to resolve it to an absolute path
/// so a spawn never depends on the (stripped) inherited `PATH`.
#[must_use]
pub fn find_executable(bin: &str) -> Option<PathBuf> {
    for dir in env::split_paths(&augmented_path()) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn normalize_firmlink_aliases(path: &str) -> String {
    for &(alias, canonical) in FIRMLINK_ALIASES {
        if path == alias {
            return canonical.to_owned();
        }
        if let Some(rest) = path.strip_prefix(&format!("{alias}/")) {
            return format!("{canonical}/{rest}");
        }
    }

    path.to_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseMode {
    Preserve,
    Fold,
}

fn should_compare_case_insensitive(path: &Path, ancestor: &Path) -> bool {
    case_variant_resolves(path)
        || case_variant_resolves(ancestor)
        || nearest_existing_case_variant_resolves(path)
        || nearest_existing_case_variant_resolves(ancestor)
        || case_behavior_unknown(path)
        || case_behavior_unknown(ancestor)
}

fn case_variant_resolves(path: &Path) -> bool {
    let Some(variant) = case_variant_path(path) else {
        return false;
    };

    variant != path && fs::metadata(&variant).is_ok()
}

fn nearest_existing_case_variant_resolves(path: &Path) -> bool {
    nearest_existing_path(path).is_some_and(|existing| case_variant_resolves(&existing))
}

fn case_behavior_unknown(path: &Path) -> bool {
    nearest_existing_path(path).is_none_or(|existing| existing.components().count() <= 1)
}

fn nearest_existing_path(path: &Path) -> Option<PathBuf> {
    let expanded = expand_tilde(path);
    expanded
        .ancestors()
        .find(|candidate| fs::metadata(candidate).is_ok())
        .map(Path::to_path_buf)
}

fn case_variant_path(path: &Path) -> Option<PathBuf> {
    let mut variant = PathBuf::new();
    let mut changed = false;

    for component in path.components() {
        match component {
            Component::Normal(value) => {
                let text = value.to_string_lossy();
                let toggled = toggle_ascii_case(&text);
                changed |= toggled != text;
                variant.push(toggled);
            }
            other => variant.push(other.as_os_str()),
        }
    }

    changed.then_some(variant)
}

fn toggle_ascii_case(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_lowercase() {
                ch.to_ascii_uppercase()
            } else if ch.is_ascii_uppercase() {
                ch.to_ascii_lowercase()
            } else {
                ch
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_check_does_not_use_string_prefix() {
        assert!(!is_same_or_descendant(
            Path::new("/Users/alice/Documents-old"),
            Path::new("/Users/alice/Documents"),
        ));
    }

    #[test]
    fn comparison_uses_detected_case_behavior_for_existing_volume() {
        let temp = tempfile::tempdir().expect("tempdir");
        let protected = temp.path().join("Protected");
        std::fs::create_dir(&protected).expect("protected dir");
        let mismatched = temp.path().join("protected").join("cache");

        if nearest_existing_case_variant_resolves(&protected) {
            assert!(is_same_or_descendant(&mismatched, &protected));
        } else {
            assert!(!is_same_or_descendant(&mismatched, &protected));
        }
    }

    #[test]
    fn comparison_falls_back_to_case_insensitive_for_unknown_volume_paths() {
        assert!(is_same_or_descendant(
            Path::new("/MissingVolume/USERS/ALICE/Documents/cache"),
            Path::new("/MissingVolume/Users/Alice/Documents"),
        ));
    }

    #[test]
    fn firmlink_aliases_compare_equal() {
        assert!(is_same_or_descendant(
            Path::new("/var/db/example"),
            Path::new("/private/var"),
        ));
    }

    #[test]
    fn firmlink_canonical_rewrites_each_alias() {
        assert_eq!(
            firmlink_canonical(Path::new("/var")),
            PathBuf::from("/private/var")
        );
        assert_eq!(
            firmlink_canonical(Path::new("/var/folders/zz/x")),
            PathBuf::from("/private/var/folders/zz/x")
        );
        assert_eq!(
            firmlink_canonical(Path::new("/etc/hosts")),
            PathBuf::from("/private/etc/hosts")
        );
        assert_eq!(
            firmlink_canonical(Path::new("/tmp/scratch")),
            PathBuf::from("/private/tmp/scratch")
        );
    }

    #[test]
    fn firmlink_canonical_is_boundary_aware_and_idempotent() {
        // Lookalikes that merely share a byte prefix must be left untouched.
        for path in ["/variable", "/etcd", "/tmpfoo", "/private/var/x"] {
            assert_eq!(
                firmlink_canonical(Path::new(path)),
                PathBuf::from(path),
                "{path}"
            );
        }
        // Already-canonical input is a fixed point.
        let canonical = firmlink_canonical(Path::new("/var/folders"));
        assert_eq!(firmlink_canonical(&canonical), canonical);
    }

    #[test]
    fn case_folded_alias_canonicalizes_like_lowercase_alias() {
        // Regression: firmlink rewriting must happen after case folding so an
        // upper/mixed-case alias resolves to the same protected location.
        assert!(is_same_or_descendant(
            Path::new("/VAR/folders/zz/x"),
            Path::new("/private/var"),
        ));
        assert!(is_same_or_descendant(
            Path::new("/Private/Var/folders/zz/x"),
            Path::new("/var"),
        ));
    }

    #[test]
    fn firmlink_table_entries_are_distinct_and_canonical() {
        for &(alias, canonical) in FIRMLINK_ALIASES {
            assert_ne!(alias, canonical);
            assert!(canonical.starts_with("/private/"));
            assert!(!alias.contains("/private/"));
        }
    }

    #[test]
    fn comparison_candidates_include_canonical_parent_for_missing_leaf() {
        let temp = tempfile::tempdir().expect("tempdir");
        let real = temp.path().join("real");
        std::fs::create_dir(&real).expect("real dir");
        let link = temp.path().join("link");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        #[cfg(not(unix))]
        return;

        let candidates = comparison_candidates(&link.join("missing"));
        assert!(
            candidates
                .iter()
                .any(|path| is_same_or_descendant(path, &real.join("missing")))
        );
    }

    #[test]
    fn augmented_path_prepends_common_tool_dirs() {
        let path = augmented_path();
        let dirs: Vec<PathBuf> = env::split_paths(&path).collect();
        // Homebrew's default bin must be present even when the inherited PATH
        // (a Finder/launchd bundle's minimal one) never listed it.
        assert!(
            dirs.iter().any(|dir| dir == Path::new("/opt/homebrew/bin")),
            "augmented PATH should include /opt/homebrew/bin: {dirs:?}"
        );
        // MacPorts and the system bin are both reachable.
        assert!(dirs.iter().any(|dir| dir == Path::new("/opt/local/bin")));
    }

    #[test]
    fn augmented_path_has_no_duplicate_entries() {
        let path = augmented_path();
        let dirs: Vec<PathBuf> = env::split_paths(&path).collect();
        let unique: HashSet<&PathBuf> = dirs.iter().collect();
        assert_eq!(
            unique.len(),
            dirs.len(),
            "PATH entries should be de-duplicated"
        );
    }
}
