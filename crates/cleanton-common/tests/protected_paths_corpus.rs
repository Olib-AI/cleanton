//! Safety release-gate corpus: `ProtectedPaths` bypass resistance (SAFETY Layer 1).
//!
//! An adversarial table of paths that must NEVER be deletable, spelled in every
//! equivalent-but-alternate form (system roots, firmlink `/var` vs `/private/var`,
//! case variants, NFC/NFD Unicode), plus the user-scoped protected set resolved
//! through `$HOME`, and a boundary corpus of lookalikes that must NOT be falsely
//! protected. Exercises the public `ProtectedPaths` API end-to-end.

use std::path::{Path, PathBuf};

use cleanton_common::ProtectedPaths;
use cleanton_common::paths::expand_tilde;

/// System roots and firmlink/case variants that the hardcoded defaults must protect,
/// independent of `$HOME`.
const HARD_PROTECTED: &[&str] = &[
    // Canonical system roots and nested children.
    "/System",
    "/System/Library/Caches/com.example",
    "/Library",
    "/Library/Frameworks",
    "/usr",
    "/usr/local/bin",
    "/bin",
    "/sbin",
    "/private",
    "/etc",
    "/etc/passwd",
    "/var",
    "/var/folders/zz/cleanton",
    "/Applications",
    "/Applications/Safari.app/Contents",
    // Firmlink equivalence: alias and canonical forms of the SAME location.
    "/private/var/folders/zz/cleanton",
    "/private/etc/passwd",
    "/tmp/scratch",
    "/private/tmp/scratch",
    // Case variants on a case-insensitive volume.
    "/SYSTEM",
    "/system/Library",
    "/LIBRARY/Frameworks",
    "/USR/bin",
    "/Bin",
    "/APPLICATIONS/Safari.app",
    "/VAR/folders/zz/x",
    "/Private/Var/folders/zz/x",
    // Normalization: trailing slash, `.`, redundant separators, harmless `..`.
    "/System/",
    "/System/./Library",
    "/System/Library/../Frameworks",
    "/usr//local//bin",
    "/var/../var/folders/zz/x",
];

/// Lookalikes that share a byte prefix with a protected root but are NOT inside it.
const NOT_PROTECTED: &[&str] = &[
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
    "/System/../opt/cache",
];

/// User-scoped protected locations (credentials, mail, user documents), spelled
/// with `~` and resolved through `$HOME`.
const USER_PROTECTED_PATHS: &[&str] = &[
    "~/.ssh/id_rsa",
    "~/.gnupg/secring.gpg",
    "~/.aws/credentials",
    "~/.azure/accessTokens.json",
    "~/.config/gcloud/credentials.db",
    "~/.config/cleanton/config.toml",
    "~/.kube/config",
    "~/.docker/config.json",
    "~/.npmrc",
    "~/.pypirc",
    "~/.netrc",
    "~/Library/Keychains/login.keychain-db",
    "~/Library/Mail/V10/MailData",
    "~/Library/Messages/chat.db",
    "~/Library/Containers/com.example.app/Data",
    "~/Library/Group Containers/group.com.example/db",
    "~/Desktop/notes.txt",
    "~/Documents/tax-return.pdf",
    "~/Downloads/installer.dmg",
    "~/Pictures/family.jpg",
    "~/Music/track.flac",
    "~/Movies/clip.mov",
];

#[test]
fn system_roots_and_equivalent_spellings_are_always_protected() {
    let protected = ProtectedPaths::defaults();
    for path in HARD_PROTECTED {
        assert!(
            protected.is_protected(Path::new(path)),
            "must be protected: {path}"
        );
    }
}

#[test]
fn lookalike_paths_are_not_falsely_protected() {
    let protected = ProtectedPaths::defaults();
    for path in NOT_PROTECTED {
        assert!(
            !protected.is_protected(Path::new(path)),
            "must NOT be protected (boundary correctness): {path}"
        );
    }
}

#[test]
fn firmlink_var_target_is_caught_by_private_var_protection() {
    // PLATFORM §9: a `/var/...` target must be caught by the `/private/var` rule,
    // and the reverse, for a user-configured root in either spelling.
    let via_private = ProtectedPaths::new([PathBuf::from("/private/var/myapp/state")]);
    assert!(via_private.is_protected(Path::new("/var/myapp/state/db")));

    let via_alias = ProtectedPaths::new([PathBuf::from("/var/other/state")]);
    assert!(via_alias.is_protected(Path::new("/private/var/other/state/db")));
}

#[test]
fn unicode_nfc_and_nfd_forms_cannot_bypass_protection() {
    // é as a single codepoint (NFC) vs `e` + COMBINING ACUTE ACCENT (NFD).
    let nfc = "/Users/alice/Caf\u{e9}";
    let nfd = "/Users/alice/Cafe\u{301}";

    let stored_composed = ProtectedPaths::new([PathBuf::from(nfc)]);
    assert!(
        stored_composed.is_protected(Path::new(&format!("{nfd}/cache"))),
        "NFD target must be caught by NFC-stored protection"
    );

    let stored_decomposed = ProtectedPaths::new([PathBuf::from(nfd)]);
    assert!(
        stored_decomposed.is_protected(Path::new(&format!("{nfc}/cache"))),
        "NFC target must be caught by NFD-stored protection"
    );
}

#[test]
fn user_scoped_protected_paths_resolve_through_home() {
    // Skip only if the environment has no HOME (never the case on a dev/CI host).
    if std::env::var_os("HOME").is_none() {
        return;
    }
    let protected = ProtectedPaths::defaults();
    for raw in USER_PROTECTED_PATHS {
        let path = expand_tilde(Path::new(raw));
        assert!(
            protected.is_protected(&path),
            "user-scoped path must be protected: {raw} -> {}",
            path.display()
        );
    }

    // A sibling that merely shares a prefix with a protected user dir is NOT protected.
    let documents_lookalike = expand_tilde(Path::new("~/Documents-archive/old.txt"));
    assert!(
        !protected.is_protected(&documents_lookalike),
        "~/Documents-archive must not be inside ~/Documents"
    );
}

#[test]
fn case_variant_of_user_configured_root_is_protected() {
    // KEYCHAINS == Keychains on a case-insensitive volume. A path on a
    // non-existent volume exercises the comparator's documented "unknown case
    // behaviour" fallback (compare case-insensitively), so the assertion is
    // deterministic on case-sensitive and case-insensitive runners alike.
    let protected = ProtectedPaths::new([PathBuf::from("/CleantonTestVol/Library/Keychains")]);
    assert!(protected.is_protected(Path::new(
        "/cleantontestvol/library/keychains/login.keychain-db"
    )));
}
