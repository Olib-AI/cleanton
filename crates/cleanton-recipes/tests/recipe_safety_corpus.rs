//! Safety release-gate corpus: recipe matcher safety floor (SAFETY Layers 1, 2, 7).
//!
//! Adversarial proof, exercised through the PUBLIC matcher API, that:
//!   * NO enabled built-in recipe matches any protected, credential, or
//!     user-document path (negative corpus), and
//!   * canonical regenerable caches with the required on-disk context proof ARE
//!     matched (positive corpus), and
//!   * the sensitive-basename floor refuses a credential even inside a directory
//!     a recipe would otherwise clean.

// Integration-test crate: setup helpers (outside `#[test]` fns, so not covered by
// clippy.toml's `allow-expect-in-tests`) use `.expect()` on fixture I/O.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use cleanton_common::paths::expand_tilde;
use cleanton_common::{FileEntry, FileKind};
use cleanton_recipes::{RecipeDocument, RecipeSet, action_for_entry, recipe_matches_entry};

/// Sixty-four MiB: comfortably above every built-in `min_size_mb` gate, so a
/// candidate is never rejected merely for being too small.
const LARGE_BYTES: u64 = 64 * 1_048_576;

fn entry(path: impl Into<PathBuf>, kind: FileKind, allocated_bytes: u64) -> FileEntry {
    FileEntry {
        path: path.into(),
        kind,
        logical_bytes: allocated_bytes,
        allocated_bytes,
        modified: Some(SystemTime::now() - Duration::from_hours(720)),
        depth: 6,
        device_id: None,
        inode: None,
        hardlink_count: None,
        symlink_target: None,
        ignored_by_git: false,
    }
}

/// Paths that no recipe may ever plan an action against, each fully qualified.
fn negative_corpus() -> Vec<(PathBuf, FileKind)> {
    let mut items: Vec<(PathBuf, FileKind)> = vec![
        // System roots and firmlink/case variants.
        (
            "/System/Library/Caches/com.example".into(),
            FileKind::Directory,
        ),
        ("/Library/Caches/whatever".into(), FileKind::Directory),
        ("/usr/local/lib/node_modules".into(), FileKind::Directory),
        ("/private/var/folders/zz/target".into(), FileKind::Directory),
        ("/var/folders/zz/target".into(), FileKind::Directory),
        ("/VAR/folders/zz/__pycache__/x.pyc".into(), FileKind::File),
        ("/Applications/Xcode.app/target".into(), FileKind::Directory),
    ];

    // Credential / secret / settings basenames, placed inside otherwise-cleanable
    // directories so that only the safety floor can be the reason for rejection.
    for name in [
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        ".credentials.json",
        "id_rsa",
        "id_ed25519",
        "kubeconfig",
        "secrets.yaml",
        "service-account.json",
        "settings.json",
        "settings.local.json",
        "mcp.json",
        ".mcp.json",
    ] {
        items.push((
            PathBuf::from(format!("/Users/dev/project/cache/{name}")),
            FileKind::File,
        ));
        items.push((
            PathBuf::from(format!("/Users/dev/project/__pycache__/{name}")),
            FileKind::File,
        ));
    }

    // User documents and personal media, resolved through $HOME.
    for (raw, kind) in [
        ("~/Documents/project/target", FileKind::Directory),
        ("~/Documents/tax-return.pdf", FileKind::File),
        ("~/Desktop/project/node_modules", FileKind::Directory),
        ("~/Downloads/project/dist", FileKind::Directory),
        ("~/Pictures/checkpoints/model.ckpt", FileKind::File),
        ("~/Movies/render/__pycache__/x.pyc", FileKind::File),
        ("~/Library/Keychains/login.keychain-db", FileKind::File),
        ("~/Library/Messages/chat.db", FileKind::File),
        ("~/.ssh/id_rsa", FileKind::File),
        ("~/.aws/credentials", FileKind::File),
    ] {
        items.push((expand_tilde(Path::new(raw)), kind));
    }

    items
}

#[test]
fn no_builtin_recipe_matches_any_protected_or_credential_path() {
    let recipes = RecipeSet::load_builtin().expect("built-in recipes validate");
    for (path, kind) in negative_corpus() {
        let candidate = entry(path.clone(), kind, LARGE_BYTES);
        for recipe in recipes.iter().filter(|recipe| recipe.recipe.enabled) {
            assert!(
                !recipe_matches_entry(recipe, &candidate),
                "built-in recipe {:?} must NOT match safety-critical path {}",
                recipe.recipe.id,
                path.display(),
            );
            assert!(
                action_for_entry(recipe, &candidate).is_none(),
                "built-in recipe {:?} must NOT plan an action for {}",
                recipe.recipe.id,
                path.display(),
            );
        }
    }
}

#[test]
fn sensitive_basename_floor_refuses_credentials_inside_a_cleanable_dir() {
    // The python bytecode recipe (`**/__pycache__/**`, no context proof, no size
    // gate) is the most permissive built-in. Even so, a credential dropped inside
    // a __pycache__ directory is refused, while a real .pyc sibling is cleaned.
    let recipes = RecipeSet::load_builtin().expect("built-in recipes validate");
    let python = recipes
        .iter()
        .find(|recipe| recipe.recipe.id == "python-bytecode")
        .expect("python-bytecode recipe is built in");

    let pycache = PathBuf::from("/Users/dev/api/__pycache__");

    // The benign bytecode file IS cleaned.
    let benign = entry(pycache.join("module.cpython-311.pyc"), FileKind::File, 2048);
    assert!(
        action_for_entry(python, &benign).is_some(),
        "a regenerable .pyc inside __pycache__ should be cleanable"
    );

    // Every credential basename in the SAME cleanable directory is refused.
    for name in [
        ".env",
        "credentials.json",
        ".credentials.json",
        "id_rsa",
        "settings.json",
        "mcp.json",
        ".mcp.json",
    ] {
        let secret = entry(pycache.join(name), FileKind::File, 2048);
        assert!(
            !recipe_matches_entry(python, &secret),
            "sensitive basename {name} must be refused by the matcher floor"
        );
        assert!(
            action_for_entry(python, &secret).is_none(),
            "sensitive basename {name} must never yield a planned action"
        );
    }
}

/// Build a project on disk with the given context-proof marker file, returning the
/// path to the (synthetic) artifact directory whose parent holds the marker.
fn project_with_marker(root: &Path, project: &str, marker: &str, artifact: &str) -> PathBuf {
    let project_dir = root.join(project);
    std::fs::create_dir_all(&project_dir).expect("create project dir");
    std::fs::write(project_dir.join(marker), b"marker").expect("write marker");
    project_dir.join(artifact)
}

#[test]
fn canonical_regenerable_caches_are_matched_with_context_proof() {
    let recipes = RecipeSet::load_builtin().expect("built-in recipes validate");
    // Markers must exist on disk: `recipe_matches_entry` resolves `parent_must_contain`
    // against the real filesystem. Build under the crate dir (NOT $TMPDIR, which is
    // under the protected /private/var on macOS).
    let temp = tempfile::Builder::new()
        .prefix("cleanton-recipes-positive-")
        .tempdir_in(std::env::current_dir().expect("cwd"))
        .expect("tempdir");
    let root = temp.path();

    // Rust target/ next to a Cargo.toml.
    let rust_target = project_with_marker(root, "rustproj", "Cargo.toml", "target");
    let rust_entry = entry(&rust_target, FileKind::Directory, LARGE_BYTES);

    // node_modules/ next to a package.json.
    let node_modules = project_with_marker(root, "webproj", "package.json", "node_modules");
    let node_entry = entry(&node_modules, FileKind::Directory, LARGE_BYTES);

    // __pycache__ bytecode (no context proof or size gate required).
    let pycache_file = root.join("api/__pycache__/mod.cpython-311.pyc");
    let py_entry = entry(&pycache_file, FileKind::File, 4096);

    // Gradle build/ proven by the any-of manifest markers (Kotlin DSL here).
    let gradle_build = project_with_marker(root, "androidproj", "build.gradle.kts", "build");
    let gradle_entry = entry(&gradle_build, FileKind::Directory, LARGE_BYTES);

    // Hugging Face Trainer checkpoint dir proven by the trainer_state.json
    // *inside* the matched directory (ml-checkpoints' `[[match.any_of]]` shape).
    let hf_checkpoint = root.join("mlproj/output/checkpoint-500");
    std::fs::create_dir_all(&hf_checkpoint).expect("create checkpoint dir");
    let trainer_state = hf_checkpoint.join("trainer_state.json");
    std::fs::write(&trainer_state, b"{}").expect("write trainer_state.json");
    // Backdate: the recipe's min_age_days probes real subtree mtimes.
    let a_month_ago_ckpt = SystemTime::now() - Duration::from_hours(31 * 24);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&trainer_state)
        .and_then(|file| file.set_modified(a_month_ago_ckpt))
        .expect("backdate trainer_state.json");
    let checkpoint_entry = entry(&hf_checkpoint, FileKind::Directory, 256 * 1_048_576);

    // Loose Lightning-style .ckpt checkpoint file (ml-checkpoints' primary spec).
    let ckpt_file = root.join("mlproj/lightning_logs/version_0/checkpoints/epoch=9.ckpt");
    let ckpt_entry = entry(&ckpt_file, FileKind::File, 256 * 1_048_576);

    // CMake build/ proven by the CMakeCache.txt *inside* the matched directory.
    let cmake_build = root.join("nativeproj/build");
    std::fs::create_dir_all(&cmake_build).expect("create cmake build dir");
    let cmake_cache = cmake_build.join("CMakeCache.txt");
    std::fs::write(&cmake_cache, b"marker").expect("write CMakeCache.txt");
    // Backdate the on-disk tree: the recipe's min_age_days probes real subtree
    // mtimes, and a freshly written marker would otherwise look "in use".
    let a_month_ago = SystemTime::now() - Duration::from_hours(31 * 24);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&cmake_cache)
        .and_then(|file| file.set_modified(a_month_ago))
        .expect("backdate CMakeCache.txt");
    let cmake_entry = entry(&cmake_build, FileKind::Directory, LARGE_BYTES);

    let expectations: [(&FileEntry, &str); 7] = [
        (&rust_entry, "rust-target-dirs"),
        (&node_entry, "node-modules"),
        (&py_entry, "python-bytecode"),
        (&gradle_entry, "jvm-gradle-build-dirs"),
        (&cmake_entry, "cmake-build-dirs"),
        (&checkpoint_entry, "ml-checkpoints"),
        (&ckpt_entry, "ml-checkpoints"),
    ];

    for (candidate, expected_id) in expectations {
        let matched: Vec<&RecipeDocument> = recipes
            .iter()
            .filter(|recipe| recipe.recipe.enabled && recipe_matches_entry(recipe, candidate))
            .collect();
        let recipe = matched
            .iter()
            .find(|recipe| recipe.recipe.id == expected_id)
            .unwrap_or_else(|| {
                panic!(
                    "{} should be matched by recipe {expected_id}, matched: {:?}",
                    candidate.path.display(),
                    matched.iter().map(|r| &r.recipe.id).collect::<Vec<_>>(),
                )
            });
        let action = action_for_entry(recipe, candidate).expect("action produced");
        assert_eq!(action.target, candidate.path);
    }
}
