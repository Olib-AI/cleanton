"""Grounded-labeler tests against the REAL recipe corpus."""

import pytest

from training import labeler as L
from training.fstree import build_root, node_to_sample
from training.labeler import KEEP, LIKELY_JUNK, SAFE_TO_REMOVE, UNCERTAIN, TreeLabeler
from training.recipes_dsl import load_recipes

MB = 1024 * 1024
GB = 1024 * MB


@pytest.fixture(scope="module")
def recipes():
    return load_recipes()


def build_world():
    root = build_root()
    home = root.dir("Users").dir("dev")
    home.age_days = 300.0

    # Rust project with full evidence and a big, old-enough target.
    code = home.dir("code", age_days=100.0)
    app = code.dir("acme-api", age_days=5.0)
    app.file("Cargo.toml", 900, 5.0)
    app.file("Cargo.lock", 60_000, 5.0)
    app.file(".gitignore", 120, 30.0)
    src = app.dir("src")
    src.file("main.rs", 6_000, 2.0)
    src.file("lib.rs", 9_000, 4.0)
    git = app.dir(".git")
    git.file("HEAD", 23, 1.0)
    git.dir("objects").dir("pack").file("pack-1.pack", 30 * MB, 5.0)
    target = app.dir("target", age_days=6.0)
    deps = target.dir("debug").dir("deps")
    deps.file("libserde-1.rlib", 30 * MB, 6.0)
    deps.file("libtokio-1.rlib", 40 * MB, 6.0)
    # A credential accidentally inside the removable tree.
    target.dir("debug").file(".env", 200, 6.0)

    # Loose target: no Cargo.toml anywhere near.
    scratch = home.dir("scratch", age_days=90.0)
    loose = scratch.dir("target", age_days=90.0)
    loose.file("results.csv", 30 * MB, 90.0)

    # Credentials.
    ssh = home.dir(".ssh", age_days=400.0)
    ssh.file("id_rsa", 3_000, 400.0)

    # Claude: statsig cache vs excluded transcripts.
    claude = home.dir(".claude", age_days=60.0)
    claude.file(".credentials.json", 500, 10.0)
    claude.dir("statsig").file("statsig.cached.evaluations.2", 300_000, 30.0)
    claude.dir("projects").dir("-Users-dev-code-acme").file("t.jsonl", 2 * MB, 3.0)

    # Documents with a node project inside (protected).
    docs = home.dir("Documents", age_days=200.0)
    web = docs.dir("old-site", age_days=500.0)
    web.file("package.json", 700, 500.0)
    nm = web.dir("node_modules", age_days=500.0)
    nm.dir("react").file("index.js", 20 * MB, 500.0)

    # Node project with evidence.
    webapp = code.dir("web-portal", age_days=3.0)
    webapp.file("package.json", 1_500, 3.0)
    webapp.file("package-lock.json", 300_000, 3.0)
    webapp.file(".gitignore", 100, 20.0)
    wnm = webapp.dir("node_modules", age_days=4.0)
    for pkg in ("react", "lodash", "axios", "vite"):
        wnm.dir(pkg).file("index.js", 5 * MB, 4.0)

    root.freeze()
    return root, home


def labels_for(root, recipes):
    return TreeLabeler(root, recipes).label_tree()


def test_floor_dominates_everything(recipes):
    root, home = build_world()
    labels = labels_for(root, recipes)
    assert labels[f"{home.path}/.ssh/id_rsa"][0] == KEEP
    assert labels[f"{home.path}/.claude/.credentials.json"][0] == KEEP
    # Everything under Documents is protected, even node_modules.
    assert labels[f"{home.path}/Documents/old-site/node_modules"][0] == KEEP
    assert labels[f"{home.path}/Documents/old-site/node_modules/react/index.js"][0] == KEEP


def test_rust_target_with_evidence_is_safe_to_remove(recipes):
    root, home = build_world()
    labels = labels_for(root, recipes)
    label, reason = labels[f"{home.path}/code/acme-api/target"]
    assert label == SAFE_TO_REMOVE, reason
    # Descendants inherit the cleanable label.
    label, reason = labels[f"{home.path}/code/acme-api/target/debug/deps/libserde-1.rlib"]
    assert label == SAFE_TO_REMOVE and reason.startswith("inside-matched")


def test_sensitive_basename_inside_matched_tree_stays_keep(recipes):
    root, home = build_world()
    labels = labels_for(root, recipes)
    assert labels[f"{home.path}/code/acme-api/target/debug/.env"][0] == KEEP


def test_node_modules_with_evidence_is_safe_to_remove(recipes):
    root, home = build_world()
    labels = labels_for(root, recipes)
    label, reason = labels[f"{home.path}/code/web-portal/node_modules"]
    assert label == SAFE_TO_REMOVE, reason


def test_loose_target_is_near_miss_uncertain(recipes):
    root, home = build_world()
    labels = labels_for(root, recipes)
    label, reason = labels[f"{home.path}/scratch/target"]
    assert label == UNCERTAIN
    assert reason.startswith("near-miss")


def test_source_and_git_internals_are_keep(recipes):
    root, home = build_world()
    labels = labels_for(root, recipes)
    assert labels[f"{home.path}/code/acme-api/src/main.rs"][0] == KEEP
    assert labels[f"{home.path}/code/acme-api/Cargo.toml"][0] == KEEP
    label, reason = labels[f"{home.path}/code/acme-api/.git/objects/pack/pack-1.pack"]
    assert label == KEEP and reason == "git-internals"


def test_claude_statsig_cleanable_but_transcripts_keep(recipes):
    root, home = build_world()
    labels = labels_for(root, recipes)
    statsig_label, statsig_reason = labels[f"{home.path}/.claude/statsig/statsig.cached.evaluations.2"]
    assert statsig_label in (SAFE_TO_REMOVE, LIKELY_JUNK), statsig_reason
    transcript_label, transcript_reason = labels[f"{home.path}/.claude/projects/-Users-dev-code-acme/t.jsonl"]
    assert transcript_label == KEEP
    assert transcript_reason.startswith(("recipe-exclude", "protected"))


def test_labels_never_hand_set_everything_covered(recipes):
    root, _home = build_world()
    labels = labels_for(root, recipes)
    named_nodes = [n for n in root.walk() if n.name]
    assert len(labels) == len(named_nodes)
    assert set(v[0] for v in labels.values()) <= {KEEP, SAFE_TO_REMOVE, LIKELY_JUNK, UNCERTAIN}


def test_context_derived_from_tree_not_sampled():
    root, home = build_world()
    app = home.children["code"].children["acme-api"]
    target = app.children["target"]
    sample = node_to_sample(target)
    # Parent (the project) really has a lockfile and gitignore.
    assert sample.has_lockfile and sample.has_gitignore
    assert sample.ancestor_has_lockfile and sample.ancestor_has_project_marker
    assert sample.sibling_count == len(app.children)
    # Directory size aggregates the subtree, like the scanner.
    assert sample.size_bytes >= 70 * MB
    loose = home.children["scratch"].children["target"]
    loose_sample = node_to_sample(loose)
    assert not loose_sample.has_lockfile
    assert not loose_sample.ancestor_has_project_marker


def test_label_names_order_matches_engine():
    assert L.LABEL_NAMES == ("keep", "safe-to-remove", "likely-junk", "uncertain")
    assert KEEP == 0 and SAFE_TO_REMOVE == 1 and LIKELY_JUNK == 2 and UNCERTAIN == 3


def test_higher_priority_recipe_wins_like_the_engine():
    """analyzer.rs sorts by Reverse(priority) and takes the FIRST match; a
    lower-priority safe recipe must not override a higher-priority cautious
    one (regression: the labeler used to always prefer the safest claim)."""
    from training.recipes_dsl import MatchSpec, Recipe

    def recipe(rid, level, priority):
        return Recipe(
            id=rid, category="t", safety_level=level, enabled=True,
            priority=priority,
            specs=(MatchSpec(directory_name="blobcache",
                             parent_must_contain=("marker.txt",)),),
        )

    root = build_root()
    home = root.dir("Users").dir("dev")
    home.age_days = 100.0
    box = home.dir("box", age_days=50.0)
    box.file("marker.txt", 10, 50.0)
    cache = box.dir("blobcache", age_days=50.0)
    cache.file("a.bin", 5 * MB, 50.0)
    root.freeze()

    high_cautious = recipe("high-cautious", "cautious", 90)
    low_safe = recipe("low-safe", "safe", 50)
    labels = TreeLabeler(root, [low_safe, high_cautious]).label_tree()
    label, reason = labels[f"{home.path}/box/blobcache"]
    assert label == LIKELY_JUNK and reason == "recipe:high-cautious"
    # Equal priority falls back to the safest claim (tie order in builtin.rs
    # is a Rust source artifact the mirror cannot cheaply reproduce).
    tied = recipe("tied-cautious", "cautious", 50)
    labels = TreeLabeler(root, [tied, low_safe]).label_tree()
    label, reason = labels[f"{home.path}/box/blobcache"]
    assert label == SAFE_TO_REMOVE and reason == "recipe:low-safe"


def test_broad_reroute_excludes_do_not_manufacture_keeps(recipes):
    """ml-checkpoints excludes ~/.cache/** only to route attribution to the
    dedicated cache recipes; unmatched ~/.cache paths must stay uncertain,
    not become author-declared keeps (regression)."""
    root = build_root()
    home = root.dir("Users").dir("dev")
    home.age_days = 300.0
    cache = home.dir(".cache", age_days=200.0)
    uv = cache.dir("uv").dir("wheels-v1")
    uv.file("stray.whl", 3 * MB, 40.0)
    root.freeze()
    labels = labels_for(root, recipes)
    label, reason = labels[f"{home.path}/.cache/uv/wheels-v1/stray.whl"]
    assert not reason.startswith("recipe-exclude"), reason
    assert label in (UNCERTAIN, SAFE_TO_REMOVE, LIKELY_JUNK), reason
    # Anchored-selector excludes still declare keeps: poetry's live venvs.
    root2 = build_root()
    home2 = root2.dir("Users").dir("dev")
    home2.age_days = 300.0
    venv = home2.dirs("Library", "Caches", "pypoetry", "virtualenvs", "app-abc123-py3.12")
    venv.file("pyvenv.cfg", 250, 5.0)
    root2.freeze()
    labels2 = labels_for(root2, recipes)
    label2, reason2 = labels2[f"{home2.path}/Library/Caches/pypoetry/virtualenvs/app-abc123-py3.12"]
    assert label2 == KEEP and reason2.startswith("recipe-exclude"), (label2, reason2)


def test_newest_age_includes_the_directory_itself(recipes):
    """The engine's newest_subtree_mtimes includes the directory's own mtime
    (ancestors() yields the path itself), so a freshly-touched dir full of old
    files must NOT clear a min_age_days gate (regression)."""
    from training.recipes_dsl import MatchSpec, Recipe

    aged = Recipe(
        id="aged-cache", category="t", safety_level="cautious", enabled=True,
        priority=50,
        specs=(MatchSpec(directory_name="stalecache",
                         parent_must_contain=("marker.txt",),
                         min_age_days=30),),
    )
    root = build_root()
    home = root.dir("Users").dir("dev")
    home.age_days = 100.0
    box = home.dir("box", age_days=90.0)
    box.file("marker.txt", 10, 90.0)
    fresh_dir = box.dir("stalecache", age_days=1.0)  # dir touched yesterday
    fresh_dir.file("old.bin", MB, 400.0)             # contents are ancient
    root.freeze()
    assert fresh_dir.newest_age_days() == 1.0
    labels = TreeLabeler(root, [aged]).label_tree()
    label, reason = labels[f"{home.path}/box/stalecache"]
    assert label == UNCERTAIN and reason.startswith("near-miss"), (label, reason)
