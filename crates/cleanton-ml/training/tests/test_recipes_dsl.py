"""Recipe DSL mirror tests: glob semantics, guards, any_of, floors, and a
corpus-wide fixture validation identical to the Rust validator harness."""

import pytest

from training import recipes_dsl as dsl
from training.recipes_dsl import (
    Entry,
    KIND_DIRECTORY,
    KIND_FILE,
    MB,
    MatchSpec,
    Recipe,
    glob_matches,
    load_recipes,
    recipe_matches,
    spec_matches,
    synthetic_fixture_entry,
)

HOME = "/Users/dev"
ALWAYS = lambda _d, _m: True  # noqa: E731
NEVER = lambda _d, _m: False  # noqa: E731


def make_recipe(*specs: MatchSpec, safety: str = "safe") -> Recipe:
    return Recipe(
        id="test", category="test", safety_level=safety, enabled=True,
        priority=50, specs=tuple(specs),
    )


# --- Glob semantics (mirror of matcher.rs documented defaults) ---------------------

def test_star_spans_separators():
    assert glob_matches("**/*.ckpt", "/Users/dev/projects/ml/last.ckpt")
    assert glob_matches("**/checkpoint-*", "/Users/dev/ml/out/checkpoint-500/nested/file.bin")
    assert not glob_matches("**/*.pt", "/Users/dev/slides/report.ppt")
    # `*` also spans `/` (require_literal_separator = false).
    assert glob_matches("dir/*", "dir/a/b/c")


def test_question_mark_and_char_classes():
    assert glob_matches("file.??", "file.rs")
    assert not glob_matches("file.??", "file.rust")
    assert glob_matches("[abc].txt", "b.txt")
    assert not glob_matches("[!abc].txt", "b.txt")
    assert glob_matches("[a-z][0-9].bin", "q7.bin")


def test_invalid_pattern_never_matches():
    assert not glob_matches("[unclosed", "anything")


def test_recursive_wildcard_matches_zero_components():
    # Verified against the Rust glob crate (0.3.3): `**` matches ZERO or more
    # path components, so the separator that follows it is optional.
    assert glob_matches("**/*.ckpt", "last.ckpt")
    assert glob_matches("**/*.ckpt", "/Users/x/last.ckpt")
    assert glob_matches("a/**/b", "a/b")
    assert glob_matches("a/**/b", "a/x/y/b")
    assert glob_matches("a/**/b", "a//b")
    assert not glob_matches("a/**/b", "a/xb")
    assert not glob_matches("a/**/b", "ab")
    assert glob_matches("**/b", "b")
    assert not glob_matches("**/b", "xb")
    # Consecutive recursive wildcards collapse.
    assert glob_matches("a/**/**/b", "a/b")
    assert glob_matches("**/**", "x")
    # The two real corpus patterns with interior `**`:
    assert glob_matches(
        "/Users/m/Library/Application Support/**/Code Cache/**",
        "/Users/m/Library/Application Support/Code Cache/js/x_0",
    )


def test_trailing_recursive_wildcard_requires_the_separator():
    # `a/**` matches "a/" and "a/b" but NOT bare "a" (glob crate behavior).
    assert glob_matches("a/**", "a/")
    assert glob_matches("a/**", "a/b/c")
    assert not glob_matches("a/**", "a")
    assert not glob_matches("/Users/x/.claude/statsig/**", "/Users/x/.claude/statsig")
    # A pattern ENDING in `**/` consumes the slash into the recursive token
    # and then matches any tail (glob crate quirk).
    assert glob_matches("a/**/", "a/")
    assert glob_matches("a/**/", "a/b")
    assert glob_matches("a/**/", "a/xb")
    assert not glob_matches("a/**/", "a")


def test_malformed_recursive_wildcards_are_invalid_and_never_match():
    # glob crate: `**` must form a whole path component; 3+ stars are invalid.
    for pattern in ("foo**", "**foo", "a**b", "***", "a/**b", "a**/b"):
        assert not glob_matches(pattern, "foobar"), pattern
        assert not glob_matches(pattern, "a/b"), pattern


def test_tilde_expansion():
    assert dsl.expand_tilde("~/Library/Caches/**", HOME) == f"{HOME}/Library/Caches/**"
    assert dsl.expand_tilde("**/x", HOME) == "**/x"


# --- Selector semantics --------------------------------------------------------------

def test_directory_name_only_matches_directories():
    spec = MatchSpec(directory_name="target")
    dir_entry = Entry(path="/p/app/target", kind=KIND_DIRECTORY, allocated_bytes=MB)
    file_entry = Entry(path="/p/app/target", kind=KIND_FILE, allocated_bytes=MB)
    assert spec_matches(spec, dir_entry, HOME, ALWAYS)
    assert not spec_matches(spec, file_entry, HOME, ALWAYS)


def test_file_name_glob_only_matches_files():
    spec = MatchSpec(file_name="*.log")
    assert spec_matches(spec, Entry(path="/p/x/build.log"), HOME, ALWAYS)
    assert not spec_matches(
        spec, Entry(path="/p/x/build.log", kind=KIND_DIRECTORY), HOME, ALWAYS
    )


def test_file_extension_requires_dot_form():
    spec = MatchSpec(file_extension=(".log",))
    assert spec_matches(spec, Entry(path="/p/x/a.log"), HOME, ALWAYS)
    assert not spec_matches(spec, Entry(path="/p/x/alog"), HOME, ALWAYS)
    assert not spec_matches(spec, Entry(path="/p/x/a.log", kind=KIND_DIRECTORY), HOME, ALWAYS)


# --- Guards ---------------------------------------------------------------------------

def test_parent_must_contain_all_markers():
    spec = MatchSpec(directory_name="target", parent_must_contain=("Cargo.toml",))
    entry = Entry(path="/p/app/target", kind=KIND_DIRECTORY, allocated_bytes=MB)
    assert spec_matches(spec, entry, HOME, lambda d, m: d == "/p/app" and m == "Cargo.toml")
    assert not spec_matches(spec, entry, HOME, NEVER)


def test_parent_must_contain_any_accepts_single_marker():
    spec = MatchSpec(
        directory_name="build",
        parent_must_contain_any=("build.gradle", "build.gradle.kts"),
    )
    entry = Entry(path="/p/app/build", kind=KIND_DIRECTORY, allocated_bytes=MB)
    assert spec_matches(spec, entry, HOME, lambda _d, m: m == "build.gradle.kts")
    assert not spec_matches(spec, entry, HOME, NEVER)


def test_self_must_contain_probes_the_directory_itself_and_refuses_files():
    spec = MatchSpec(path_glob="**/checkpoint-*", self_must_contain=("trainer_state.json",))
    dir_entry = Entry(path="/p/out/checkpoint-500", kind=KIND_DIRECTORY, allocated_bytes=MB)
    file_entry = Entry(path="/p/out/checkpoint-500.tar", kind=KIND_FILE, allocated_bytes=MB)
    assert spec_matches(
        spec, dir_entry, HOME,
        lambda d, m: d == "/p/out/checkpoint-500" and m == "trainer_state.json",
    )
    assert not spec_matches(spec, dir_entry, HOME, NEVER)
    assert not spec_matches(spec, file_entry, HOME, ALWAYS)


def test_min_size_uses_allocated_bytes():
    spec = MatchSpec(directory_name="target", min_size_mb=10)
    small = Entry(path="/p/target", kind=KIND_DIRECTORY, allocated_bytes=9 * MB)
    big = Entry(path="/p/target", kind=KIND_DIRECTORY, allocated_bytes=11 * MB)
    assert not spec_matches(spec, small, HOME, ALWAYS)
    assert spec_matches(spec, big, HOME, ALWAYS)


def test_min_age_directory_uses_newest_in_subtree():
    spec = MatchSpec(directory_name="old_dir", min_age_days=7)
    fresh_inside = Entry(
        path="/p/old_dir", kind=KIND_DIRECTORY, allocated_bytes=MB,
        age_days=10.0, newest_age_days=0.5,
    )
    all_old = Entry(
        path="/p/old_dir", kind=KIND_DIRECTORY, allocated_bytes=MB,
        age_days=10.0, newest_age_days=10.0,
    )
    assert not spec_matches(spec, fresh_inside, HOME, ALWAYS)
    assert spec_matches(spec, all_old, HOME, ALWAYS)


def test_min_age_none_modified_never_matches():
    spec = MatchSpec(file_name="a.log", min_age_days=7)
    entry = Entry(path="/p/a.log", age_days=None)
    assert not spec_matches(spec, entry, HOME, ALWAYS)


# --- Excludes -----------------------------------------------------------------------

def test_exclude_names_and_paths():
    spec = MatchSpec(
        path_glob="~/.claude/statsig/**",
        exclude_paths=("~/.claude/projects/**",),
        exclude_names=(".credentials.json",),
    )
    assert spec_matches(spec, Entry(path=f"{HOME}/.claude/statsig/x.2"), HOME, ALWAYS)
    assert not spec_matches(
        spec, Entry(path=f"{HOME}/.claude/statsig/.credentials.json"), HOME, ALWAYS
    )
    assert not spec_matches(
        spec, Entry(path=f"{HOME}/.claude/projects/x/y.jsonl"), HOME, ALWAYS
    )


# --- any_of + floors ------------------------------------------------------------------

def test_any_of_alternative_matches_when_primary_does_not():
    recipe = make_recipe(
        MatchSpec(path_glob="**/*.ckpt"),
        MatchSpec(path_glob="**/checkpoint-*", self_must_contain=("trainer_state.json",)),
    )
    ckpt = Entry(path="/p/ml/last.ckpt", allocated_bytes=MB)
    ckdir = Entry(path="/p/ml/out/checkpoint-500", kind=KIND_DIRECTORY, allocated_bytes=MB)
    other = Entry(path="/p/ml/train.py", allocated_bytes=MB)
    assert recipe_matches(recipe, ckpt, HOME, ALWAYS)
    assert recipe_matches(recipe, ckdir, HOME, ALWAYS)
    assert not recipe_matches(recipe, other, HOME, ALWAYS)


def test_safety_floors_apply_to_all_alternatives():
    recipe = make_recipe(
        MatchSpec(path_glob="**/*.ckpt"),
        MatchSpec(path_glob="**/checkpoint-*"),
    )
    protected = Entry(path="/Applications/Foo/checkpoint-500", kind=KIND_DIRECTORY, allocated_bytes=MB)
    user_doc = Entry(path=f"{HOME}/Documents/ml/model.ckpt", allocated_bytes=MB)
    sensitive = Entry(path="/p/cache/checkpoint-x/credentials.json", allocated_bytes=MB)
    assert not recipe_matches(recipe, protected, HOME, ALWAYS)
    assert not recipe_matches(recipe, user_doc, HOME, ALWAYS)
    # sensitive basename inside otherwise-matching glob
    glob_recipe = make_recipe(MatchSpec(path_glob="**/checkpoint-x/**"))
    assert not recipe_matches(glob_recipe, sensitive, HOME, ALWAYS)


def test_near_miss_detection():
    recipe = make_recipe(
        MatchSpec(directory_name="target", parent_must_contain=("Cargo.toml",), min_size_mb=10)
    )
    loose = Entry(path="/p/scratch/target", kind=KIND_DIRECTORY, allocated_bytes=60 * MB)
    assert dsl.recipe_near_miss(recipe, loose, HOME, NEVER)
    proven = Entry(path="/p/app/target", kind=KIND_DIRECTORY, allocated_bytes=60 * MB)
    assert not dsl.recipe_near_miss(recipe, proven, HOME, ALWAYS)


# --- Safety floors (mirror of safety.rs normalization) --------------------------------

def test_protected_firmlink_aliases():
    # safety.rs resolves /tmp,/var,/etc through their /private firmlinks.
    assert dsl.is_protected("/tmp/scratch.bin", HOME)
    assert dsl.is_protected("/var/folders/zz/x", HOME)
    assert dsl.is_protected("/etc/hosts", HOME)
    assert dsl.is_protected("/private/tmp/x", HOME)


def test_protected_comparison_is_case_insensitive():
    # ProtectedPaths always also compares case-folded (the over-protecting,
    # safe direction on APFS's default case-insensitive volumes).
    assert dsl.is_protected("/SYSTEM/Library/x", HOME)
    assert dsl.is_protected("/applications/Foo.app", HOME)
    assert dsl.is_protected(f"{HOME}/documents/notes.txt", HOME)
    # Lookalike prefixes are NOT protected (component-wise boundary).
    assert not dsl.is_protected("/Systems/x", HOME)
    assert not dsl.is_protected(f"{HOME}/Documents-old/x", HOME)


def test_fixture_kind_mirrors_validator_directory_decision():
    # validator.rs spec_wants_directory: a literal directory_name DECIDES for
    # its spec; it does not fall through to the self-marker+glob probe.
    recipe = make_recipe(
        MatchSpec(
            directory_name="build",
            path_glob="**/checkpoint-*",
            self_must_contain=("trainer_state.json",),
        )
    )
    entry = synthetic_fixture_entry(recipe, "out/checkpoint-500", HOME)
    assert entry.kind == KIND_FILE  # directory_name "build" != "checkpoint-500"


# --- Corpus-wide fixture validation (mirror of the Rust validator) --------------------

@pytest.fixture(scope="module")
def corpus():
    recipes = load_recipes(include_disabled=True)
    assert len(recipes) >= 120, "expected the full recipe corpus"
    return recipes


def test_all_should_match_fixtures_match_optimistically(corpus):
    for recipe in corpus:
        for fixture in recipe.should_match:
            entry = synthetic_fixture_entry(recipe, fixture, HOME)
            assert recipe_matches(recipe, entry, HOME, ALWAYS), (
                f"{recipe.id}: should_match fixture did not match: {fixture}"
            )


def test_all_should_not_match_fixtures_reject_pessimistically(corpus):
    for recipe in corpus:
        for fixture in recipe.should_not_match:
            entry = synthetic_fixture_entry(recipe, fixture, HOME)
            assert not recipe_matches(recipe, entry, HOME, NEVER), (
                f"{recipe.id}: should_not_match fixture matched: {fixture}"
            )


def test_corpus_parses_expected_dsl_surface(corpus):
    ids = {r.id for r in corpus}
    assert "rust-target-dirs" in ids
    assert "node-modules" in ids
    with_any_of = [r for r in corpus if len(r.specs) > 1]
    assert len(with_any_of) >= 5, "any_of recipes should parse into multiple specs"
    levels = {r.safety_level for r in corpus}
    assert levels <= {"safe", "cautious", "aggressive"}
