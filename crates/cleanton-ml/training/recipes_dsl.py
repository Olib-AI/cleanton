"""Python mirror of the cleanton recipe DSL (parser + matcher semantics).

Parses ``recipes/*.toml`` and reproduces the EXACT matching semantics of
``crates/cleanton-recipes/src/{parser,matcher}.rs`` so training labels stay
grounded in what the shipped engine actually does:

* selectors: ``directory_name`` (literal, dirs only), ``file_name`` (glob on
  the basename, files only), ``file_extension`` (".ext" list, files only),
  ``path_glob`` (glob on the full path);
* guards: ``parent_must_contain`` (all-of), ``parent_must_contain_any``
  (any-of), ``self_must_contain`` (all-of, dirs only), ``min_size_mb``
  (allocated bytes), ``min_age_days`` (for dirs: the NEWEST entry in the
  subtree must be old enough);
* ``[match.exclude]`` paths (globs, ``~`` expanded) and names (literal
  basenames);
* ``[[match.any_of]]`` alternatives — the recipe matches when the top-level
  spec OR any alternative matches;
* safety floors applied last: protected roots + sensitive basenames
  (mirrors ``recipe_matches_entry_full``).

Glob semantics mirror the Rust ``glob`` crate defaults: ``*``/``**`` match
any sequence INCLUDING ``/`` (``require_literal_separator = false``), ``?``
matches any single character, ``[...]``/``[!...]`` are character classes.
"""

from __future__ import annotations

import functools
import posixpath
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

KIND_FILE = "file"
KIND_DIRECTORY = "directory"

MB = 1_048_576

# Mirror of matcher.rs SENSITIVE_BASENAMES (compared case-insensitively).
SENSITIVE_BASENAMES = frozenset({
    ".env", ".netrc", ".npmrc", ".pypirc", "credentials", "credentials.json",
    ".credentials.json", "auth.json", ".auth.json", "id_rsa", "id_dsa",
    "id_ecdsa", "id_ed25519", "kubeconfig", "secrets.yaml", "secrets.yml",
    "service-account.json", "settings.json", "settings.local.json",
    "mcp.json", ".mcp.json",
})

# Mirror of safety.rs HARDCODED_PROTECTED.
HARDCODED_PROTECTED = (
    "/System", "/Library", "/usr", "/bin", "/sbin", "/private", "/etc",
    "/var", "/Applications",
)

# Mirror of safety.rs USER_PROTECTED (home-relative).
USER_PROTECTED = (
    ".ssh", ".gnupg", ".aws", ".azure", ".config/gcloud", ".config/cleanton",
    ".kube", ".docker/config.json", ".npmrc", ".pypirc", ".netrc",
    "Library/Keychains", "Library/Mail", "Library/Messages",
    "Library/Containers", "Library/Group Containers",
    "Desktop", "Documents", "Downloads", "Pictures", "Music", "Movies",
)


@functools.lru_cache(maxsize=4096)
def _compile_glob(pattern: str) -> re.Pattern | None:
    """Translate a Rust ``glob::Pattern`` to a compiled Python regex.

    Defaults mirrored: ``require_literal_separator=false`` (so ``*`` and ``?``
    span ``/``) and ``require_literal_leading_dot=false``.
    Returns None for invalid patterns (which never match, as in Rust).

    ``**`` mirrors the glob crate exactly (verified against glob 0.3.3):
    it is valid only as a WHOLE path component (start-or-after-``/`` and
    end-or-before-``/``; runs of 3+ stars are invalid, as is ``a**b``), it
    matches ZERO or more components (``a/**/b`` matches ``a/b``; ``**/x``
    matches ``x``), and a trailing ``/**`` requires the slash (``a/**``
    matches ``a/`` but not ``a``).
    """
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            start = i
            while i < n and pattern[i] == "*":
                i += 1
            run = i - start
            if run == 1:
                out.append(".*")
                continue
            if run > 2:
                return None  # glob crate: wildcards are * or ** only
            # ** must form a single path component.
            bounded_left = start == 0 or pattern[start - 1] == "/"
            bounded_right = i == n or pattern[i] == "/"
            if not (bounded_left and bounded_right):
                return None
            if i < n - 1:  # followed by '/' with more pattern: zero+ components
                out.append("(?:.*/)?")
                i += 1  # the separator is consumed by the recursive token
            else:
                # Trailing '**' or trailing '**/': any remainder. The glob
                # crate consumes the slash after '**' into the recursive
                # token, so a pattern ending in '**/' matches any tail too.
                out.append(".*")
                i = n
            continue
        if ch == "?":
            out.append(".")
        elif ch == "[":
            j = i + 1
            negate = False
            if j < n and pattern[j] in "!^":
                negate = pattern[j] == "!"
                if negate:
                    j += 1
            # ']' immediately after the opening (or '!') is a literal member.
            body_start = j
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                return None  # unclosed class: invalid pattern
            body = pattern[body_start:j]
            body = body.replace("\\", "\\\\")
            # Escape regex class metacharacters except '-' (ranges kept).
            # '[' is escaped too (regex "nested set" warning; literal member).
            body = body.replace("^", "\\^").replace("]", "\\]").replace("[", "\\[")
            out.append("[" + ("^" if negate else "") + body + "]")
            i = j
        else:
            out.append(re.escape(ch))
        i += 1
    try:
        # DOTALL: the glob crate's wildcards match every character, including
        # newlines that are technically legal in file names.
        return re.compile("(?s)^" + "".join(out) + "$")
    except re.error:
        return None


@functools.lru_cache(maxsize=4096)
def _literal_prefix(pattern: str) -> str:
    """Longest leading literal (a necessary ``startswith`` precondition) —
    a pure fast path; the regex remains the authority."""
    out: list[str] = []
    for ch in pattern:
        if ch in "*?[":
            break
        out.append(ch)
    return "".join(out)


def glob_matches(pattern: str, text: str) -> bool:
    if not text.startswith(_literal_prefix(pattern)):
        return False
    compiled = _compile_glob(pattern)
    return bool(compiled and compiled.match(text))


def expand_tilde(pattern: str, home: str) -> str:
    if pattern == "~":
        return home
    if pattern.startswith("~/"):
        return home + pattern[1:]
    return pattern


# --- Data model -----------------------------------------------------------------


@dataclass(frozen=True)
class MatchSpec:
    directory_name: str | None = None
    file_name: str | None = None
    file_extension: tuple[str, ...] | None = None
    path_glob: str | None = None
    parent_must_contain: tuple[str, ...] | None = None
    parent_must_contain_any: tuple[str, ...] | None = None
    self_must_contain: tuple[str, ...] | None = None
    min_size_mb: int | None = None
    min_age_days: int | None = None
    exclude_paths: tuple[str, ...] = ()
    exclude_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class Recipe:
    id: str
    category: str
    safety_level: str
    enabled: bool
    priority: int
    specs: tuple[MatchSpec, ...]  # top-level spec first, then any_of alternatives
    should_match: tuple[str, ...] = ()
    should_not_match: tuple[str, ...] = ()


@dataclass(frozen=True)
class Entry:
    """The subset of FileEntry the matcher consults."""

    path: str
    kind: str = KIND_FILE
    allocated_bytes: int = 0
    age_days: float | None = 0.0  # None mirrors modified == None
    # Age of the newest entry inside the subtree (directories); None = unknown.
    newest_age_days: float | None = None


def _spec_from_dict(data: dict) -> MatchSpec:
    exclude = data.get("exclude", {})
    return MatchSpec(
        directory_name=data.get("directory_name"),
        file_name=data.get("file_name"),
        file_extension=tuple(data["file_extension"]) if "file_extension" in data else None,
        path_glob=data.get("path_glob"),
        parent_must_contain=tuple(data["parent_must_contain"]) if "parent_must_contain" in data else None,
        parent_must_contain_any=tuple(data["parent_must_contain_any"]) if "parent_must_contain_any" in data else None,
        self_must_contain=tuple(data["self_must_contain"]) if "self_must_contain" in data else None,
        min_size_mb=data.get("min_size_mb"),
        min_age_days=data.get("min_age_days"),
        exclude_paths=tuple(exclude.get("paths", ())),
        exclude_names=tuple(exclude.get("names", ())),
    )


def parse_recipe_toml(text: str) -> Recipe:
    doc = tomllib.loads(text)
    recipe = doc["recipe"]
    matcher = doc.get("match", {})
    top = _spec_from_dict(matcher)
    alternatives = tuple(_spec_from_dict(alt) for alt in matcher.get("any_of", ()))
    test = doc.get("test", {})
    return Recipe(
        id=recipe["id"],
        category=recipe.get("category", ""),
        safety_level=recipe.get("safety_level", "cautious"),
        enabled=recipe.get("enabled", True),
        priority=recipe.get("priority", 50),
        specs=(top, *alternatives),
        should_match=tuple(test.get("should_match", ())),
        should_not_match=tuple(test.get("should_not_match", ())),
    )


def default_recipes_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "recipes"


def load_recipes(recipes_dir: Path | None = None, include_disabled: bool = False) -> list[Recipe]:
    directory = recipes_dir or default_recipes_dir()
    recipes: list[Recipe] = []
    for path in sorted(directory.glob("*.toml")):
        recipe = parse_recipe_toml(path.read_text(encoding="utf-8"))
        if recipe.enabled or include_disabled:
            recipes.append(recipe)
    return recipes


# --- Matching --------------------------------------------------------------------

DirContains = Callable[[str, str], bool]


def spec_selector_matches(spec: MatchSpec, entry: Entry, home: str) -> bool:
    """Selector-only evaluation (no guards, no excludes) — used to detect
    near-miss decoys: entries that LOOK like a recipe target but fail a guard."""
    name = posixpath.basename(entry.path)

    if spec.directory_name is not None:
        if entry.kind != KIND_DIRECTORY or name != spec.directory_name:
            return False

    if spec.file_name is not None:
        if entry.kind != KIND_FILE or not glob_matches(spec.file_name, name):
            return False

    if spec.file_extension is not None:
        if entry.kind != KIND_FILE:
            return False
        dot = name.rfind(".")
        ext = "." + name[dot + 1:] if 0 < dot < len(name) - 1 else None
        if ext is None or ext not in spec.file_extension:
            return False

    if spec.path_glob is not None:
        expanded = expand_tilde(spec.path_glob, home)
        if not glob_matches(expanded, entry.path):
            return False

    # A spec with no selector at all never "looks like" anything.
    return any(
        item is not None
        for item in (spec.directory_name, spec.file_name, spec.file_extension, spec.path_glob)
    )


def spec_excluded(spec: MatchSpec, entry: Entry, home: str) -> bool:
    name = posixpath.basename(entry.path)
    if any(name == excluded for excluded in spec.exclude_names):
        return True
    return any(
        glob_matches(expand_tilde(pattern, home), entry.path)
        for pattern in spec.exclude_paths
    )


def spec_matches(
    spec: MatchSpec,
    entry: Entry,
    home: str,
    dir_contains: DirContains,
) -> bool:
    """Full mirror of matcher.rs ``spec_matches_entry`` (no safety floors)."""
    if spec_excluded(spec, entry, home):
        return False
    if not spec_selector_matches(spec, entry, home) and any(
        item is not None
        for item in (spec.directory_name, spec.file_name, spec.file_extension, spec.path_glob)
    ):
        return False

    if spec.parent_must_contain is not None:
        parent = posixpath.dirname(entry.path)
        if not parent:
            return False
        if not all(dir_contains(parent, marker) for marker in spec.parent_must_contain):
            return False

    if spec.parent_must_contain_any is not None:
        parent = posixpath.dirname(entry.path)
        if not parent:
            return False
        if not any(dir_contains(parent, marker) for marker in spec.parent_must_contain_any):
            return False

    if spec.self_must_contain is not None:
        if entry.kind != KIND_DIRECTORY:
            return False
        if not all(dir_contains(entry.path, marker) for marker in spec.self_must_contain):
            return False

    if spec.min_size_mb is not None and entry.allocated_bytes < spec.min_size_mb * MB:
        return False

    if spec.min_age_days is not None:
        if entry.kind == KIND_DIRECTORY:
            age = entry.newest_age_days if entry.newest_age_days is not None else entry.age_days
        else:
            age = entry.age_days
        if age is None or age < spec.min_age_days:
            return False

    return True


# Mirror of paths.rs FIRMLINK_ALIASES: macOS presents these top-level aliases
# as the same on-disk location, so `/tmp/x` is protected via `/private/tmp/x`.
FIRMLINK_ALIASES = (("/var", "/private/var"), ("/etc", "/private/etc"), ("/tmp", "/private/tmp"))


def _firmlink_canonical(path: str) -> str:
    for alias, canonical in FIRMLINK_ALIASES:
        if path == alias or path.startswith(alias + "/"):
            return canonical + path[len(alias):]
    return path


def is_protected(path: str, home: str) -> bool:
    """Mirror of safety.rs ``is_protected_fast``: firmlink-normalized,
    component-wise prefix check, always ALSO compared case-folded (Rust folds
    with Unicode NFC + casefold; ASCII casefold is the training-data subset)."""
    normalized = _firmlink_canonical(path)
    folded = normalized.lower()

    def under(root: str) -> bool:
        root_norm = _firmlink_canonical(root)
        if normalized == root_norm or normalized.startswith(root_norm + "/"):
            return True
        root_fold = root_norm.lower()
        return folded == root_fold or folded.startswith(root_fold + "/")

    if any(under(root) for root in HARDCODED_PROTECTED):
        return True
    return any(under(posixpath.join(home, rel)) for rel in USER_PROTECTED)


def is_sensitive_basename(path: str) -> bool:
    return posixpath.basename(path).lower() in SENSITIVE_BASENAMES


def recipe_matches(
    recipe: Recipe,
    entry: Entry,
    home: str,
    dir_contains: DirContains,
) -> bool:
    """Mirror of ``recipe_matches_entry_full``: any spec matches, then floors."""
    if not any(spec_matches(spec, entry, home, dir_contains) for spec in recipe.specs):
        return False
    if is_protected(entry.path, home) or is_sensitive_basename(entry.path):
        return False
    return True


def recipe_near_miss(
    recipe: Recipe,
    entry: Entry,
    home: str,
    dir_contains: DirContains,
) -> bool:
    """True when a selector matched but the recipe as a whole did not:
    the systematic adversarial construction the guards imply."""
    if recipe_matches(recipe, entry, home, dir_contains):
        return False
    return any(spec_selector_matches(spec, entry, home) for spec in recipe.specs)


def recipe_excluded(recipe: Recipe, entry: Entry, home: str) -> bool:
    """True when any spec's exclude explicitly rejects this path."""
    return any(spec_excluded(spec, entry, home) for spec in recipe.specs)


# --- Fixture harness (mirror of validator.rs synthetic_entry) ---------------------


def synthetic_fixture_entry(recipe: Recipe, fixture: str, home: str) -> Entry:
    path = expand_tilde(fixture, home)

    def wants_directory(spec: MatchSpec) -> bool:
        # Mirror of validator.rs spec_wants_directory: a literal directory_name
        # DECIDES for its spec (no fall-through to the self-marker probe).
        name = posixpath.basename(path)
        if spec.directory_name is not None:
            return spec.directory_name == name
        return spec.self_must_contain is not None and (
            spec.path_glob is not None
            and glob_matches(expand_tilde(spec.path_glob, home), path)
        )

    kind = KIND_DIRECTORY if any(wants_directory(s) for s in recipe.specs) else KIND_FILE
    min_bytes = (max((s.min_size_mb or 1) for s in recipe.specs) + 1) * MB
    min_age = max((s.min_age_days or 30) for s in recipe.specs) + 1
    return Entry(
        path=path,
        kind=kind,
        allocated_bytes=min_bytes,
        age_days=float(min_age),
        newest_age_days=float(min_age),
    )
