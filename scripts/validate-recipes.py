#!/usr/bin/env python3
"""Validate the Cleanton built-in recipe registry without a Rust toolchain.

This is the *offline* half of the recipe gate. The authoritative validator is
`cleanton_recipes::validate_recipe` (Rust, exercised by
`cargo test -p cleanton-recipes`); this script catches the same structural
mistakes -- and the registration/doc drift the Rust test cannot see -- before a
PR is ever opened, so the Rust job stays green on the first CI run.

Checks:
  * every `recipes/*.toml` parses and has a well-formed `[recipe]`/`[match]`/
    `[action]`/`[test]` block;
  * ids are unique, kebab-case, and every file is registered in
    `crates/cleanton-recipes/src/builtin.rs` (and vice versa);
  * `delete` actions require `safety_level = "aggressive"`;
  * every recipe has non-empty `should_match` / `should_not_match` fixtures and
    no fixture names a credential/secret basename;
  * `path_glob`/`file_name` values are relative, non-broad, valid globs;
  * `doc/RECIPES.md` names every recipe (coverage is reported; a hard failure
    only fires for recipes that are *registered but undocumented* when
    `--strict-docs` is passed).

Exit code 0 = clean, 1 = problems found.
"""

from __future__ import annotations

import argparse
import fnmatch
import glob as globmod
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RECIPES_DIR = REPO / "recipes"
BUILTIN = REPO / "crates" / "cleanton-recipes" / "src" / "builtin.rs"
DOCS = REPO / "doc" / "RECIPES.md"

SAFETY_LEVELS = {"safe", "cautious", "aggressive"}
ACTION_TYPES = {"trash", "delete", "archive"}
ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

# Basenames a recipe may never legitimately target (mirrors the matcher's
# sensitive-basename floor in cleanton-recipes/src/matcher.rs).
SENSITIVE_BASENAMES = {
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
}

# Glob metacharacters; a pattern made only of these is "broad" and rejected by
# the Rust validator (`is_broad_pattern`).
GLOB_META = set("*?[]{},!")


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    @property
    def ok(self) -> bool:
        return not self.errors


def _glob_is_valid(pattern: str) -> bool:
    """Best-effort glob validity: balanced brackets and no stray NUL/absolute."""
    if "\x00" in pattern:
        return False
    depth = 0
    for ch in pattern:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _is_broad(pattern: str) -> bool:
    norm = pattern.lstrip("./").strip("/").replace("\\", "/")
    if norm in {"*", "**", "**/*", "**/**", "*/*"}:
        return True
    # A pattern with no literal (non-glob, non-separator) signal is broad.
    has_literal = any(
        ch not in GLOB_META and ch not in "/\\." for ch in norm
    )
    return not has_literal


def _is_plain_segment(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip()
        and "/" not in value
        and "\\" not in value
        and value not in {".", ".."}
    )


def _validate_glob(rep: Report, where: str, pattern: str) -> None:
    if pattern.strip() != pattern or not pattern:
        rep.error(f"{where}: invalid glob {pattern!r}")
        return
    if Path(pattern).is_absolute():
        rep.error(f"{where}: absolute path_glob is not allowed: {pattern!r}")
        return
    if _is_broad(pattern):
        rep.error(f"{where}: broad glob is not allowed: {pattern!r}")
        return
    if not _glob_is_valid(pattern):
        rep.error(f"{where}: invalid glob {pattern!r}")


def _validate_match(rep: Report, where: str, matcher: dict) -> None:
    has_target = any(
        matcher.get(key)
        for key in ("directory_name", "file_name", "file_extension", "path_glob")
    )
    if not has_target:
        rep.error(
            f"{where}: matcher must include a target selector "
            "(directory_name, file_name, file_extension, or path_glob)"
        )

    directory_name = matcher.get("directory_name")
    if directory_name is not None and (
        not _is_plain_segment(directory_name)
        or any(ch in GLOB_META for ch in directory_name)
    ):
        rep.error(
            f"{where}: directory_name must be a literal path segment: {directory_name!r}"
        )

    file_name = matcher.get("file_name")
    if file_name is not None:
        if not _is_plain_segment(file_name):
            rep.error(f"{where}: file_name must be a single path segment: {file_name!r}")
        _validate_glob(rep, where, file_name)
        if _is_broad(file_name):
            rep.error(f"{where}: broad file_name pattern is not allowed: {file_name!r}")

    extensions = matcher.get("file_extension")
    if extensions is not None:
        if not extensions:
            rep.error(f"{where}: file_extension must not be empty")
        for ext in extensions:
            if len(ext) <= 1 or not ext.startswith(".") or ext[1:].count(".") or "/" in ext or "\\" in ext:
                rep.error(f"{where}: invalid file_extension: {ext!r}")

    path_glob = matcher.get("path_glob")
    if path_glob is not None:
        _validate_glob(rep, where, path_glob)

    for field in (
        "parent_must_contain",
        "parent_must_contain_any",
        "self_must_contain",
    ):
        markers = matcher.get(field)
        if markers is None:
            continue
        if not markers:
            rep.error(f"{where}: {field} must not be empty")
        for marker in markers:
            if (
                marker != marker.strip()
                or not marker
                or Path(marker).is_absolute()
                or "\\" in marker
                or any(ch in GLOB_META for ch in marker)
            ):
                rep.error(f"{where}: invalid {field} marker: {marker!r}")

    if matcher.get("min_size_mb") == 0:
        rep.error(f"{where}: min_size_mb must be greater than zero")
    if matcher.get("min_age_days") == 0:
        rep.error(f"{where}: min_age_days must be greater than zero")

    for exclude in matcher.get("exclude", {}).get("paths", []):
        _validate_glob(rep, where, exclude)

    for alt in matcher.get("any_of", []):
        if alt.get("any_of"):
            rep.error(f"{where}: any_of alternatives must not nest")
        _validate_match(rep, where + " (any_of)", alt)


def _validate_recipe(rep: Report, path: Path, doc: dict) -> str | None:
    recipe = doc.get("recipe")
    if recipe is None:
        rep.error(f"{path}: missing [recipe] block")
        return None

    rid = recipe.get("id")
    if not rid or not ID_RE.match(rid):
        rep.error(f"{path}: invalid recipe id {rid!r}; use kebab-case")

    for field in ("name", "description", "category"):
        if not recipe.get(field):
            rep.error(f"{path}: [recipe] must set {field}")

    safety = recipe.get("safety_level")
    if safety not in SAFETY_LEVELS:
        rep.error(
            f"{path}: invalid safety_level {safety!r}; one of {sorted(SAFETY_LEVELS)}"
        )

    priority = recipe.get("priority", 50)
    if not isinstance(priority, int) or not (0 <= priority <= 255):
        rep.error(f"{path}: priority must be an int in 0..=255, got {priority!r}")

    matcher = doc.get("match")
    if matcher is None:
        rep.error(f"{path}: missing [match] block")
    else:
        _validate_match(rep, str(path), matcher)

    action = doc.get("action")
    if action is None:
        rep.error(f"{path}: missing [action] block")
    else:
        action_type = action.get("type")
        if action_type not in ACTION_TYPES:
            rep.error(
                f"{path}: invalid action type {action_type!r}; one of {sorted(ACTION_TYPES)}"
            )
        if action_type == "delete" and safety != "aggressive":
            rep.error(f"{path}: delete actions must use safety_level = 'aggressive'")
        if not action.get("prompt"):
            rep.error(f"{path}: [action] must set a prompt")

    test = doc.get("test", {})
    should_match = test.get("should_match") or []
    should_not_match = test.get("should_not_match") or []
    if not should_match or not should_not_match:
        rep.error(
            f"{path}: recipe tests must include should_match and should_not_match fixtures"
        )
    for label, fixtures in (("should_match", should_match),):
        for fixture in fixtures:
            basename = Path(fixture).name
            if basename in SENSITIVE_BASENAMES:
                rep.error(
                    f"{path}: {label} fixture references sensitive basename: {fixture}"
                )

    return rid


def _builtin_entries() -> set[str]:
    if not BUILTIN.is_file():
        return set()
    return set(re.findall(r'"(recipes/[^"]+\.toml)"', BUILTIN.read_text()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict-docs",
        action="store_true",
        help="fail when a registered recipe is missing from doc/RECIPES.md",
    )
    args = parser.parse_args()

    rep = Report()

    files = sorted(RECIPES_DIR.glob("*.toml"))
    if not files:
        rep.error(f"no recipes found in {RECIPES_DIR}")
        _finish(rep, args.strict_docs, 0)
        return 1

    seen_ids: dict[str, Path] = {}
    seen_files: set[str] = set()
    ids: set[str] = set()

    for path in files:
        if path.name in seen_files:
            rep.error(f"duplicate recipe filename: {path.name}")
        seen_files.add(path.name)
        try:
            doc = tomllib.loads(path.read_text())
        except tomllib.TOMLDecodeError as err:
            rep.error(f"{path}: TOML parse error: {err}")
            continue
        rid = _validate_recipe(rep, path, doc)
        if rid:
            if rid in seen_ids:
                rep.error(
                    f"{path}: duplicate recipe id {rid!r} (also in {seen_ids[rid]})"
                )
            seen_ids[rid] = path
            ids.add(rid)

    # Registration parity with builtin.rs.
    builtin = _builtin_entries()
    for path in files:
        entry = f"recipes/{path.name}"
        if entry not in builtin:
            rep.error(f"{path.name}: not registered in builtin.rs")
    for entry in sorted(builtin):
        if not (REPO / entry).is_file():
            rep.error(f"builtin.rs registers a missing recipe file: {entry}")

    # Docs coverage (informational unless --strict-docs).
    documented: set[str] = set()
    if DOCS.is_file():
        text = DOCS.read_text()
        documented = {rid for rid in ids if rid in text}
    for rid in sorted(ids - documented):
        msg = f"recipe {rid!r} is not mentioned in doc/RECIPES.md"
        if args.strict_docs:
            rep.error(msg)
        else:
            rep.warn(msg)

    _finish(rep, args.strict_docs, len(files))
    return 0 if rep.ok else 1


def _finish(rep: Report, strict_docs: bool, recipe_count: int) -> None:
    print(f"== recipes: {recipe_count} checked, {len(rep.warnings)} warnings ==")
    for warning in rep.warnings:
        print(f"  warning: {warning}")
    for error in rep.errors:
        print(f"  error:   {error}")
    if rep.ok:
        print("Recipe registry OK.")
    else:
        print(f"Recipe registry has {len(rep.errors)} error(s).")


if __name__ == "__main__":
    sys.exit(main())
