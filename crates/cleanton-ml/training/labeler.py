"""Grounded labeling: safety floors + the full recipe corpus + near-miss logic.

Labels are never hand-set. Every node of a generated virtual tree is labeled
by the same rules the shipped engine enforces, in priority order:

1. **Safety floor** — protected roots (``safety.rs``) and sensitive
   basenames (``matcher.rs``) are always ``Keep``. Dominates everything.
2. **Recipe exclude** — a path a recipe's ``[match.exclude]`` explicitly
   protects (e.g. ``~/.claude/projects/**``) is ``Keep``.
3. **Recipe match** — an entry fully matched by an enabled recipe is
   cleanable: ``safe`` recipes → ``SafeToRemove``; ``cautious`` /
   ``aggressive`` recipes → ``LikelyJunk``. Descendants of a matched
   directory inherit the label (trashing the dir removes them), except
   floored paths.
4. **Keep evidence** — ``.git`` internals, project manifests/lockfiles,
   source files outside matched/cache trees, documents/media shapes.
5. **Near miss** — a recipe selector matched but a guard refused
   (loose ``target`` with no ``Cargo.toml``, fresh ``.venv``, small ``.pt``,
   ``checkpoint-alpha`` without ``trainer_state.json``) → ``Uncertain``.
6. Everything else → ``Uncertain``.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass

from . import features as F
from . import recipes_dsl as dsl
from .fstree import Node
from .recipes_dsl import Entry, Recipe

KEEP = 0
SAFE_TO_REMOVE = 1
LIKELY_JUNK = 2
UNCERTAIN = 3

LABEL_NAMES = ("keep", "safe-to-remove", "likely-junk", "uncertain")
NUM_CLASSES = 4
CLEAN_LABELS = frozenset({SAFE_TO_REMOVE, LIKELY_JUNK})

_SAFE_LEVELS = frozenset({"safe"})


@dataclass(frozen=True)
class Labeled:
    node_path: str
    label: int
    reason: str


def _home_of(root: Node) -> str:
    users = root.children.get("Users")
    if users is None or not users.children:
        raise ValueError("world tree has no /Users/<name> home")
    name = next(iter(users.children))
    return f"/Users/{name}"


def _entry_for(node: Node) -> Entry:
    size = node.subtree_bytes() if node.kind == F.KIND_DIRECTORY else node.size_bytes
    return Entry(
        path=node.path,
        kind=node.kind,
        allocated_bytes=size,
        age_days=node.age_days,
        newest_age_days=node.newest_age_days() if node.kind == F.KIND_DIRECTORY else None,
    )


def _keep_evidence(node: Node) -> str | None:
    """Rule 4: shapes the engine would never clean and users clearly value."""
    path = node.path
    name = node.name
    if F._has_signal_component(path, node.kind, ".git"):
        return "git-internals"
    if name in dsl.SENSITIVE_BASENAMES:
        return "sensitive-basename"
    from .vocab import LOCKFILES, PROJECT_MARKERS

    if name in LOCKFILES or name in PROJECT_MARKERS:
        return "project-manifest"
    ext_id = F.extension_id(path)
    in_removable_shape = (
        F.in_build_dir(path, node.kind)
        or F.in_cache_dir(path, node.kind)
        or F._has_signal_component(path, node.kind, "node_modules")
        or F.in_venv(path, node.kind)
    )
    if ext_id in F._SOURCE_EXT_IDS and not in_removable_shape:
        return "source-file"
    if (ext_id in F._DOC_EXT_IDS or ext_id in F._MEDIA_EXT_IDS) and not in_removable_shape:
        return "document-or-media"
    return None


class TreeLabeler:
    """Labels every node of one world tree against the recipe corpus."""

    def __init__(self, root: Node, recipes: list[Recipe]):
        self.root = root
        # Mirror the engine's match order: recipes sorted by priority
        # descending (analyzer.rs sorts by Reverse(priority); first matching
        # recipe wins per entry). The stable sort preserves load order within
        # equal priorities; where several equal-priority recipes match, the
        # safest claim is kept (the tie order inside builtin.rs is a Rust
        # source artifact, and erring safe is the conservative direction).
        self.recipes = sorted(recipes, key=lambda r: -r.priority)
        self.home = _home_of(root)
        # Recipe prefilters: exact directory-name selectors are cheap dictionary
        # hits; everything else runs its compiled globs.
        self._nodes_by_path: dict[str, Node] = {n.path: n for n in root.walk() if n.name}

    def _dir_contains(self, dir_path: str, marker: str) -> bool:
        node = self._nodes_by_path.get(dir_path)
        if node is None:
            return False
        current = node
        for part in [p for p in marker.split("/") if p]:
            child = current.children.get(part)
            if child is None:
                return False
            current = child
        return True

    def label_node(self, node: Node, matched_ancestor: tuple[int, str] | None) -> tuple[int, str, tuple[int, str] | None]:
        """Return (label, reason, matched_state_for_descendants)."""
        path = node.path

        # 1. Safety floor dominates everything, including inherited matches.
        if dsl.is_protected(path, self.home):
            return KEEP, "protected-root", matched_ancestor
        if dsl.is_sensitive_basename(path):
            return KEEP, "sensitive-basename", matched_ancestor

        # 3b. Inside a matched (removable) directory: inherit its class.
        if matched_ancestor is not None:
            label, recipe_id = matched_ancestor
            return label, f"inside-matched:{recipe_id}", matched_ancestor

        entry = _entry_for(node)

        matched_label: int | None = None
        matched_id = ""
        matched_priority: int | None = None
        excluded_id: str | None = None
        near_miss_id: str | None = None
        for recipe in self.recipes:
            # Engine reality: the first match in priority order wins. Once a
            # match exists, lower-priority recipes cannot change the outcome
            # (a match also dominates exclude/near-miss in the final label).
            if matched_priority is not None and recipe.priority < matched_priority:
                break
            selector_hit = any(
                dsl.spec_selector_matches(spec, entry, self.home) for spec in recipe.specs
            )
            if selector_hit and dsl.recipe_matches(recipe, entry, self.home, self._dir_contains):
                label = SAFE_TO_REMOVE if recipe.safety_level in _SAFE_LEVELS else LIKELY_JUNK
                if matched_priority is None or recipe.priority > matched_priority:
                    matched_label, matched_id = label, recipe.id
                    matched_priority = recipe.priority
                elif recipe.priority == matched_priority and label < (matched_label or UNCERTAIN):
                    # Equal priority: keep the safest claim (see __init__ note).
                    matched_label, matched_id = label, recipe.id
            elif excluded_id is None and _exclude_is_specific(recipe, entry, self.home):
                # A path-glob exclude names this path explicitly: the recipe
                # author declared it protected (e.g. ~/.claude/projects/**).
                excluded_id = recipe.id
            elif selector_hit and near_miss_id is None:
                near_miss_id = recipe.id

        # 2. Recipe-explicit exclusion is an author-declared KEEP.
        if matched_label is None and excluded_id is not None:
            return KEEP, f"recipe-exclude:{excluded_id}", None

        # 3. Full recipe match → cleanable; descendants inherit.
        if matched_label is not None:
            return matched_label, f"recipe:{matched_id}", (matched_label, matched_id)

        # 4. Keep evidence.
        evidence = _keep_evidence(node)
        if evidence is not None:
            return KEEP, evidence, None

        # 5. Near miss → uncertain (never cleanable without the guard proof).
        if near_miss_id is not None:
            return UNCERTAIN, f"near-miss:{near_miss_id}", None

        # 6. No signal.
        return UNCERTAIN, "no-signal", None

    def label_tree(self) -> dict[str, tuple[int, str]]:
        """Label every named node; returns {path: (label, reason)}."""
        results: dict[str, tuple[int, str]] = {}

        def visit(node: Node, matched: tuple[int, str] | None) -> None:
            state = matched
            if node.name:
                label, reason, state = self.label_node(node, matched)
                results[node.path] = (label, reason)
            for child in node.children.values():
                visit(child, state)

        visit(self.root, None)
        return results


def _exclude_is_specific(recipe: Recipe, entry: Entry, home: str) -> bool:
    """An exclude hit counts as author-declared keep only when it names the
    path explicitly (path glob hit) AND the excluding spec's selector is
    path-anchored (its expanded ``path_glob`` has an absolute literal prefix,
    e.g. ``~/.claude/statsig/**`` or ``~/Library/Caches/pypoetry/**``).

    Anchored recipes are scoped to one concrete tree, so their excludes name
    specific protected subtrees the author chose to keep (Claude transcripts,
    live poetry virtualenvs). Unanchored selectors (``**/*.pt``) use broad
    excludes like ``~/.cache/**`` merely to ROUTE attribution to a more
    specific recipe — such a hit says nothing about the file's value, so it
    must not manufacture a Keep label for every unmatched cache path."""
    for spec in recipe.specs:
        if not spec.exclude_paths or spec.path_glob is None:
            continue
        expanded_selector = dsl.expand_tilde(spec.path_glob, home)
        if not dsl._literal_prefix(expanded_selector).startswith("/"):
            continue
        if any(
            dsl.glob_matches(dsl.expand_tilde(pattern, home), entry.path)
            for pattern in spec.exclude_paths
        ):
            return True
    return False


def derive_label(node: Node, labeler: TreeLabeler) -> int:
    """Convenience for tests: label one node with ancestor inheritance."""
    ancestors: list[Node] = []
    current = node.parent
    while current is not None and current.name:
        ancestors.append(current)
        current = current.parent
    matched: tuple[int, str] | None = None
    for ancestor in reversed(ancestors):
        label, _, matched = labeler.label_node(ancestor, matched)
    label, _, _ = labeler.label_node(node, matched)
    return label
