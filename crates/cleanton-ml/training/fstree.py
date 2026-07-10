"""Virtual filesystem trees for coherent dataset generation.

The generator builds whole macOS home-directory trees out of ``Node`` objects
instead of sampling isolated paths, so every piece of correlated metadata —
sibling counts, gitignore/lockfile presence, ancestor project markers,
subtree sizes, age locality — is derived from the ACTUAL generated tree,
never sampled independently (the main consistency flaw of the v1 dataset).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from .features import KIND_DIRECTORY, KIND_FILE, FileSample
from .vocab import LOCKFILES, PROJECT_MARKERS

_LOCKFILE_SET = frozenset(LOCKFILES)
_MARKER_SET = frozenset(PROJECT_MARKERS)


@dataclass
class Node:
    """One file or directory in a virtual tree."""

    name: str
    kind: str = KIND_FILE
    size_bytes: int = 0
    age_days: float = 0.0
    children: dict[str, "Node"] = field(default_factory=dict)
    parent: "Node | None" = field(default=None, repr=False)

    # -- construction ---------------------------------------------------------

    def dir(self, name: str, age_days: float | None = None) -> "Node":
        """Get or create a child directory."""
        child = self.children.get(name)
        if child is None:
            child = Node(name=name, kind=KIND_DIRECTORY,
                         age_days=self.age_days if age_days is None else age_days)
            child.parent = self
            self.children[name] = child
        return child

    def dirs(self, *names: str) -> "Node":
        node = self
        for name in names:
            node = node.dir(name)
        return node

    def file(self, name: str, size_bytes: int, age_days: float | None = None) -> "Node":
        """Create (or overwrite) a child file."""
        child = Node(
            name=name,
            kind=KIND_FILE,
            size_bytes=int(size_bytes),
            age_days=self.age_days if age_days is None else float(age_days),
        )
        child.parent = self
        self.children[name] = child
        return child

    # -- queries ---------------------------------------------------------------

    @property
    def path(self) -> str:
        parts: list[str] = []
        node: Node | None = self
        while node is not None and node.name:
            parts.append(node.name)
            node = node.parent
        return "/" + "/".join(reversed(parts))

    @property
    def depth(self) -> int:
        count = 0
        node: Node | None = self
        while node is not None and node.name:
            count += 1
            node = node.parent
        return count

    def subtree_bytes(self) -> int:
        """Aggregate logical size (mirrors scanner directory aggregation)."""
        cached = getattr(self, "_cached_subtree_bytes", None)
        if cached is not None:
            return cached
        if self.kind == KIND_FILE:
            return self.size_bytes
        return sum(child.subtree_bytes() for child in self.children.values())

    def newest_age_days(self) -> float | None:
        """Age of the NEWEST entry in the subtree (smallest age), INCLUDING
        the directory itself.

        Mirrors the engine's ``newest_subtree_mtimes`` for ``min_age_days``
        on directories: every scanned entry's mtime — the directory's own
        included — propagates to its ancestor dirs via ``Path::ancestors()``
        (which yields the path itself first). Returns None for files.
        """
        cached = getattr(self, "_cached_newest_age", ...)
        if cached is not ...:
            return cached
        if self.kind == KIND_FILE:
            return None
        return min(child.age_days for child in self.walk())

    def freeze(self) -> None:
        """Cache subtree aggregates bottom-up (call once after building)."""
        for child in self.children.values():
            child.freeze()
        if self.kind == KIND_FILE:
            self._cached_subtree_bytes = self.size_bytes
            self._cached_newest_age = None
            return
        total = 0
        newest: float = self.age_days  # the directory's own mtime counts
        for child in self.children.values():
            total += child.subtree_bytes()
            candidates = [child.age_days]
            child_newest = child.newest_age_days()
            if child_newest is not None:
                candidates.append(child_newest)
            for age in candidates:
                if age < newest:
                    newest = age
        self._cached_subtree_bytes = total
        self._cached_newest_age = newest
        # Per-directory context flags (one pass over the direct children).
        self._dir_has_gitignore = ".gitignore" in self.children
        self._dir_has_lockfile = any(name in _LOCKFILE_SET for name in self.children)
        self._dir_has_marker = any(
            name in _MARKER_SET
            or (name == ".git" and self.children[name].kind == KIND_DIRECTORY)
            for name in self.children
        )

    def walk(self) -> Iterator["Node"]:
        yield self
        for child in self.children.values():
            yield from child.walk()

    def find(self, path_parts: list[str]) -> "Node | None":
        node = self
        for part in path_parts:
            child = node.children.get(part)
            if child is None:
                return None
            node = child
        return node

    def has_child(self, name: str) -> bool:
        return name in self.children


def build_root() -> Node:
    """An anonymous root ("" name) so child paths start at '/'."""
    return Node(name="", kind=KIND_DIRECTORY)


# --- Sample extraction --------------------------------------------------------


def node_to_sample(node: Node) -> FileSample:
    """Derive the FileSample (entry + context) for a node FROM THE TREE.

    Context semantics mirror the Rust engine's ``build_contexts`` +
    the v2 ancestor extensions:
      - has_gitignore / has_lockfile / sibling_count / sibling_total_bytes
        describe the node's PARENT directory contents;
      - ancestor_* flags scan every ancestor directory (parent upward).
    """
    parent = node.parent
    siblings = list(parent.children.values()) if parent is not None else []
    if parent is not None and getattr(parent, "_dir_has_gitignore", None) is not None:
        has_gitignore = parent._dir_has_gitignore
        has_lockfile = parent._dir_has_lockfile
    else:
        has_gitignore = any(s.name == ".gitignore" for s in siblings)
        has_lockfile = any(s.name in _LOCKFILE_SET for s in siblings)
    sibling_total = sum(s.subtree_bytes() for s in siblings)

    ancestor_lockfile = False
    ancestor_marker = False
    ancestor = parent
    while ancestor is not None:
        if getattr(ancestor, "_dir_has_lockfile", None) is not None:
            ancestor_lockfile = ancestor_lockfile or ancestor._dir_has_lockfile
            ancestor_marker = ancestor_marker or ancestor._dir_has_marker
        else:
            for child in ancestor.children.values():
                if child.name in _LOCKFILE_SET:
                    ancestor_lockfile = True
                if child.name in _MARKER_SET or (
                    child.name == ".git" and child.kind == KIND_DIRECTORY
                ):
                    ancestor_marker = True
        if ancestor_lockfile and ancestor_marker:
            break
        ancestor = ancestor.parent

    size = node.subtree_bytes() if node.kind == KIND_DIRECTORY else node.size_bytes
    return FileSample(
        path=node.path,
        kind=node.kind,
        size_bytes=size,
        age_days=node.age_days,
        depth=node.depth,
        has_gitignore=has_gitignore,
        has_lockfile=has_lockfile,
        sibling_count=len(siblings),
        sibling_total_bytes=sibling_total,
        ancestor_has_lockfile=ancestor_lockfile,
        ancestor_has_project_marker=ancestor_marker,
    )
