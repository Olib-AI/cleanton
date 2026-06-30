"""Rule-based labeler grounded in the cleanton recipe corpus + protected paths.

Labels are NOT hand-assigned per sample. Instead every synthetic path is run
through ``derive_label`` which encodes the same safety rules the shipped engine
enforces:

* ``crates/cleanton-common/src/safety.rs`` ``HARDCODED_PROTECTED`` /
  ``USER_PROTECTED`` -> anything inside a protected root, or any credential
  basename, is **Keep** and can never be classified cleanable.
* ``recipes/*.toml`` regenerable caches / build artifacts (target with a Cargo
  lockfile, node_modules with package evidence, ``__pycache__``/``*.pyc``,
  ``~/Library/Caches/...``, the Claude statsig cache, etc.) -> **SafeToRemove**.
* Long-unused / orphaned waste (old venvs, old logs, orphaned app support, old
  large checkpoints, stale wandb runs) -> **LikelyJunk**.
* Everything else (genuine near-miss decoys: a loose ``target`` with no project
  evidence, a random archive in Downloads, an unknown blob) -> **Uncertain**.

The home directory of every synthetic path is ``/Users/dev``.
"""

from __future__ import annotations

import posixpath

from features import FileSample, is_source_ext

# Label ids (mirror of the sidecar ``label_order`` consumed by Rust).
KEEP = 0
SAFE_TO_REMOVE = 1
LIKELY_JUNK = 2
UNCERTAIN = 3

LABEL_NAMES = ("keep", "safe-to-remove", "likely-junk", "uncertain")
NUM_CLASSES = len(LABEL_NAMES)

# A clean-class label is one that authorizes removal; predicting any of these on
# a true Keep file is a catastrophic false positive.
CLEAN_LABELS = frozenset({SAFE_TO_REMOVE, LIKELY_JUNK})

HOME = "/Users/dev"

# Mirror of safety.rs HARDCODED_PROTECTED.
_HARDCODED_PROTECTED = (
    "/System",
    "/Library",
    "/usr",
    "/bin",
    "/sbin",
    "/private",
    "/etc",
    "/var",
    "/Applications",
)

# Mirror of safety.rs USER_PROTECTED (home-relative).
_USER_PROTECTED = (
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
)

# Sensitive basenames the engine treats as a hard floor (credentials/config).
_CREDENTIAL_BASENAMES = frozenset(
    {
        ".credentials.json",
        "credentials",
        "credentials.json",
        "settings.json",
        "settings.local.json",
        ".claude.json",
        "mcp.json",
        ".mcp.json",
        "id_rsa",
        "id_ed25519",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "login.keychain-db",
        "secring.gpg",
    }
)


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def is_protected(path: str) -> bool:
    for root in _HARDCODED_PROTECTED:
        if _under(path, root):
            return True
    for rel in _USER_PROTECTED:
        if _under(path, posixpath.join(HOME, rel)):
            return True
    return False


def _has_component(path: str, name: str) -> bool:
    return name in [part for part in path.split("/") if part]


def derive_label(sample: FileSample) -> int:
    """Derive the 4-class label for a path from recipe + protected-path rules."""

    path = sample.path
    basename = posixpath.basename(path)
    low = path.lower()

    # 1. Protected roots and credential basenames are ALWAYS Keep. This is the
    #    safety floor: it dominates every other rule.
    if is_protected(path) or basename in _CREDENTIAL_BASENAMES:
        return KEEP

    # 1b. Agent histories the ai-claude-code-cache recipe explicitly EXCLUDES
    #     from cleaning (transcripts, todos, history, sessions) are Keep. Only
    #     the ~/.claude/statsig cache is regenerable; everything else under
    #     ~/.claude that is not a credential basename is kept.
    _claude_keep = tuple(
        posixpath.join(HOME, ".claude", part)
        for part in ("projects", "todos", "history", "sessions")
    )
    if any(_under(path, root) for root in _claude_keep):
        return KEEP

    # 2. Regenerable global caches under ~/Library/Caches, ~/.cache, and the
    #    Claude statsig cache are recipe-matched SafeToRemove (these dirs are
    #    NOT in the protected set).
    cache_roots = (
        posixpath.join(HOME, "Library/Caches"),
        posixpath.join(HOME, ".cache"),
        posixpath.join(HOME, ".npm/_cacache"),
        posixpath.join(HOME, ".claude/statsig"),
        posixpath.join(HOME, "Library/Developer/Xcode/DerivedData"),
    )
    if any(_under(path, root) for root in cache_roots):
        return SAFE_TO_REMOVE

    # 3. Build artifacts / dependency dirs with local project evidence are
    #    recipe-matched SafeToRemove (rust target, node_modules, __pycache__,
    #    dist/build/out, .pyc/.pyo, .next).
    if _has_component(path, "__pycache__") or basename.endswith((".pyc", ".pyo")):
        return SAFE_TO_REMOVE
    if _has_component(path, "node_modules") and sample.has_lockfile:
        return SAFE_TO_REMOVE
    if _has_component(path, "target") and (sample.has_lockfile or sample.has_gitignore):
        return SAFE_TO_REMOVE
    if any(
        _has_component(path, part) for part in ("dist", "build", "out", ".next", ".parcel-cache")
    ) and (sample.has_lockfile or sample.has_gitignore):
        return SAFE_TO_REMOVE

    # 4. Long-unused / orphaned waste -> LikelyJunk.
    if _has_component(path, ".venv") and sample.age_days >= 30:
        return LIKELY_JUNK
    if _under(path, posixpath.join(HOME, "Library/Logs")) and sample.age_days >= 30:
        return LIKELY_JUNK
    if "orphanedapp" in low and sample.age_days >= 30:
        return LIKELY_JUNK
    if basename.endswith(".ckpt") and sample.age_days >= 14 and sample.size_bytes >= 100_000_000:
        return LIKELY_JUNK
    if _has_component(path, "wandb") and sample.age_days >= 30:
        return LIKELY_JUNK
    if basename in (".DS_Store",) and sample.age_days >= 30:
        return LIKELY_JUNK

    # 5. Genuine source files outside build/cache are Keep.
    if is_source_ext(path) and not _has_component(path, "node_modules"):
        if not any(
            _has_component(path, part)
            for part in ("target", "dist", "build", "out", ".next", "__pycache__")
        ):
            return KEEP

    # 6. Everything else is ambiguous -> Uncertain (near-miss decoys land here:
    #    a loose ``target`` with no project evidence, a random archive, an
    #    unknown blob).
    return UNCERTAIN
