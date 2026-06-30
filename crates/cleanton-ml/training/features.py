"""Zero-drift feature extraction.

This is a bit-for-bit Python mirror of the Rust ``extract_features_at`` logic in
``crates/cleanton-ml/src/lib.rs``. The 12-feature schema, the extension/parent
category tables, and the binary signal predicates MUST match Rust exactly so the
training distribution lines up with what the shipped extractor produces at
inference time.

Do NOT change the schema here without changing Rust in lockstep.
"""

from __future__ import annotations

import math
import posixpath
from dataclasses import dataclass

import numpy as np

FEATURE_COUNT = 12
FEATURE_NAMES = (
    "extension_id",
    "size_log10",
    "age_days",
    "depth",
    "parent_id",
    "has_gitignore",
    "has_lockfile",
    "is_hidden",
    "sibling_count",
    "in_build_dir",
    "is_source_ext",
    "in_cache_dir",
)

# --- Extension category table (mirror of Rust EXTENSION_ID_* constants) -------
# Maps a lowercase extension string to its integer category id.
_EXTENSION_IDS: dict[str, int] = {
    "rs": 1,
    "swift": 2,
    "ts": 3,
    "tsx": 4,
    "js": 5,
    "jsx": 6,
    "py": 7,
    "go": 8,
    "java": 9,
    "kt": 10,
    "kts": 10,
    "c": 11,
    "h": 12,
    "cc": 13,
    "cpp": 13,
    "cxx": 13,
    "hh": 14,
    "hpp": 14,
    "hxx": 14,
    "cs": 15,
    "rb": 16,
    "php": 17,
    "scala": 18,
    "sh": 19,
    "bash": 19,
    "zsh": 20,
    "fish": 21,
    "html": 22,
    "htm": 22,
    "css": 23,
    "scss": 24,
    "sass": 24,
    "json": 25,
    "toml": 26,
    "yaml": 27,
    "yml": 28,
    "lock": 29,
    "md": 30,
    "markdown": 30,
    "txt": 31,
    "log": 32,
    "tmp": 33,
    "cache": 34,
    "pyc": 35,
    "pyo": 35,
    "o": 36,
    "obj": 36,
    "so": 37,
    "dylib": 38,
    "dll": 39,
    "exe": 40,
    "a": 41,
    "lib": 41,
    "wasm": 42,
    "class": 43,
    "jar": 44,
    "zip": 45,
    "gz": 46,
    "tar": 47,
    "tgz": 48,
    "png": 49,
    "jpg": 50,
    "jpeg": 51,
    "gif": 52,
    "webp": 53,
    "svg": 54,
    "pdf": 55,
    "db": 56,
    "sqlite": 57,
    "sqlite3": 58,
    "ckpt": 59,
    "pt": 59,
    "pth": 59,
    "safetensors": 60,
    "onnx": 61,
}

# Source-code extension ids (mirror of Rust ``is_source_extension``).
_SOURCE_EXT_IDS: frozenset[int] = frozenset(range(1, 25))  # rs(1) .. scss(24)

# --- Parent directory category table (mirror of Rust PARENT_ID_* constants) ---
_PARENT_IDS: dict[str, int] = {
    "target": 1,
    "build": 2,
    ".build": 2,
    "dist": 3,
    "out": 4,
    "cache": 5,
    ".cache": 5,
    "tmp": 6,
    "temp": 6,
    "node_modules": 7,
    "src": 8,
    "sources": 9,
    "tests": 10,
    "__tests__": 10,
    "test": 11,
    "docs": 12,
    "doc": 12,
    "assets": 13,
    "resources": 13,
    "deriveddata": 14,
    ".next": 15,
    ".nuxt": 16,
    ".venv": 17,
    "venv": 17,
    ".tox": 18,
    ".mypy_cache": 19,
    ".pytest_cache": 20,
    ".git": 21,
    ".cargo": 22,
    "cargo": 22,
    "wandb": 23,
}

_BUILD_COMPONENTS: frozenset[str] = frozenset(
    {
        "target",
        "build",
        ".build",
        "dist",
        "out",
        ".next",
        ".nuxt",
        ".svelte-kit",
        "coverage",
        "deriveddata",
        "debug",
        "release",
    }
)

# File kinds (mirror of Rust FileKind).
KIND_FILE = "file"
KIND_DIRECTORY = "directory"


@dataclass(frozen=True)
class FileSample:
    """Raw metadata for one path, the input to feature extraction.

    Mirrors the fields the Rust extractor reads from ``FileEntry`` +
    ``FileContext``.
    """

    path: str
    kind: str = KIND_FILE
    size_bytes: int = 0
    age_days: float = 0.0
    depth: int = 0
    has_gitignore: bool = False
    has_lockfile: bool = False
    sibling_count: int = 0


def _extension(path: str) -> str | None:
    name = posixpath.basename(path)
    # Rust ``Path::extension`` returns None for dotfiles with no internal dot
    # (e.g. ``.gitignore``) and for trailing-dot names.
    dot = name.rfind(".")
    if dot <= 0 or dot == len(name) - 1:
        return None
    return name[dot + 1 :]


def extension_id(path: str) -> int:
    ext = _extension(path)
    if ext is None:
        return 0
    return _EXTENSION_IDS.get(ext.lower(), 0)


def _directory_id(directory: str) -> int:
    return _PARENT_IDS.get(directory.lower(), 0)


def parent_id(path: str) -> int:
    parent = posixpath.dirname(path)
    if not parent:
        return 0
    name = posixpath.basename(parent)
    if not name:
        return 0
    return _directory_id(name)


def is_source_ext(path: str) -> bool:
    return extension_id(path) in _SOURCE_EXT_IDS


def _signal_path(path: str, kind: str) -> str:
    if kind == KIND_DIRECTORY:
        return path
    return posixpath.dirname(path)


def _components(path: str) -> list[str]:
    return [part for part in path.split("/") if part]


def in_build_dir(path: str, kind: str) -> bool:
    signal = _signal_path(path, kind)
    return any(part.lower() in _BUILD_COMPONENTS for part in _components(signal))


def in_cache_dir(path: str, kind: str) -> bool:
    signal = _signal_path(path, kind)
    for part in _components(signal):
        low = part.lower()
        if "cache" in low or "tmp" in low:
            return True
    return False


def is_hidden(path: str) -> bool:
    name = posixpath.basename(path)
    return name.startswith(".") and name not in (".", "..")


def _log10_count(value: int) -> float:
    return math.log10(float(value) + 1.0)


def _bounded_depth(depth: int) -> float:
    # Rust saturates depth into u16 before widening to f32.
    return float(min(max(depth, 0), 65535))


def extract_features(sample: FileSample) -> np.ndarray:
    """Return the 12-feature float32 vector for ``sample``."""

    values = np.empty(FEATURE_COUNT, dtype=np.float32)
    values[0] = float(extension_id(sample.path))
    values[1] = _log10_count(int(sample.size_bytes))
    values[2] = float(sample.age_days)
    values[3] = _bounded_depth(int(sample.depth))
    values[4] = float(parent_id(sample.path))
    values[5] = 1.0 if sample.has_gitignore else 0.0
    values[6] = 1.0 if sample.has_lockfile else 0.0
    values[7] = 1.0 if is_hidden(sample.path) else 0.0
    values[8] = _log10_count(int(sample.sibling_count))
    values[9] = 1.0 if in_build_dir(sample.path, sample.kind) else 0.0
    values[10] = 1.0 if is_source_ext(sample.path) else 0.0
    values[11] = 1.0 if in_cache_dir(sample.path, sample.kind) else 0.0
    return values


def _self_check() -> None:
    """Mirror of the Rust ``extracts_documented_twelve_feature_vector`` test.

    Confirms the documented example yields the exact same vector as Rust.
    """

    sample = FileSample(
        path="/workspace/project/target/cache/.artifact.rs",
        kind=KIND_FILE,
        size_bytes=999,
        age_days=2.0,
        depth=4,
        has_gitignore=True,
        has_lockfile=False,
        sibling_count=99,
    )
    got = extract_features(sample)
    expected = np.array(
        [1.0, 3.0, 2.0, 4.0, 5.0, 1.0, 0.0, 1.0, 2.0, 1.0, 1.0, 1.0],
        dtype=np.float32,
    )
    if not np.allclose(got, expected, atol=1e-6):
        raise AssertionError(f"feature parity self-check failed: {got} != {expected}")

    unknown = FileSample(path="/workspace/project/notes.unknown", size_bytes=1)
    got2 = extract_features(unknown)
    expected2 = np.array(
        [0.0, math.log10(2.0), 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        dtype=np.float32,
    )
    if not np.allclose(got2, expected2, atol=1e-6):
        raise AssertionError(f"feature parity self-check failed: {got2} != {expected2}")


if __name__ == "__main__":
    _self_check()
    print("features.py parity self-check passed")
