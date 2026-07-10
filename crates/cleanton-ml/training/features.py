"""Feature schema v2 — the reference implementation the Rust port mirrors.

Every feature is computable in Rust from ``FileEntry`` plus a cheap
``FileContext`` built from scan data alone (no extra filesystem access).
The exact formulas are documented per feature below and exported (with the
vocabulary tables and a schema hash) by ``python3 -m training.features
--schema`` so the Rust port can verify bit-for-bit parity.

Layout (FEATURE_COUNT = 53 float32 values):

  index  name                     kind         formula
  -----  ----                     ----         -------
  0      extension_id             categorical  EXTENSION_IDS[lowercase ext] or 0. Extension per Rust
                                               ``Path::extension``: substring after the last '.' of the
                                               basename; None for dotfiles (".gitignore") and names
                                               ending in '.'.
  1      parent_id                categorical  DIR_IDS[lowercase basename(dirname(path))] or 0.
  2      grandparent_id           categorical  DIR_IDS[lowercase basename(dirname(dirname(path)))] or 0.
  3      size_log10               numeric      log10((size_bytes as f64) + 1.0) as f32.
  4      age_log10                numeric      log10((age_days as f64) + 1.0) as f32, age_days computed
                                               as Rust does: duration_since(modified).as_secs_f64()/86400
                                               truncated to f32 first, 0.0 when modified is None.
  5      depth                    numeric      min(depth, 65535) as f32 (Rust: u16 saturation then widen).
                                               depth = number of NORMAL components of the absolute
                                               path (Rust: components() filtered to Component::Normal;
                                               "/Users/maya/x" -> 3) — NOT FileEntry.depth, which is
                                               relative to the scan root and varies with where the
                                               scan began.
  6      sibling_count_log10      numeric      log10((sibling_count as f64) + 1.0) as f32.
  7      name_len_log10           numeric      log10((utf8 byte length of basename) + 1.0) as f32.
  8      digit_ratio              numeric      (ascii digit bytes in basename as f32) /
                                               (utf8 byte length of basename as f32); 0.0 for empty.
  9      size_vs_siblings         numeric      size_log10 - log10((sibling_total_bytes as f64)+1.0) as f32.
  10     is_dir                   binary       kind == Directory.
  11     is_hidden                binary       basename starts with '.' and is not "." or "..".
  12     under_hidden_dir         binary       any component of dirname(path) starts with '.'.
  13     has_gitignore            binary       context (parent dir contains a .gitignore entry).
  14     has_lockfile             binary       context (parent dir contains a known lockfile).
  15     ancestor_has_lockfile    binary       context (any ancestor dir within the scan contains a
                                               known lockfile).
  16     ancestor_has_project_marker binary    context (any ancestor dir within the scan contains a
                                               PROJECT_MARKERS basename).
  17     in_build_dir             binary       any lowercased component of the SIGNAL PATH (the path
                                               itself for dirs, its parent for files) is in
                                               BUILD_COMPONENTS or starts with "cmake-build-".
  18     in_cache_dir             binary       any lowercased signal-path component contains "cache"
                                               or "tmp" (identical to v1).
  19     in_node_modules          binary       any signal-path component == "node_modules".
  20     in_venv                  binary       any signal-path component in VENV_COMPONENTS.
  21     in_git_dir               binary       any signal-path component == ".git".
  22     in_library               binary       any lowercased signal-path component == "library".
  23     in_library_caches        binary       consecutive lowercased signal-path components
                                               ("library", "caches").
  24     in_app_support           binary       consecutive ("library", "application support").
  25     in_containers            binary       consecutive ("library", "containers") or
                                               ("library", "group containers").
  26     in_logs                  binary       consecutive ("library", "logs") or any lowercased
                                               signal-path component == "logs".
  27     in_derived_data          binary       any lowercased signal-path component == "deriveddata".
  28     in_user_data             binary       full-path components: c[0].lower()=="users", len>=3 and
                                               c[2].lower() in {"desktop","documents","downloads",
                                               "pictures","movies","music"}.
  29     in_system_root           binary       first full-path component lowercased in
                                               {"system","library","usr","bin","sbin","private","etc",
                                               "var","applications"}.
  30     is_source_ext            binary       extension class == source.
  31     is_media_ext             binary       extension class == media.
  32     is_doc_ext               binary       extension class == doc.
  33     is_archive_ext           binary       extension class == archive.
  34     is_artifact_ext          binary       extension class == artifact (compiled/build outputs).
  35     is_ml_weight_ext         binary       extension class == ml_weight.
  36     is_log_tmp_ext           binary       extension class == log_tmp.
  37-52  name_hash_bucket_0..15   binary       basename lowercased, split on chars outside [a-z0-9];
                                               drop empty and all-digit tokens; for each token set
                                               bucket fnv1a32(token) % 16 to 1.0.
                                               fnv1a32: h=2166136261; per byte: h^=b; h=(h*16777619)
                                               mod 2^32.

Standardization: the sidecar carries mean/std per feature. For the 3
categorical slots mean=0.0/std=1.0 (identity) — the model consumes the raw
ids via in-graph embeddings (exported as one-hot Equal+MatMul; see
model.py). Rust applies (x - mean) / std elementwise exactly as for v1.
"""

from __future__ import annotations

import hashlib
import json
import math
import posixpath
import sys
from dataclasses import dataclass

import numpy as np

SCHEMA_VERSION = "v2"

# --- Extension vocabulary ------------------------------------------------------
# v1 ids 0..61 are preserved verbatim; v2 appends 62+. Multiple spellings may
# share an id (aliases), exactly like Rust's match arms.
EXTENSION_IDS: dict[str, int] = {
    # v1 table (unchanged ids)
    "rs": 1, "swift": 2, "ts": 3, "tsx": 4, "js": 5, "jsx": 6, "py": 7,
    "go": 8, "java": 9, "kt": 10, "kts": 10, "c": 11, "h": 12,
    "cc": 13, "cpp": 13, "cxx": 13, "hh": 14, "hpp": 14, "hxx": 14,
    "cs": 15, "rb": 16, "php": 17, "scala": 18, "sh": 19, "bash": 19,
    "zsh": 20, "fish": 21, "html": 22, "htm": 22, "css": 23,
    "scss": 24, "sass": 24, "json": 25, "toml": 26, "yaml": 27, "yml": 28,
    "lock": 29, "md": 30, "markdown": 30, "txt": 31, "log": 32, "tmp": 33,
    "cache": 34, "pyc": 35, "pyo": 35, "o": 36, "obj": 36, "so": 37,
    "dylib": 38, "dll": 39, "exe": 40, "a": 41, "lib": 41, "wasm": 42,
    "class": 43, "jar": 44, "zip": 45, "gz": 46, "tar": 47, "tgz": 48,
    "png": 49, "jpg": 50, "jpeg": 51, "gif": 52, "webp": 53, "svg": 54,
    "pdf": 55, "db": 56, "sqlite": 57, "sqlite3": 58,
    "ckpt": 59, "pt": 59, "pth": 59, "safetensors": 60, "onnx": 61,
    # v2 additions
    "ipynb": 62, "whl": 63, "dmg": 64, "pkg": 65,
    "mov": 66, "mp4": 67, "m4v": 67, "avi": 68, "mkv": 69, "webm": 70,
    "mp3": 71, "m4a": 72, "aac": 72, "wav": 73, "flac": 74, "ogg": 75,
    "heic": 76, "heif": 76, "tiff": 77, "tif": 77, "bmp": 78, "raw": 79,
    "docx": 80, "doc": 80, "xlsx": 81, "xls": 81, "pptx": 82, "ppt": 82,
    "key": 83, "pages": 84, "numbers": 85, "csv": 86, "tsv": 86,
    "xml": 87, "plist": 88, "rlib": 89, "rmeta": 90, "d": 91, "pdb": 92,
    "node": 93, "map": 94, "ttf": 95, "otf": 95, "woff": 96, "woff2": 96,
    "ico": 97, "icns": 98, "jsonl": 99, "parquet": 100, "arrow": 100,
    "npy": 101, "npz": 101, "h5": 102, "hdf5": 102, "gguf": 103,
    "bin": 104, "dat": 105, "swp": 106, "bak": 107, "old": 107, "orig": 107,
    "part": 108, "crdownload": 108, "download": 108, "torrent": 109,
    "iso": 110, "xz": 111, "bz2": 111, "7z": 112, "rar": 112, "zst": 113,
    "br": 113, "deb": 114, "rpm": 114, "apk": 115, "ipa": 115, "aab": 115,
    "mjs": 116, "cjs": 116, "vue": 117, "svelte": 118, "astro": 118,
    "dart": 119, "ex": 120, "exs": 120, "erl": 120, "hs": 121, "jl": 122,
    "lua": 123, "r": 124, "m": 125, "mm": 125, "proto": 126,
    "graphql": 126, "sql": 127, "tfstate": 128, "tfvars": 128,
    "dsym": 129, "xcarchive": 129, "car": 130, "nib": 130, "storyboardc": 130,
    "pack": 131, "idx": 131, "pb": 132, "tflite": 132, "mlmodel": 132,
    "env": 133, "pem": 134, "p12": 134, "cer": 134, "crt": 134,
    "gitignore": 135, "editorconfig": 135,
}
EXTENSION_VOCAB_SIZE = 136  # ids 0..135 (0 = unknown)

# Extension classes (feature 30-36). Every id maps to at most one class.
_SOURCE_EXT_IDS = frozenset(range(1, 25)) | frozenset(
    {116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127}
)
_MEDIA_EXT_IDS = frozenset({49, 50, 51, 52, 53, 54, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79})
_DOC_EXT_IDS = frozenset({30, 31, 55, 80, 81, 82, 83, 84, 85, 86})
_ARCHIVE_EXT_IDS = frozenset({44, 45, 46, 47, 48, 63, 64, 65, 109, 110, 111, 112, 113, 114, 115})
_ARTIFACT_EXT_IDS = frozenset({35, 36, 37, 38, 39, 40, 41, 42, 43, 89, 90, 91, 92, 93, 94, 129, 130, 131})
_ML_WEIGHT_EXT_IDS = frozenset({59, 60, 61, 102, 103, 132})
_LOG_TMP_EXT_IDS = frozenset({32, 33, 34, 106, 107, 108})

# --- Directory vocabulary (parent_id / grandparent_id) ---------------------------
# v1 ids 0..23 preserved; v2 appends 24+. Keys are lowercased directory names.
DIR_IDS: dict[str, int] = {
    # v1 table (unchanged ids)
    "target": 1, "build": 2, ".build": 2, "dist": 3, "out": 4,
    "cache": 5, ".cache": 5, "tmp": 6, "temp": 6, "node_modules": 7,
    "src": 8, "sources": 9, "tests": 10, "__tests__": 10, "test": 11,
    "docs": 12, "doc": 12, "assets": 13, "resources": 13,
    "deriveddata": 14, ".next": 15, ".nuxt": 16, ".venv": 17, "venv": 17,
    ".tox": 18, ".mypy_cache": 19, ".pytest_cache": 20, ".git": 21,
    ".cargo": 22, "cargo": 22, "wandb": 23,
    # v2 additions
    "__pycache__": 24, "site-packages": 25, "checkpoints": 26,
    "lightning_logs": 27, "logs": 28, "log": 28,
    "downloads": 29, "documents": 30, "desktop": 31, "pictures": 32,
    "movies": 33, "music": 34, "library": 35, "caches": 36,
    "applications": 37, "containers": 38, "group containers": 38,
    "application support": 39, "preferences": 40,
    ".gradle": 41, "gradle": 41, ".npm": 42, "_cacache": 43,
    ".yarn": 44, ".pnpm-store": 45, ".bun": 46, ".deno": 47,
    ".docker": 48, ".kube": 49, ".ssh": 50, ".aws": 51, ".config": 52,
    ".local": 53, "share": 54, "bin": 55, "lib": 56, "include": 57,
    "frameworks": 58, "plugins": 59, "extensions": 60, "models": 61,
    "datasets": 62, "data": 63, "weights": 64, "runs": 65,
    "outputs": 66, "output": 66, "artifacts": 67, ".terraform": 68,
    ".stack-work": 69, "_build": 70, "zig-cache": 71, "zig-out": 71,
    ".dart_tool": 72, ".pub-cache": 73, ".cocoapods": 74, "pods": 75,
    ".idea": 76, ".vscode": 77, "objects": 78, "blobs": 79,
    "snapshots": 80, "refs": 81, "statsig": 82, "huggingface": 83,
    "hub": 84, "torch": 85, "pip": 86, "wheels": 87, "homebrew": 88,
    ".rustup": 89, "toolchains": 90, "registry": 91, "git": 92,
    "worktrees": 93, "coverage": 94, ".claude": 95, "projects": 96,
    "sessions": 97, "history": 98, "todos": 99, "developer": 100,
    "xcode": 101, "simulator": 102, "devices": 103, "screenshots": 104,
    "attachments": 105, "mail": 106, "messages": 107, "keychains": 108,
    "incremental": 109, "deps": 110, ".fingerprint": 111, "release": 112,
    "debug": 113, "virtualenvs": 114, "pypoetry": 115, "uv": 116,
    "go-build": 117, "mod": 118, "pkg": 119, "vendor": 120,
}
DIR_VOCAB_SIZE = 121  # ids 0..120 (0 = unknown)

# --- Path component sets ----------------------------------------------------------
# v1 BUILD_COMPONENTS plus v2 ecosystem build dirs. Compared lowercased.
BUILD_COMPONENTS = frozenset({
    "target", "build", ".build", "dist", "out", ".next", ".nuxt",
    ".svelte-kit", "coverage", "deriveddata", "debug", "release",
    "zig-out", "zig-cache", "_build", ".stack-work",
})
CMAKE_BUILD_PREFIX = "cmake-build-"

VENV_COMPONENTS = frozenset({".venv", "venv", ".tox", "virtualenvs", "site-packages"})

USER_DATA_ROOTS = frozenset({"desktop", "documents", "downloads", "pictures", "movies", "music"})

SYSTEM_ROOTS = frozenset({
    "system", "library", "usr", "bin", "sbin", "private", "etc", "var",
    "applications",
})

FEATURE_NAMES: tuple[str, ...] = (
    "extension_id", "parent_id", "grandparent_id",
    "size_log10", "age_log10", "depth", "sibling_count_log10",
    "name_len_log10", "digit_ratio", "size_vs_siblings",
    "is_dir", "is_hidden", "under_hidden_dir",
    "has_gitignore", "has_lockfile", "ancestor_has_lockfile",
    "ancestor_has_project_marker",
    "in_build_dir", "in_cache_dir", "in_node_modules", "in_venv",
    "in_git_dir", "in_library", "in_library_caches", "in_app_support",
    "in_containers", "in_logs", "in_derived_data", "in_user_data",
    "in_system_root",
    "is_source_ext", "is_media_ext", "is_doc_ext", "is_archive_ext",
    "is_artifact_ext", "is_ml_weight_ext", "is_log_tmp_ext",
) + tuple(f"name_hash_bucket_{i}" for i in range(16))

FEATURE_COUNT = len(FEATURE_NAMES)
assert FEATURE_COUNT == 53

CATEGORICAL_COUNT = 3
NAME_HASH_BUCKETS = 16
NAME_HASH_OFFSET = 37  # index of name_hash_bucket_0

KIND_FILE = "file"
KIND_DIRECTORY = "directory"


@dataclass(frozen=True)
class FileSample:
    """Raw metadata for one path — mirrors Rust FileEntry + FileContext v2.

    ``size_bytes`` is ``logical_bytes`` (for directories the scanner reports
    the aggregated subtree size). ``sibling_total_bytes`` is the sum of
    logical bytes over the entries sharing the same parent (context).
    """

    path: str
    kind: str = KIND_FILE
    size_bytes: int = 0
    age_days: float = 0.0
    depth: int = 0
    has_gitignore: bool = False
    has_lockfile: bool = False
    sibling_count: int = 0
    sibling_total_bytes: int = 0
    ancestor_has_lockfile: bool = False
    ancestor_has_project_marker: bool = False


# --- Primitive helpers (each mirrors a Rust formula exactly) ----------------------

def _basename(path: str) -> str:
    return posixpath.basename(path)


def _extension(path: str) -> str | None:
    """Mirror of Rust ``Path::extension``."""
    name = _basename(path)
    dot = name.rfind(".")
    if dot <= 0 or dot == len(name) - 1:
        return None
    return name[dot + 1:]


def extension_id(path: str) -> int:
    ext = _extension(path)
    if ext is None:
        return 0
    return EXTENSION_IDS.get(ext.lower(), 0)


def dir_id(directory_basename: str) -> int:
    return DIR_IDS.get(directory_basename.lower(), 0)


def parent_id(path: str) -> int:
    parent = posixpath.dirname(path)
    name = posixpath.basename(parent)
    if not name:
        return 0
    return dir_id(name)


def grandparent_id(path: str) -> int:
    grandparent = posixpath.dirname(posixpath.dirname(path))
    name = posixpath.basename(grandparent)
    if not name:
        return 0
    return dir_id(name)


def _components(path: str) -> list[str]:
    return [part for part in path.split("/") if part]


def _signal_path(path: str, kind: str) -> str:
    """The path itself for directories, the parent for files (v1 convention)."""
    if kind == KIND_DIRECTORY:
        return path
    return posixpath.dirname(path)


def _signal_components(path: str, kind: str) -> list[str]:
    return _components(_signal_path(path, kind))


def _log10_plus1(value: float) -> float:
    return math.log10(value + 1.0)


def is_hidden(path: str) -> bool:
    name = _basename(path)
    return name.startswith(".") and name not in (".", "..")


def under_hidden_dir(path: str) -> bool:
    return any(part.startswith(".") for part in _components(posixpath.dirname(path)))


def in_build_dir(path: str, kind: str) -> bool:
    for part in _signal_components(path, kind):
        low = part.lower()
        if low in BUILD_COMPONENTS or low.startswith(CMAKE_BUILD_PREFIX):
            return True
    return False


def in_cache_dir(path: str, kind: str) -> bool:
    for part in _signal_components(path, kind):
        low = part.lower()
        if "cache" in low or "tmp" in low:
            return True
    return False


def _has_signal_component(path: str, kind: str, name: str) -> bool:
    return any(part == name for part in _signal_components(path, kind))


def _has_signal_component_lower(path: str, kind: str, name: str) -> bool:
    return any(part.lower() == name for part in _signal_components(path, kind))


def in_venv(path: str, kind: str) -> bool:
    return any(part in VENV_COMPONENTS for part in _signal_components(path, kind))


def _consecutive_lower(parts: list[str], first: str, second: str) -> bool:
    lows = [part.lower() for part in parts]
    return any(
        lows[i] == first and lows[i + 1] == second for i in range(len(lows) - 1)
    )


def in_library_caches(path: str, kind: str) -> bool:
    return _consecutive_lower(_signal_components(path, kind), "library", "caches")


def in_app_support(path: str, kind: str) -> bool:
    return _consecutive_lower(
        _signal_components(path, kind), "library", "application support"
    )


def in_containers(path: str, kind: str) -> bool:
    parts = _signal_components(path, kind)
    return _consecutive_lower(parts, "library", "containers") or _consecutive_lower(
        parts, "library", "group containers"
    )


def in_logs(path: str, kind: str) -> bool:
    parts = _signal_components(path, kind)
    return _consecutive_lower(parts, "library", "logs") or any(
        part.lower() == "logs" for part in parts
    )


def in_user_data(path: str) -> bool:
    parts = _components(path)
    return (
        len(parts) >= 3
        and parts[0].lower() == "users"
        and parts[2].lower() in USER_DATA_ROOTS
    )


def in_system_root(path: str) -> bool:
    parts = _components(path)
    return bool(parts) and parts[0].lower() in SYSTEM_ROOTS


def fnv1a32(data: bytes) -> int:
    h = 2166136261
    for byte in data:
        h ^= byte
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def name_hash_buckets(path: str) -> list[float]:
    """16 binary buckets over the basename's alphanumeric tokens."""
    buckets = [0.0] * NAME_HASH_BUCKETS
    token: list[str] = []
    lowered = _basename(path).lower()
    tokens: list[str] = []
    for ch in lowered:
        if ("a" <= ch <= "z") or ("0" <= ch <= "9"):
            token.append(ch)
        elif token:
            tokens.append("".join(token))
            token = []
    if token:
        tokens.append("".join(token))
    for tok in tokens:
        if tok.isdigit():
            continue
        buckets[fnv1a32(tok.encode("utf-8")) % NAME_HASH_BUCKETS] = 1.0
    return buckets


def _bounded_depth(depth: int) -> float:
    return float(min(max(depth, 0), 65535))


def _binary(value: bool) -> float:
    return 1.0 if value else 0.0


def extract_features(sample: FileSample) -> np.ndarray:
    """Return the 53-feature float32 vector for ``sample``."""
    path = sample.path
    kind = sample.kind
    name = _basename(path)
    name_bytes = name.encode("utf-8")
    name_len = len(name_bytes)
    digit_count = sum(1 for b in name_bytes if 0x30 <= b <= 0x39)

    ext_id = extension_id(path)
    size_log10 = np.float32(_log10_plus1(float(sample.size_bytes)))
    # age_days is truncated to f32 first (Rust computes it as f32), then the
    # log formula runs in f64 and truncates back — mirror both steps.
    age_f32 = np.float32(sample.age_days)
    sibling_total_log10 = np.float32(_log10_plus1(float(sample.sibling_total_bytes)))

    values = np.empty(FEATURE_COUNT, dtype=np.float32)
    values[0] = float(ext_id)
    values[1] = float(parent_id(path))
    values[2] = float(grandparent_id(path))
    values[3] = size_log10
    values[4] = np.float32(_log10_plus1(float(age_f32)))
    values[5] = _bounded_depth(int(sample.depth))
    values[6] = np.float32(_log10_plus1(float(int(sample.sibling_count))))
    values[7] = np.float32(_log10_plus1(float(name_len)))
    values[8] = np.float32(digit_count) / np.float32(name_len) if name_len else np.float32(0.0)
    values[9] = np.float32(size_log10 - sibling_total_log10)
    values[10] = _binary(kind == KIND_DIRECTORY)
    values[11] = _binary(is_hidden(path))
    values[12] = _binary(under_hidden_dir(path))
    values[13] = _binary(sample.has_gitignore)
    values[14] = _binary(sample.has_lockfile)
    values[15] = _binary(sample.ancestor_has_lockfile)
    values[16] = _binary(sample.ancestor_has_project_marker)
    values[17] = _binary(in_build_dir(path, kind))
    values[18] = _binary(in_cache_dir(path, kind))
    values[19] = _binary(_has_signal_component(path, kind, "node_modules"))
    values[20] = _binary(in_venv(path, kind))
    values[21] = _binary(_has_signal_component(path, kind, ".git"))
    values[22] = _binary(_has_signal_component_lower(path, kind, "library"))
    values[23] = _binary(in_library_caches(path, kind))
    values[24] = _binary(in_app_support(path, kind))
    values[25] = _binary(in_containers(path, kind))
    values[26] = _binary(in_logs(path, kind))
    values[27] = _binary(_has_signal_component_lower(path, kind, "deriveddata"))
    values[28] = _binary(in_user_data(path))
    values[29] = _binary(in_system_root(path))
    values[30] = _binary(ext_id in _SOURCE_EXT_IDS)
    values[31] = _binary(ext_id in _MEDIA_EXT_IDS)
    values[32] = _binary(ext_id in _DOC_EXT_IDS)
    values[33] = _binary(ext_id in _ARCHIVE_EXT_IDS)
    values[34] = _binary(ext_id in _ARTIFACT_EXT_IDS)
    values[35] = _binary(ext_id in _ML_WEIGHT_EXT_IDS)
    values[36] = _binary(ext_id in _LOG_TMP_EXT_IDS)
    values[NAME_HASH_OFFSET:NAME_HASH_OFFSET + NAME_HASH_BUCKETS] = name_hash_buckets(path)
    return values


# --- Schema export / hash ---------------------------------------------------------

def schema_dict() -> dict:
    """Canonical machine-readable schema for the Rust port + sidecar."""
    return {
        "version": SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "feature_order": list(FEATURE_NAMES),
        "categorical_count": CATEGORICAL_COUNT,
        "extension_vocab_size": EXTENSION_VOCAB_SIZE,
        "dir_vocab_size": DIR_VOCAB_SIZE,
        "extension_ids": dict(sorted(EXTENSION_IDS.items())),
        "dir_ids": dict(sorted(DIR_IDS.items())),
        "extension_classes": {
            "source": sorted(_SOURCE_EXT_IDS),
            "media": sorted(_MEDIA_EXT_IDS),
            "doc": sorted(_DOC_EXT_IDS),
            "archive": sorted(_ARCHIVE_EXT_IDS),
            "artifact": sorted(_ARTIFACT_EXT_IDS),
            "ml_weight": sorted(_ML_WEIGHT_EXT_IDS),
            "log_tmp": sorted(_LOG_TMP_EXT_IDS),
        },
        "build_components": sorted(BUILD_COMPONENTS),
        "cmake_build_prefix": CMAKE_BUILD_PREFIX,
        "venv_components": sorted(VENV_COMPONENTS),
        "user_data_roots": sorted(USER_DATA_ROOTS),
        "system_roots": sorted(SYSTEM_ROOTS),
        "name_hash": {
            "buckets": NAME_HASH_BUCKETS,
            "algorithm": "fnv1a32 over utf-8 token bytes, bucket = hash % 16",
            "tokenizer": "lowercase basename, split on chars outside [a-z0-9], drop empty and all-digit tokens",
        },
        # Semantics a Rust port must NOT guess (pinned here so the schema hash
        # covers them):
        "semantics": {
            "depth": "count of Normal components of the absolute path ('/Users/maya/x' -> 3); NOT FileEntry.depth (scan-root relative)",
            "size_bytes": "FileEntry.logical_bytes; directories use the scanner's aggregated subtree logical bytes",
            "age_days": "duration_since(modified).as_secs_f64()/86400 as f32; 0.0 when modified is None",
            "lowercase": "Unicode lowercase (Python str.lower / Rust char::to_lowercase); token chars are restricted to ASCII [a-z0-9] so the two agree on every ASCII name",
            "sibling_total_bytes": "sum of logical_bytes over entries sharing the parent directory (context v2)",
        },
    }


def schema_hash() -> str:
    canonical = json.dumps(schema_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def self_check() -> None:
    """Fixed-vector checks the Rust port must reproduce bit-for-bit."""
    sample = FileSample(
        path="/Users/dev/code/acme-api/target/debug/deps/libacme_api-8f2c.rlib",
        kind=KIND_FILE,
        size_bytes=999,
        age_days=2.0,
        depth=8,
        has_gitignore=False,
        has_lockfile=False,
        sibling_count=99,
        sibling_total_bytes=9_999,
        ancestor_has_lockfile=True,
        ancestor_has_project_marker=True,
    )
    got = extract_features(sample)
    checks = {
        0: 89.0,   # rlib
        1: 110.0,  # deps
        2: 113.0,  # debug
        3: 3.0,    # log10(1000)
        4: np.float32(math.log10(3.0)),
        5: 8.0,
        6: 2.0,    # log10(100)
        7: np.float32(math.log10(27.0)),  # len("libacme_api-8f2c.rlib")=21? recomputed below
        10: 0.0,
        15: 1.0,
        16: 1.0,
        17: 1.0,   # target + debug
        19: 0.0,
        30: 0.0,
        34: 1.0,   # artifact ext
    }
    name = "libacme_api-8f2c.rlib"
    checks[7] = np.float32(math.log10(len(name.encode()) + 1.0))
    checks[8] = np.float32(3.0) / np.float32(len(name.encode()))  # digits: 8,2,--wait '8f2c' has 8,2 => plus none
    # digits in "libacme_api-8f2c.rlib": '8', '2' -> 2 digits
    checks[8] = np.float32(2.0) / np.float32(len(name.encode()))
    for index, expected in checks.items():
        actual = got[index]
        if not math.isclose(float(actual), float(expected), abs_tol=1e-6):
            raise AssertionError(
                f"self-check failed at feature {index} ({FEATURE_NAMES[index]}): "
                f"{actual} != {expected}"
            )

    # Unknown blob: everything conservative-zero except size/name-derived slots.
    blob = FileSample(path="/opt/blob", size_bytes=1)
    got2 = extract_features(blob)
    if float(got2[0]) != 0.0 or float(got2[1]) != 0.0 or float(got2[29]) != 0.0:
        raise AssertionError("unknown blob should extract zero categorical/system signals")

    # Hash buckets are deterministic.
    if name_hash_buckets("/a/node_modules/react/index.js") != name_hash_buckets(
        "/b/x/index.js"
    ):
        raise AssertionError("name hash buckets must depend only on the basename")


def main(argv: list[str]) -> int:
    if "--schema" in argv:
        payload = schema_dict()
        payload["schema_sha256"] = schema_hash()
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    self_check()
    print(f"features v2 self-check passed; schema sha256 = {schema_hash()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
