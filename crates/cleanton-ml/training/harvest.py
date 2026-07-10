"""Optional read-only local harvest (OFF by default; ``--harvest`` opt-in).

Walks THIS machine's home directory collecting **metadata only** — path
shape, extension, size, mtime, depth, per-directory context — never file
contents, and never anything under a safety-floor protected root
(``safety.rs`` HARDCODED_PROTECTED + USER_PROTECTED are skipped entirely).
Strictly read-only: no file is opened, created, modified, or removed.

Output: a JSON calibration summary (size/age quantiles per extension
class) plus a real-world eval matrix — feature vectors for the harvested
entries, with the subset that carries a sensitive basename marked as
definite keeps (evaluate.py reports the model's cleanable-rate on them).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import numpy as np

from . import recipes_dsl as dsl
from .features import (
    _ARCHIVE_EXT_IDS,
    _ARTIFACT_EXT_IDS,
    _DOC_EXT_IDS,
    _MEDIA_EXT_IDS,
    _ML_WEIGHT_EXT_IDS,
    _SOURCE_EXT_IDS,
    FileSample,
    extension_id,
    extract_features,
)
from .vocab import LOCKFILES, PROJECT_MARKERS

MAX_ENTRIES = 200_000
MAX_SECONDS = 120.0

_LOCKS = frozenset(LOCKFILES)
_MARKERS = frozenset(PROJECT_MARKERS)


def _protected_roots(home: str) -> list[str]:
    # A hardcoded root that is an ANCESTOR of the walked home would prune the
    # entire walk (nothing would ever be harvested); the roots exist to stop
    # us descending INTO protected territory from an unprotected home, so
    # ancestors of home are excluded here. On a real machine (/Users/<name>)
    # no hardcoded root is an ancestor and the list is used verbatim.
    roots = [
        root for root in dsl.HARDCODED_PROTECTED
        if not (home == root or home.startswith(root + os.sep))
    ]
    roots.extend(os.path.join(home, rel) for rel in dsl.USER_PROTECTED)
    return roots


def _ext_class(ext_id: int) -> str:
    if ext_id in _SOURCE_EXT_IDS:
        return "source"
    if ext_id in _MEDIA_EXT_IDS:
        return "media"
    if ext_id in _DOC_EXT_IDS:
        return "doc"
    if ext_id in _ARCHIVE_EXT_IDS:
        return "archive"
    if ext_id in _ARTIFACT_EXT_IDS:
        return "artifact"
    if ext_id in _ML_WEIGHT_EXT_IDS:
        return "ml_weight"
    return "other"


def harvest(home: str | None = None, max_entries: int = MAX_ENTRIES) -> dict:
    home = home or os.path.expanduser("~")
    protected = _protected_roots(home)
    now = time.time()
    deadline = now + MAX_SECONDS

    rows: list[FileSample] = []
    sensitive_keep_idx: list[int] = []
    class_sizes: dict[str, list[float]] = {}
    class_ages: dict[str, list[float]] = {}

    ancestor_lock: dict[str, bool] = {}
    ancestor_marker: dict[str, bool] = {}

    for dirpath, dirnames, filenames in os.walk(home, topdown=True, followlinks=False):
        if time.time() > deadline or len(rows) >= max_entries:
            break
        # Prune protected roots entirely (never even list them).
        dirnames[:] = [
            d for d in dirnames
            if not any(
                os.path.join(dirpath, d) == root or os.path.join(dirpath, d).startswith(root + os.sep)
                for root in protected
            )
        ]
        names = set(filenames) | set(dirnames)
        has_gitignore = ".gitignore" in names
        has_lockfile = bool(names & _LOCKS)
        has_marker = bool(names & _MARKERS) or ".git" in dirnames
        parent = os.path.dirname(dirpath)
        anc_lock = has_lockfile or ancestor_lock.get(parent, False)
        anc_marker = has_marker or ancestor_marker.get(parent, False)
        ancestor_lock[dirpath] = anc_lock
        ancestor_marker[dirpath] = anc_marker

        sibling_count = len(filenames) + len(dirnames)
        sizes: dict[str, int] = {}
        total = 0
        for name in filenames:
            try:
                stat = os.lstat(os.path.join(dirpath, name))
            except OSError:
                continue
            sizes[name] = stat.st_size
            total += stat.st_size

        depth_base = len([p for p in dirpath.split(os.sep) if p])
        for name in filenames:
            if len(rows) >= max_entries:
                break
            full = os.path.join(dirpath, name)
            try:
                stat = os.lstat(full)
            except OSError:
                continue
            age = max(0.0, (now - stat.st_mtime) / 86_400.0)
            sample = FileSample(
                path=full, kind="file", size_bytes=stat.st_size, age_days=age,
                depth=depth_base + 1, has_gitignore=has_gitignore,
                has_lockfile=has_lockfile, sibling_count=sibling_count,
                sibling_total_bytes=total, ancestor_has_lockfile=anc_lock,
                ancestor_has_project_marker=anc_marker,
            )
            if dsl.is_sensitive_basename(full):
                sensitive_keep_idx.append(len(rows))
            rows.append(sample)
            cls = _ext_class(extension_id(full))
            class_sizes.setdefault(cls, []).append(float(stat.st_size))
            class_ages.setdefault(cls, []).append(age)

    def quantiles(values: list[float]) -> dict[str, float]:
        if not values:
            return {}
        arr = np.asarray(values)
        return {
            "p10": float(np.quantile(arr, 0.10)),
            "p50": float(np.quantile(arr, 0.50)),
            "p90": float(np.quantile(arr, 0.90)),
            "p99": float(np.quantile(arr, 0.99)),
            "n": int(len(arr)),
        }

    features = (
        np.stack([extract_features(s) for s in rows]).astype(np.float32)
        if rows else np.empty((0, 53), dtype=np.float32)
    )
    return {
        "home": home,
        "entries": len(rows),
        "calibration": {
            "size_bytes": {cls: quantiles(v) for cls, v in class_sizes.items()},
            "age_days": {cls: quantiles(v) for cls, v in class_ages.items()},
        },
        "features": features,
        "paths": [s.path for s in rows],
        "sensitive_keep_indices": sensitive_keep_idx,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="read-only metadata harvest")
    parser.add_argument("--out", required=True, help="output .npz path")
    parser.add_argument("--home", default=None)
    parser.add_argument("--max-entries", type=int, default=MAX_ENTRIES)
    args = parser.parse_args(argv)

    result = harvest(args.home, args.max_entries)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        out,
        features=result["features"],
        sensitive_keep_indices=np.asarray(result["sensitive_keep_indices"], dtype=np.int64),
    )
    summary = {k: result[k] for k in ("home", "entries", "calibration")}
    out.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2))
    print(f"harvested {result['entries']} entries (metadata only) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
