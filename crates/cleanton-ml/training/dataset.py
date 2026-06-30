"""Deterministic synthetic macOS dataset generation.

Produces a large pool of realistic file/dir paths with metadata, derives every
label through :mod:`labeler` (so labels are grounded in recipes + protected
paths, never hand-set), then balances the classes. Also builds a held-out
*golden keep-set* of critical files (credentials, documents, source, system,
app containers, agent histories) used by :mod:`evaluate` to enforce the 0%
false-positive gate.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, replace

import numpy as np

import labeler
from features import (
    FEATURE_COUNT,
    KIND_DIRECTORY,
    KIND_FILE,
    FileSample,
    extract_features,
)

HOME = labeler.HOME

KB = 1024
MB = 1024 * 1024
GB = 1024 * MB


@dataclass
class Dataset:
    features: np.ndarray  # (N, 12) float32
    labels: np.ndarray  # (N,) int64
    samples: list[FileSample]


def _depth(path: str) -> int:
    return len([p for p in path.split("/") if p])


def _src_name(rng: random.Random) -> str:
    return rng.choice(
        ["main", "lib", "app", "utils", "handler", "model", "router", "index", "core", "view"]
    )


def _pkg(rng: random.Random) -> str:
    return rng.choice(
        ["react", "lodash", "left-pad", "chalk", "express", "vite", "eslint", "typescript", "axios"]
    )


def _project(rng: random.Random) -> str:
    return rng.choice(
        ["web-app", "api-server", "ml-pipeline", "cli-tool", "dashboard", "mobile", "infra", "site"]
    )


# Each template is a callable returning a FileSample. Templates are intentionally
# over-generated and re-balanced afterwards; the labeler decides the final class.
def _build_pool(rng: random.Random, per_template: int) -> list[FileSample]:
    samples: list[FileSample] = []

    def emit(make) -> None:
        for _ in range(per_template):
            samples.append(make())

    # --- Source code (-> Keep) -------------------------------------------------
    emit(
        lambda: FileSample(
            path=f"{HOME}/code/{_project(rng)}/src/{_src_name(rng)}.rs",
            kind=KIND_FILE,
            size_bytes=rng.randint(200, 40 * KB),
            age_days=rng.uniform(0, 120),
            depth=0,
            has_gitignore=True,
            has_lockfile=rng.random() < 0.6,
            sibling_count=rng.randint(3, 40),
        )
    )
    emit(
        lambda: FileSample(
            path=f"{HOME}/code/{_project(rng)}/src/{_src_name(rng)}."
            + rng.choice(["ts", "tsx", "py", "go", "swift", "js"]),
            kind=KIND_FILE,
            size_bytes=rng.randint(200, 40 * KB),
            age_days=rng.uniform(0, 200),
            depth=0,
            has_gitignore=True,
            has_lockfile=rng.random() < 0.5,
            sibling_count=rng.randint(3, 40),
        )
    )

    # --- User documents / media (-> Keep, protected) --------------------------
    emit(
        lambda: FileSample(
            path=f"{HOME}/Documents/{rng.choice(['report', 'thesis', 'invoice', 'notes', 'taxes'])}."
            + rng.choice(["pdf", "txt", "md", "docx"]),
            kind=KIND_FILE,
            size_bytes=rng.randint(10 * KB, 8 * MB),
            age_days=rng.uniform(0, 900),
            depth=0,
            sibling_count=rng.randint(2, 60),
        )
    )
    emit(
        lambda: FileSample(
            path=f"{HOME}/Pictures/{rng.choice(['IMG_2207', 'vacation', 'screenshot', 'family'])}."
            + rng.choice(["jpg", "jpeg", "png", "webp"]),
            kind=KIND_FILE,
            size_bytes=rng.randint(200 * KB, 12 * MB),
            age_days=rng.uniform(0, 1500),
            depth=0,
            sibling_count=rng.randint(10, 500),
        )
    )
    emit(
        lambda: FileSample(
            path=f"{HOME}/Desktop/{rng.choice(['draft', 'budget', 'todo'])}."
            + rng.choice(["txt", "md", "pdf", "key"]),
            kind=KIND_FILE,
            size_bytes=rng.randint(1 * KB, 4 * MB),
            age_days=rng.uniform(0, 400),
            depth=0,
            sibling_count=rng.randint(2, 30),
        )
    )

    # --- Credentials / secrets (-> Keep, protected) ---------------------------
    emit(
        lambda: FileSample(
            path=rng.choice(
                [
                    f"{HOME}/.ssh/id_rsa",
                    f"{HOME}/.ssh/id_ed25519",
                    f"{HOME}/.aws/credentials",
                    f"{HOME}/.config/gcloud/credentials.db",
                    f"{HOME}/.npmrc",
                    f"{HOME}/.netrc",
                    f"{HOME}/.gnupg/secring.gpg",
                    f"{HOME}/Library/Keychains/login.keychain-db",
                    f"{HOME}/.claude/.credentials.json",
                    f"{HOME}/.config/cleanton/config.toml",
                ]
            ),
            kind=KIND_FILE,
            size_bytes=rng.randint(64, 8 * KB),
            age_days=rng.uniform(0, 1200),
            depth=0,
            sibling_count=rng.randint(1, 10),
        )
    )

    # --- Agent histories + app containers (-> Keep) ---------------------------
    # Grounded in the ai-claude-code-cache recipe excludes (transcripts/history)
    # and the Library/Containers protected root.
    emit(
        lambda: FileSample(
            path=rng.choice(
                [
                    f"{HOME}/.claude/projects/{_project(rng)}/transcript.jsonl",
                    f"{HOME}/.claude/history/2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}.jsonl",
                    f"{HOME}/.claude/sessions/{rng.randint(1000, 9999)}.json",
                    f"{HOME}/.claude/todos/{_project(rng)}.json",
                    f"{HOME}/Library/Containers/com.apple.mail/Data/state.db",
                    f"{HOME}/Library/Containers/com.example.app/Data/Documents/{_src_name(rng)}.dat",
                ]
            ),
            kind=KIND_FILE,
            size_bytes=rng.randint(1 * KB, 40 * MB),
            age_days=rng.uniform(0, 600),
            depth=0,
            sibling_count=rng.randint(2, 80),
        )
    )

    # --- System paths (-> Keep, protected) ------------------------------------
    emit(
        lambda: FileSample(
            path=rng.choice(
                [
                    "/System/Library/Frameworks/Foundation.framework/Foundation",
                    "/usr/lib/libSystem.dylib",
                    "/Library/Frameworks/Python.framework/Versions/3.12/Python",
                    "/Applications/Safari.app/Contents/Info.plist",
                    "/private/etc/hosts",
                ]
            ),
            kind=KIND_FILE,
            size_bytes=rng.randint(4 * KB, 30 * MB),
            age_days=rng.uniform(0, 2000),
            depth=0,
            sibling_count=rng.randint(2, 80),
        )
    )

    # --- Rust build artifacts (-> SafeToRemove) -------------------------------
    emit(
        lambda: FileSample(
            path=f"{HOME}/code/{_project(rng)}/target/release/{_src_name(rng)}."
            + rng.choice(["o", "rlib", "d", "a"]),
            kind=KIND_FILE,
            size_bytes=rng.randint(100 * KB, 80 * MB),
            age_days=rng.uniform(0, 90),
            depth=0,
            has_gitignore=True,
            has_lockfile=True,
            sibling_count=rng.randint(20, 800),
        )
    )
    emit(
        lambda: FileSample(
            path=f"{HOME}/code/{_project(rng)}/target",
            kind=KIND_DIRECTORY,
            size_bytes=rng.randint(50 * MB, 4 * GB),
            age_days=rng.uniform(0, 60),
            depth=0,
            has_gitignore=True,
            has_lockfile=True,
            sibling_count=rng.randint(3, 12),
        )
    )

    # --- node_modules (-> SafeToRemove) ---------------------------------------
    emit(
        lambda: FileSample(
            path=f"{HOME}/code/{_project(rng)}/node_modules/{_pkg(rng)}/"
            + rng.choice(["index.js", "package.json", "dist/bundle.js"]),
            kind=KIND_FILE,
            size_bytes=rng.randint(1 * KB, 2 * MB),
            age_days=rng.uniform(0, 200),
            depth=0,
            has_gitignore=True,
            has_lockfile=True,
            sibling_count=rng.randint(50, 2000),
        )
    )

    # --- Python pyc / __pycache__ (-> SafeToRemove) ---------------------------
    emit(
        lambda: FileSample(
            path=f"{HOME}/code/{_project(rng)}/pkg/__pycache__/{_src_name(rng)}.cpython-312.pyc",
            kind=KIND_FILE,
            size_bytes=rng.randint(500, 200 * KB),
            age_days=rng.uniform(0, 120),
            depth=0,
            has_gitignore=True,
            sibling_count=rng.randint(3, 50),
        )
    )

    # --- dist / build / .next (-> SafeToRemove) -------------------------------
    emit(
        lambda: FileSample(
            path=f"{HOME}/code/{_project(rng)}/"
            + rng.choice(["dist", "build", "out", ".next"])
            + f"/{_src_name(rng)}."
            + rng.choice(["js", "css", "map", "html"]),
            kind=KIND_FILE,
            size_bytes=rng.randint(1 * KB, 5 * MB),
            age_days=rng.uniform(0, 60),
            depth=0,
            has_gitignore=True,
            has_lockfile=rng.random() < 0.5,
            sibling_count=rng.randint(5, 200),
        )
    )

    # --- Global regenerable caches (-> SafeToRemove) --------------------------
    emit(
        lambda: FileSample(
            path=rng.choice(
                [
                    f"{HOME}/Library/Caches/pip/wheels/{_pkg(rng)}.whl",
                    f"{HOME}/Library/Caches/Homebrew/downloads/{_pkg(rng)}.tar.gz",
                    f"{HOME}/.cache/{_pkg(rng)}/blob.bin",
                    f"{HOME}/.npm/_cacache/content-v2/sha512/{_pkg(rng)}",
                    f"{HOME}/.claude/statsig/statsig.cached.evaluations.2",
                    f"{HOME}/Library/Developer/Xcode/DerivedData/{_project(rng)}/Build/x.o",
                ]
            ),
            kind=KIND_FILE,
            size_bytes=rng.randint(4 * KB, 60 * MB),
            age_days=rng.uniform(7, 400),
            depth=0,
            sibling_count=rng.randint(10, 1000),
        )
    )

    # --- Old venvs (-> LikelyJunk) --------------------------------------------
    emit(
        lambda: FileSample(
            path=f"{HOME}/code/{_project(rng)}/.venv/lib/python3.12/site-packages/{_pkg(rng)}/x.py",
            kind=KIND_FILE,
            size_bytes=rng.randint(1 * KB, 4 * MB),
            age_days=rng.uniform(45, 600),
            depth=0,
            has_gitignore=True,
            sibling_count=rng.randint(20, 800),
        )
    )

    # --- Old logs (-> LikelyJunk) ---------------------------------------------
    emit(
        lambda: FileSample(
            path=f"{HOME}/Library/Logs/{_project(rng)}/session.log",
            kind=KIND_FILE,
            size_bytes=rng.randint(1 * KB, 50 * MB),
            age_days=rng.uniform(31, 720),
            depth=0,
            sibling_count=rng.randint(2, 40),
        )
    )

    # --- Orphaned app support (-> LikelyJunk) ---------------------------------
    emit(
        lambda: FileSample(
            path=f"{HOME}/Library/Application Support/OrphanedApp/data/{_src_name(rng)}.bin",
            kind=KIND_FILE,
            size_bytes=rng.randint(10 * KB, 200 * MB),
            age_days=rng.uniform(45, 900),
            depth=0,
            sibling_count=rng.randint(2, 60),
        )
    )

    # --- Old large ML checkpoints / wandb (-> LikelyJunk) ---------------------
    emit(
        lambda: FileSample(
            path=f"{HOME}/code/ml-pipeline/checkpoints/epoch-{rng.randint(1, 40)}.ckpt",
            kind=KIND_FILE,
            size_bytes=rng.randint(120 * MB, 3 * GB),
            age_days=rng.uniform(15, 400),
            depth=0,
            has_gitignore=True,
            sibling_count=rng.randint(2, 30),
        )
    )
    emit(
        lambda: FileSample(
            path=f"{HOME}/code/ml-pipeline/wandb/run-{rng.randint(1000, 9999)}/files/output.log",
            kind=KIND_FILE,
            size_bytes=rng.randint(10 * KB, 80 * MB),
            age_days=rng.uniform(31, 500),
            depth=0,
            sibling_count=rng.randint(2, 50),
        )
    )

    # --- Ambiguous near-miss decoys (-> Uncertain) ----------------------------
    # Loose "target"/"build"/"node_modules" with NO project evidence: must NOT
    # be SafeToRemove.
    emit(
        lambda: FileSample(
            path=f"{HOME}/scratch/loose/{rng.choice(['target', 'build', 'node_modules'])}/{_src_name(rng)}.bin",
            kind=KIND_FILE,
            size_bytes=rng.randint(1 * KB, 30 * MB),
            age_days=rng.uniform(0, 300),
            depth=0,
            has_gitignore=False,
            has_lockfile=False,
            sibling_count=rng.randint(1, 20),
        )
    )
    # Random archive in a non-protected scratch area.
    emit(
        lambda: FileSample(
            path=f"{HOME}/scratch/{rng.choice(['backup', 'archive', 'misc'])}/{_src_name(rng)}."
            + rng.choice(["zip", "tar", "gz", "tgz"]),
            kind=KIND_FILE,
            size_bytes=rng.randint(100 * KB, 800 * MB),
            age_days=rng.uniform(0, 700),
            depth=0,
            sibling_count=rng.randint(1, 25),
        )
    )
    # Unknown blob with no recognizable signals.
    emit(
        lambda: FileSample(
            path=f"{HOME}/scratch/{_src_name(rng)}."
            + rng.choice(["bin", "dat", "unknown", "out"]),
            kind=KIND_FILE,
            size_bytes=rng.randint(0, 100 * MB),
            age_days=rng.uniform(0, 365),
            depth=0,
            sibling_count=rng.randint(0, 15),
        )
    )

    return samples


def _balance(
    samples: list[FileSample], rng: random.Random, cap_per_class: int
) -> list[tuple[FileSample, int]]:
    by_class: dict[int, list[FileSample]] = {i: [] for i in range(labeler.NUM_CLASSES)}
    for sample in samples:
        by_class[labeler.derive_label(sample)].append(sample)

    counts = {cls: len(items) for cls, items in by_class.items()}
    smallest = min(counts.values())
    target = min(smallest, cap_per_class)
    if target == 0:
        raise RuntimeError(f"a class has zero samples: {counts}")

    balanced: list[tuple[FileSample, int]] = []
    for cls, items in by_class.items():
        rng.shuffle(items)
        for sample in items[:target]:
            balanced.append((sample, cls))
    rng.shuffle(balanced)
    return balanced


def generate(seed: int = 1337, per_template: int = 2500, cap_per_class: int = 4000) -> Dataset:
    rng = random.Random(seed)
    pool = _build_pool(rng, per_template)
    # Derive depth from the path (the generators leave it at 0) so it is a real,
    # non-degenerate feature consistent with the golden keep-set.
    pool = [replace(sample, depth=_depth(sample.path)) for sample in pool]
    pairs = _balance(pool, rng, cap_per_class)

    n = len(pairs)
    features = np.empty((n, FEATURE_COUNT), dtype=np.float32)
    labels = np.empty(n, dtype=np.int64)
    out_samples: list[FileSample] = []
    for i, (sample, label) in enumerate(pairs):
        features[i] = extract_features(sample)
        labels[i] = label
        out_samples.append(sample)
    return Dataset(features=features, labels=labels, samples=out_samples)


def golden_keep_set() -> list[FileSample]:
    """Hardcoded critical files that MUST be predicted Keep (0% FP gate)."""

    paths = [
        # Credentials / secrets.
        f"{HOME}/.ssh/id_rsa",
        f"{HOME}/.ssh/id_ed25519",
        f"{HOME}/.aws/credentials",
        f"{HOME}/.config/gcloud/credentials.db",
        f"{HOME}/.gnupg/secring.gpg",
        f"{HOME}/.netrc",
        f"{HOME}/.npmrc",
        f"{HOME}/Library/Keychains/login.keychain-db",
        f"{HOME}/.claude/.credentials.json",
        f"{HOME}/.config/cleanton/config.toml",
        # User documents / media.
        f"{HOME}/Documents/thesis.pdf",
        f"{HOME}/Documents/taxes-2025.pdf",
        f"{HOME}/Desktop/budget.key",
        f"{HOME}/Pictures/IMG_2207.jpg",
        f"{HOME}/Movies/wedding.mov",
        # Source code.
        f"{HOME}/code/api-server/src/main.rs",
        f"{HOME}/code/web-app/src/index.ts",
        f"{HOME}/code/ml-pipeline/src/model.py",
        # System / app containers.
        "/System/Library/Frameworks/Foundation.framework/Foundation",
        "/usr/lib/libSystem.dylib",
        "/Applications/Safari.app/Contents/Info.plist",
        f"{HOME}/Library/Containers/com.apple.mail/Data/state.db",
        # Agent histories (transcripts, never the statsig cache).
        f"{HOME}/.claude/projects/web-app/transcript.jsonl",
        f"{HOME}/.claude/history/2026-06-01.jsonl",
    ]
    out = []
    for p in paths:
        kind = KIND_FILE
        out.append(
            FileSample(
                path=p,
                kind=kind,
                size_bytes=4096,
                age_days=365.0,
                depth=_depth(p),
                has_gitignore="/code/" in p,
                has_lockfile=False,
                sibling_count=8,
            )
        )
    return out


def golden_keep_features() -> np.ndarray:
    samples = golden_keep_set()
    feats = np.empty((len(samples), FEATURE_COUNT), dtype=np.float32)
    for i, s in enumerate(samples):
        feats[i] = extract_features(s)
    return feats
