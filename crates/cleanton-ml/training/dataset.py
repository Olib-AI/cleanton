"""Dataset assembly: worlds -> labeled splits + golden / adversarial suites.

Split protocol: WORLDS are the split unit (no sample leakage across splits).
Training uses a class-balanced subsample; a separate realistic-prior eval
split keeps the natural on-disk distribution (mostly keep/uncertain) so
reported metrics are not inflated by balancing.

Golden keep corpus = curated critical shapes + every recipe
``should_not_match`` fixture whose grounded label is Keep and which no other
recipe legitimately cleans. The adversarial suite = systematic near-miss
decoys (selector hit, guard refused) drawn from held-out worlds plus curated
guard-derived cases.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

import numpy as np

from . import labeler as L
from . import recipes_dsl as dsl
from .features import FEATURE_COUNT, KIND_DIRECTORY, KIND_FILE, FileSample, extract_features
from .fstree import node_to_sample
from .generator import generate_world
from .labeler import KEEP, LIKELY_JUNK, SAFE_TO_REMOVE, UNCERTAIN, TreeLabeler

GOLDEN_HOME = "/Users/maya"

KB, MB, GB = 1024, 1024**2, 1024**3


@dataclass
class Suite:
    """A named eval suite of samples with expected labels."""

    name: str
    samples: list[FileSample] = field(default_factory=list)
    labels: list[int] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def add(self, sample: FileSample, label: int, reason: str) -> None:
        self.samples.append(sample)
        self.labels.append(label)
        self.reasons.append(reason)

    def features(self) -> np.ndarray:
        if not self.samples:
            return np.empty((0, FEATURE_COUNT), dtype=np.float32)
        return np.stack([extract_features(s) for s in self.samples]).astype(np.float32)

    def label_array(self) -> np.ndarray:
        return np.asarray(self.labels, dtype=np.int64)


@dataclass
class Bundle:
    x_train: np.ndarray
    y_train: np.ndarray
    x_val: np.ndarray
    y_val: np.ndarray
    x_test_balanced: np.ndarray
    y_test_balanced: np.ndarray
    x_test_realistic: np.ndarray
    y_test_realistic: np.ndarray
    golden: Suite
    adversarial: Suite   # curated structural decoys: hard zero-tolerance gate
    near_miss: Suite     # mined guard-failures from held-out worlds: rate gate
    fixtures: Suite
    class_counts: dict[str, dict[str, int]]


def _collect_world(seed: int, scale: float, recipes) -> list[tuple[FileSample, int, str]]:
    root = generate_world(seed, scale=scale)
    labels = TreeLabeler(root, recipes).label_tree()
    out: list[tuple[FileSample, int, str]] = []
    for node in root.walk():
        if not node.name:
            continue
        label, reason = labels[node.path]
        out.append((node_to_sample(node), label, reason))
    return out


def _balanced(
    rows: list[tuple[FileSample, int, str]],
    rng: random.Random,
    per_class: int,
    oversample: bool = False,
) -> tuple[np.ndarray, np.ndarray]:
    by_class: dict[int, list[FileSample]] = {c: [] for c in range(L.NUM_CLASSES)}
    for sample, label, _ in rows:
        by_class[label].append(sample)
    counts = {c: len(v) for c, v in by_class.items()}
    if min(counts.values()) == 0:
        raise RuntimeError(f"a class has zero samples: {counts}")
    # Train/val may oversample scarce classes with replacement so batches stay
    # balanced at full size; test never oversamples (no inflated metrics).
    target = per_class if oversample else min(per_class, min(counts.values()))
    xs: list[np.ndarray] = []
    ys: list[int] = []
    for cls, items in by_class.items():
        rng.shuffle(items)
        take = items[: min(target, len(items))]
        while oversample and len(take) < target:
            take.append(rng.choice(items))
        for sample in take:
            xs.append(extract_features(sample))
            ys.append(cls)
    order = list(range(len(ys)))
    rng.shuffle(order)
    x = np.stack([xs[i] for i in order]).astype(np.float32)
    y = np.asarray([ys[i] for i in order], dtype=np.int64)
    return x, y


def _realistic(
    rows: list[tuple[FileSample, int, str]], rng: random.Random, cap: int
) -> tuple[np.ndarray, np.ndarray]:
    picked = list(rows)
    rng.shuffle(picked)
    picked = picked[:cap]
    x = np.stack([extract_features(s) for s, _, _ in picked]).astype(np.float32)
    y = np.asarray([label for _, label, _ in picked], dtype=np.int64)
    return x, y


# --- Golden keep corpus -------------------------------------------------------


def _sample(
    path: str,
    kind: str = KIND_FILE,
    size: int = 4096,
    age: float = 90.0,
    gitignore: bool = False,
    lockfile: bool = False,
    siblings: int = 8,
    sibling_bytes: int = 256 * KB,
    anc_lock: bool = False,
    anc_marker: bool = False,
) -> FileSample:
    depth = len([p for p in path.split("/") if p])
    return FileSample(
        path=path, kind=kind, size_bytes=size, age_days=age, depth=depth,
        has_gitignore=gitignore, has_lockfile=lockfile, sibling_count=siblings,
        sibling_total_bytes=sibling_bytes, ancestor_has_lockfile=anc_lock,
        ancestor_has_project_marker=anc_marker,
    )


def curated_golden_keeps() -> list[tuple[FileSample, str]]:
    """Critical keep shapes: every one must NEVER be classified cleanable."""
    h = GOLDEN_HOME
    proj = dict(gitignore=True, lockfile=True, anc_lock=True, anc_marker=True)
    rows: list[tuple[FileSample, str]] = []

    def add(sample: FileSample, why: str) -> None:
        rows.append((sample, why))

    # Credentials / secrets.
    add(_sample(f"{h}/.ssh/id_rsa", age=500), "credential")
    add(_sample(f"{h}/.ssh/id_ed25519", age=300), "credential")
    add(_sample(f"{h}/.aws/credentials", age=120), "credential")
    add(_sample(f"{h}/.config/gcloud/credentials.db", size=40 * KB, age=30), "credential")
    add(_sample(f"{h}/.gnupg/secring.gpg", age=700), "credential")
    add(_sample(f"{h}/.netrc", age=200), "credential")
    add(_sample(f"{h}/.npmrc", age=200), "credential")
    add(_sample(f"{h}/.kube/config", age=60), "credential")
    add(_sample(f"{h}/.docker/config.json", age=45), "credential")
    add(_sample(f"{h}/Library/Keychains/login.keychain-db", size=2 * MB, age=10), "credential")
    add(_sample(f"{h}/.claude/.credentials.json", age=5), "credential")
    add(_sample(f"{h}/.claude/settings.json", age=20), "credential")
    add(_sample(f"{h}/code/acme-api/.env", age=15, **proj), "credential")
    add(_sample(f"{h}/code/acme-api/config/service-account.json", age=90, **proj), "credential")

    # Source + manifests in ACTIVE projects.
    add(_sample(f"{h}/code/acme-api/src/main.rs", size=9 * KB, age=2, siblings=18, **proj), "active-source")
    add(_sample(f"{h}/code/acme-api/Cargo.toml", size=1200, age=3, siblings=9, **proj), "manifest")
    add(_sample(f"{h}/code/acme-api/Cargo.lock", size=80 * KB, age=3, siblings=9, **proj), "lockfile")
    add(_sample(f"{h}/code/web-portal/src/index.tsx", size=6 * KB, age=1, siblings=25, **proj), "active-source")
    add(_sample(f"{h}/code/web-portal/package.json", size=1800, age=4, siblings=11, **proj), "manifest")
    add(_sample(f"{h}/code/ml-pipeline/train.py", size=14 * KB, age=6, siblings=12, **proj), "active-source")
    add(_sample(f"{h}/work/gateway/go.mod", size=700, age=8, siblings=8, **proj), "manifest")
    add(_sample(f"{h}/code/acme-api/README.md", size=5 * KB, age=30, siblings=9, **proj), "docs")

    # Documents / media shapes.
    add(_sample(f"{h}/Documents/thesis-final.pdf", size=4 * MB, age=400, siblings=30, sibling_bytes=200 * MB), "document")
    add(_sample(f"{h}/Documents/taxes-2025.xlsx", size=300 * KB, age=100), "document")
    add(_sample(f"{h}/Documents/passport-scan.jpg", size=2 * MB, age=600), "document")
    add(_sample(f"{h}/Desktop/todo.md", size=2 * KB, age=1), "document")
    add(_sample(f"{h}/Desktop/Screenshot 2026-06-30 at 20.15.55.png", size=3 * MB, age=9), "document")
    add(_sample(f"{h}/Downloads/lease-agreement.pdf", size=900 * KB, age=200), "document")
    add(_sample(f"{h}/Pictures/Photos Library.photoslibrary/originals/IMG_2207.heic", size=3 * MB, age=800, siblings=400, sibling_bytes=2 * GB), "media")
    add(_sample(f"{h}/Movies/wedding-ceremony.mov", size=2 * GB, age=900), "media")
    add(_sample(f"{h}/Music/Music/Media/favorite-song.m4a", size=9 * MB, age=500), "media")

    # Mail / Messages / Containers shapes.
    add(_sample(f"{h}/Library/Mail/V10/MailData/Envelope Index", size=180 * MB, age=1), "mail")
    add(_sample(f"{h}/Library/Messages/chat.db", size=400 * MB, age=0.5), "messages")
    add(_sample(f"{h}/Library/Containers/com.apple.mail/Data/state.db", size=25 * MB, age=3), "container")
    add(_sample(f"{h}/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite", size=80 * MB, age=2), "container")
    add(_sample(f"{h}/Library/Containers/com.apple.news/Data/Library/Caches/cache.db", size=30 * MB, age=90), "container-cache")

    # .git internals (active project).
    add(_sample(f"{h}/code/acme-api/.git/objects/pack/pack-9f2ce01a.pack", size=40 * MB, age=5, siblings=2, anc_lock=True, anc_marker=True), "git-internals")
    add(_sample(f"{h}/code/acme-api/.git/index", size=60 * KB, age=0.2, siblings=6, anc_lock=True, anc_marker=True), "git-internals")
    add(_sample(f"{h}/code/acme-api/.git/HEAD", size=23, age=0.2, siblings=6, anc_lock=True, anc_marker=True), "git-internals")

    # LIVE virtualenvs (pyvenv.cfg present, fresh mtime).
    add(_sample(f"{h}/code/ml-pipeline/.venv/pyvenv.cfg", size=220, age=0.5, anc_marker=True), "live-venv")
    add(_sample(f"{h}/code/ml-pipeline/.venv/lib/python3.12/site-packages/requests/__init__.py", size=5 * KB, age=0.5, siblings=40, anc_marker=True), "live-venv")
    add(_sample(f"{h}/code/ml-pipeline/.venv", kind=KIND_DIRECTORY, size=300 * MB, age=0.5, anc_marker=True, siblings=14), "live-venv")

    # Agent history (recipe-excluded keeps).
    add(_sample(f"{h}/.claude/projects/-Users-maya-code-acme/9a1b.jsonl", size=2 * MB, age=3), "agent-history")
    add(_sample(f"{h}/.claude/todos/54ac.json", size=3 * KB, age=1), "agent-history")

    # System / app paths (floor).
    add(_sample("/System/Library/Frameworks/Foundation.framework/Foundation", size=9 * MB, age=900), "system")
    add(_sample("/usr/lib/libSystem.dylib", size=2 * MB, age=900), "system")
    add(_sample("/Applications/Safari.app/Contents/Info.plist", size=4 * KB, age=400), "system")
    add(_sample("/private/etc/hosts", size=300, age=800), "system")
    return rows


def curated_adversarial() -> list[tuple[FileSample, int, str]]:
    """Near-miss decoys: LOOK cleanable, must never be confidently cleaned.

    Built from the recipes' guard conditions (missing parent marker, failed
    min_size / min_age, absent self marker, extension lookalikes).
    """
    h = GOLDEN_HOME
    rows: list[tuple[FileSample, int, str]] = []

    def add(sample: FileSample, why: str, label: int = UNCERTAIN) -> None:
        rows.append((sample, label, why))

    # target/ with NO Cargo.toml next to it.
    add(_sample(f"{h}/scratch/target", kind=KIND_DIRECTORY, size=60 * MB, age=90, siblings=4), "loose-target")
    add(_sample(f"{h}/scratch/target/results.csv", size=12 * MB, age=90, siblings=3), "loose-target-file")
    # node_modules with NO package.json.
    add(_sample(f"{h}/scratch/node_modules", kind=KIND_DIRECTORY, size=40 * MB, age=120), "loose-node-modules")
    # build/ that is actually a source dir (no CMakeCache.txt inside).
    add(_sample(f"{h}/scratch/build/deploy.sh", size=2 * KB, age=30), "build-as-source")
    # checkpoint-* dir WITHOUT trainer_state.json.
    add(_sample(f"{h}/code/photos/checkpoint-alpha", kind=KIND_DIRECTORY, size=300 * MB, age=200), "fake-checkpoint-dir")
    # Tiny .pt (site-packages path hook, fails the 200MB weight floor).
    add(_sample(f"{h}/code/tools/.venv/lib/python3.12/site-packages/distutils-precedence.pth", size=150, age=200, anc_marker=True), "pth-hook")
    add(_sample(f"{h}/scratch/hook.pt", size=2 * KB, age=100), "small-pt")
    # .ppt is not .pt.
    add(_sample(f"{h}/Documents/quarterly-review.ppt", size=9 * MB, age=200), "ppt-not-pt", label=KEEP)
    # Fresh .venv (fails age gates; live).
    add(_sample(f"{h}/scratch/fresh-experiment/.venv", kind=KIND_DIRECTORY, size=200 * MB, age=1), "fresh-venv")
    # target/ with evidence but tiny (fails min_size_mb=10).
    add(_sample(f"{h}/code/hello-rust/target", kind=KIND_DIRECTORY, size=900 * KB, age=10, gitignore=True, lockfile=True, anc_lock=True, anc_marker=True), "tiny-target")
    # Non-Unity Library dir (a book project).
    add(_sample(f"{h}/code/book-draft/Library/references.bib", size=90 * KB, age=200), "non-unity-library")
    add(_sample(f"{h}/code/book-draft/Library", kind=KIND_DIRECTORY, size=90 * KB, age=200), "non-unity-library")
    # A recent large log (recipes usually age-gate logs).
    add(_sample(f"{h}/Library/Logs/AcmeSync/sync.log", size=80 * MB, age=0.5), "fresh-log")
    # NOTE deliberately absent: an npm-linked package inside a marker-proven
    # node_modules. In the 53-feature space it is indistinguishable from a
    # normally installed package (symlink-ness is not a feature), and the
    # engine's node-modules recipe legitimately cleans that tree — so the
    # grounded label for the shape is cleanable and a zero-tolerance gate on
    # it is unsatisfiable by construction (it failed G2 exactly this way).
    return rows


def _keep_shaped(entry: dsl.Entry) -> bool:
    """Document / media / source shapes outside removable trees."""
    from . import features as F

    ext_id = F.extension_id(entry.path)
    keepish = (
        ext_id in F._SOURCE_EXT_IDS
        or ext_id in F._DOC_EXT_IDS
        or ext_id in F._MEDIA_EXT_IDS
    )
    removable_shape = (
        F.in_build_dir(entry.path, entry.kind)
        or F.in_cache_dir(entry.path, entry.kind)
        or F._has_signal_component(entry.path, entry.kind, "node_modules")
        or F.in_venv(entry.path, entry.kind)
    )
    return keepish and not removable_shape


def mined_fixture_suites(recipes) -> tuple[list[tuple[FileSample, str]], list[tuple[FileSample, int, str]]]:
    """Mine recipe [test] fixtures.

    Returns (golden_keeps, fixture_examples):
    * ``should_not_match`` fixtures that no enabled recipe legitimately cleans
      and whose grounded shape is keep-like -> extra GOLDEN keep rows;
    * ``should_match`` fixtures -> labeled cleanable examples (per the
      recipe's safety level) used as an eval suite.
    """
    home = GOLDEN_HOME
    golden: list[tuple[FileSample, str]] = []
    examples: list[tuple[FileSample, int, str]] = []
    no_markers = lambda _dir, _marker: False  # noqa: E731 (pessimistic probe)

    from .vocab import LOCKFILES, PROJECT_MARKERS

    def to_sample(entry: dsl.Entry, recipe: dsl.Recipe) -> FileSample:
        """Fixture with guard-implied context: like the Rust validator we
        assume the recipe's parent markers ARE present, so a marker that is a
        known lockfile/manifest sets the corresponding context flags."""
        depth = len([p for p in entry.path.split("/") if p])
        markers: set[str] = set()
        for spec in recipe.specs:
            markers.update(spec.parent_must_contain or ())
            markers.update(spec.parent_must_contain_any or ())
        has_lockfile = bool(markers & set(LOCKFILES))
        has_marker = bool(markers & set(PROJECT_MARKERS))
        return FileSample(
            path=entry.path, kind=entry.kind, size_bytes=entry.allocated_bytes,
            age_days=float(entry.age_days or 0.0), depth=depth,
            has_gitignore=has_marker, has_lockfile=has_lockfile,
            sibling_count=6, sibling_total_bytes=entry.allocated_bytes * 2,
            ancestor_has_lockfile=has_lockfile,
            ancestor_has_project_marker=has_marker or has_lockfile,
        )

    for recipe in recipes:
        for fixture in recipe.should_match:
            entry = dsl.synthetic_fixture_entry(recipe, fixture, home)
            if not entry.path.startswith("/"):
                entry = dsl.Entry(
                    path=f"{home}/{entry.path}", kind=entry.kind,
                    allocated_bytes=entry.allocated_bytes,
                    age_days=entry.age_days, newest_age_days=entry.newest_age_days,
                )
            label = SAFE_TO_REMOVE if recipe.safety_level == "safe" else LIKELY_JUNK
            examples.append((to_sample(entry, recipe), label, f"fixture:{recipe.id}"))
        for fixture in recipe.should_not_match:
            entry = dsl.synthetic_fixture_entry(recipe, fixture, home)
            if not entry.path.startswith("/"):
                entry = dsl.Entry(
                    path=f"{home}/{entry.path}", kind=entry.kind,
                    allocated_bytes=entry.allocated_bytes,
                    age_days=entry.age_days, newest_age_days=entry.newest_age_days,
                )
            # Skip fixtures another recipe legitimately cleans.
            if any(dsl.recipe_matches(r, entry, home, no_markers) for r in recipes):
                continue
            floored = dsl.is_protected(entry.path, home) or dsl.is_sensitive_basename(entry.path)
            if floored or _keep_shaped(entry):
                golden.append((to_sample(entry, recipe), f"fixture-keep:{recipe.id}"))
    return golden, examples


def save_bundle(bundle: Bundle, path) -> None:
    """Persist a bundle (arrays via npz + suite metadata via JSON strings)."""
    import json

    def suite_meta(suite: Suite) -> str:
        return json.dumps({
            "name": suite.name,
            "samples": [s.__dict__ for s in suite.samples],
            "labels": suite.labels,
            "reasons": suite.reasons,
        })

    np.savez_compressed(
        path,
        x_train=bundle.x_train, y_train=bundle.y_train,
        x_val=bundle.x_val, y_val=bundle.y_val,
        x_test_balanced=bundle.x_test_balanced, y_test_balanced=bundle.y_test_balanced,
        x_test_realistic=bundle.x_test_realistic, y_test_realistic=bundle.y_test_realistic,
        golden=suite_meta(bundle.golden),
        adversarial=suite_meta(bundle.adversarial),
        near_miss=suite_meta(bundle.near_miss),
        fixtures=suite_meta(bundle.fixtures),
        class_counts=np.bytes_(str(bundle.class_counts).encode()),
    )


def load_bundle(path) -> Bundle:
    import ast
    import json

    data = np.load(path, allow_pickle=False)

    def suite_from(meta: str) -> Suite:
        payload = json.loads(meta)
        suite = Suite(payload["name"])
        for raw, label, reason in zip(payload["samples"], payload["labels"], payload["reasons"]):
            suite.add(FileSample(**raw), int(label), reason)
        return suite

    return Bundle(
        x_train=data["x_train"], y_train=data["y_train"],
        x_val=data["x_val"], y_val=data["y_val"],
        x_test_balanced=data["x_test_balanced"], y_test_balanced=data["y_test_balanced"],
        x_test_realistic=data["x_test_realistic"], y_test_realistic=data["y_test_realistic"],
        golden=suite_from(str(data["golden"])),
        adversarial=suite_from(str(data["adversarial"])),
        near_miss=suite_from(str(data["near_miss"])),
        fixtures=suite_from(str(data["fixtures"])),
        class_counts=ast.literal_eval(data["class_counts"].tobytes().decode()),
    )


def build(
    seed: int = 1337,
    train_worlds: int = 16,
    val_worlds: int = 3,
    test_worlds: int = 5,
    scale: float = 0.6,
    per_class_train: int = 30_000,
    per_class_val: int = 4_000,
    per_class_test: int = 4_000,
    realistic_cap: int = 60_000,
    recipes=None,
) -> Bundle:
    rng = random.Random(seed)
    if recipes is None:
        recipes = dsl.load_recipes()

    def collect(world_seeds: list[int]) -> list[tuple[FileSample, int, str]]:
        rows: list[tuple[FileSample, int, str]] = []
        for ws in world_seeds:
            rows.extend(_collect_world(ws, scale, recipes))
        return rows

    base = seed * 1000
    train_rows = collect([base + i for i in range(train_worlds)])
    val_rows = collect([base + 500 + i for i in range(val_worlds)])
    test_rows = collect([base + 800 + i for i in range(test_worlds)])

    golden = Suite("golden-keep")
    for sample, why in curated_golden_keeps():
        golden.add(sample, KEEP, why)
    mined_golden, fixture_examples = mined_fixture_suites(recipes)
    for sample, why in mined_golden:
        golden.add(sample, KEEP, why)

    adversarial = Suite("adversarial-curated")
    for sample, label, why in curated_adversarial():
        adversarial.add(sample, label, why)

    near_miss = Suite("near-miss-mined")
    near_miss_rows = [
        r for r in test_rows if r[2].startswith(("near-miss", "recipe-exclude"))
    ]
    rng.shuffle(near_miss_rows)
    for sample, label, reason in near_miss_rows[:500]:
        near_miss.add(sample, label, reason)

    fixtures = Suite("recipe-fixtures")
    for sample, label, why in fixture_examples:
        fixtures.add(sample, label, why)

    x_train, y_train = _balanced(train_rows, rng, per_class_train, oversample=True)
    x_val, y_val = _balanced(val_rows, rng, per_class_val, oversample=True)
    x_test_b, y_test_b = _balanced(test_rows, rng, per_class_test)
    x_test_r, y_test_r = _realistic(test_rows, rng, realistic_cap)

    def counts(rows: list[tuple[FileSample, int, str]]) -> dict[str, int]:
        out = {name: 0 for name in L.LABEL_NAMES}
        for _, label, _ in rows:
            out[L.LABEL_NAMES[label]] += 1
        return out

    return Bundle(
        x_train=x_train, y_train=y_train,
        x_val=x_val, y_val=y_val,
        x_test_balanced=x_test_b, y_test_balanced=y_test_b,
        x_test_realistic=x_test_r, y_test_realistic=y_test_r,
        golden=golden, adversarial=adversarial, near_miss=near_miss, fixtures=fixtures,
        class_counts={
            "train_raw": counts(train_rows),
            "val_raw": counts(val_rows),
            "test_raw": counts(test_rows),
        },
    )
