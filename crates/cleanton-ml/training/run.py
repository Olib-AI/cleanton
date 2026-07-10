"""Single deterministic entrypoint: dataset -> train -> evaluate -> export.

Full run (what the orchestrator executes; writes ../models/*_v2.*):

    python3 -m training.run

Smoke run (seconds end-to-end, artifacts to a temp dir, v1/v2 model files
in ../models are NOT touched):

    python3 -m training.run --smoke

Run from the crate root (``crates/cleanton-ml``) so the ``training``
package is importable.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

from . import dataset as ds
from . import features
from .evaluate import enforce, evaluate, print_report, save_report
from .export_onnx import export
from .train import DEFAULT_EPOCHS, SEED, load_result, save_result, train

SMOKE = {
    "train_worlds": 8, "val_worlds": 2, "test_worlds": 3, "scale": 0.6,
    "per_class_train": 2_500, "per_class_val": 500, "per_class_test": 500,
    "realistic_cap": 8_000, "epochs": 16,
}
FULL = {
    "train_worlds": 48, "val_worlds": 8, "test_worlds": 12, "scale": 1.6,
    "per_class_train": 20_000, "per_class_val": 3_000, "per_class_test": 3_000,
    "realistic_cap": 60_000, "epochs": DEFAULT_EPOCHS,
}


def _harvest_report(result, harvest_file: Path) -> None:
    """Advisory report on real-machine metadata (never a gate: harvested
    entries carry no ground-truth labels beyond the sensitive-basename floor)."""
    import numpy as np

    from .evaluate import predict_probs
    from .labeler import LIKELY_JUNK, SAFE_TO_REMOVE

    data = np.load(harvest_file)
    features_matrix = data["features"]
    sensitive = data["sensitive_keep_indices"]
    if features_matrix.shape[0] == 0:
        print("  harvest report: no entries")
        return
    probs = predict_probs(result, features_matrix.astype(np.float32))
    pred = probs.argmax(axis=1)
    clean = np.isin(pred, (SAFE_TO_REMOVE, LIKELY_JUNK))
    print(f"  REAL-WORLD harvest      : n={len(pred)} predicted-cleanable={float(clean.mean()):.4f}")
    if len(sensitive):
        violations = int(clean[sensitive].sum())
        print(f"    sensitive-basename keeps: n={len(sensitive)} predicted-cleanable={violations}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="cleanton-ml v2 training pipeline")
    parser.add_argument("--smoke", action="store_true", help="fast end-to-end proof run (temp dir)")
    parser.add_argument("--out-dir", type=Path, default=None, help="artifact output dir (default ../models; smoke: temp dir)")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--epochs", type=int, default=None)
    parser.add_argument("--device", default="cpu", choices=["cpu", "mps"])
    parser.add_argument("--no-enforce", action="store_true", help="report gates without failing (experiments only)")
    parser.add_argument(
        "--stage", default="all", choices=["all", "dataset", "train", "eval", "export"],
        help="run one stage using cached artifacts from --out-dir (default: all, in memory)",
    )
    parser.add_argument(
        "--harvest-file", type=Path, default=None,
        help="optional .npz from `python3 -m training.harvest` (read-only local "
             "metadata) for a real-world advisory report; OFF by default",
    )
    args = parser.parse_args(argv)

    config = dict(SMOKE if args.smoke else FULL)
    if args.epochs is not None:
        config["epochs"] = args.epochs
    epochs = config.pop("epochs")

    if args.out_dir is not None:
        out_dir = args.out_dir
    elif args.smoke:
        out_dir = Path(tempfile.mkdtemp(prefix="cleanton-ml-smoke-"))
    else:
        out_dir = Path(__file__).resolve().parent.parent / "models"
    out_dir.mkdir(parents=True, exist_ok=True)

    mode = "SMOKE" if args.smoke else "FULL"
    print(f"[cleanton-ml v2] {mode} pipeline (seed={args.seed}, device={args.device})")
    print(f"[cleanton-ml v2] artifacts -> {out_dir}")

    started = time.monotonic()
    bundle_path = out_dir / "dataset_v2.npz"
    model_path = out_dir / "model_v2.pt"

    # 0. Feature schema self-check + hash (the Rust port verifies this hash).
    features.self_check()
    print(f"[1/5] feature schema v2 self-check OK (sha256 {features.schema_hash()[:16]}...)")

    # 1. Dataset: coherent worlds, grounded labels, world-level splits.
    if args.stage in ("all", "dataset"):
        t0 = time.monotonic()
        bundle = ds.build(seed=args.seed, **config)
        print(
            f"[2/5] dataset in {time.monotonic() - t0:.1f}s: "
            f"train={len(bundle.y_train)} val={len(bundle.y_val)} "
            f"test-balanced={len(bundle.y_test_balanced)} test-realistic={len(bundle.y_test_realistic)} "
            f"golden={len(bundle.golden.samples)} adversarial={len(bundle.adversarial.samples)} "
            f"near-miss={len(bundle.near_miss.samples)} fixtures={len(bundle.fixtures.samples)}"
        )
        print(f"      raw label priors (train worlds): {bundle.class_counts['train_raw']}")
        if args.stage == "dataset":
            ds.save_bundle(bundle, bundle_path)
            print(f"saved {bundle_path}")
            return 0
    else:
        bundle = ds.load_bundle(bundle_path)
        print(f"[2/5] dataset loaded from {bundle_path}")

    # 2. Train.
    if args.stage in ("all", "train"):
        t0 = time.monotonic()
        result = train(
            bundle.x_train, bundle.y_train, bundle.x_val, bundle.y_val,
            epochs=epochs, seed=args.seed, device=args.device,
        )
        print(
            f"[3/5] training done in {time.monotonic() - t0:.1f}s "
            f"({len(result.history)} epochs, {result.safety_rounds} safety fine-tune rounds)"
        )
        if args.stage == "train":
            save_result(result, model_path)
            print(f"saved {model_path}")
            return 0
    else:
        result = load_result(model_path)
        print(f"[3/5] model loaded from {model_path}")

    # 3. Evaluate + enforce gates.
    report = evaluate(result, bundle, smoke=args.smoke)
    print_report(report)
    save_report(report, out_dir / "eval_report_v2.json")
    if args.harvest_file is not None:
        _harvest_report(result, args.harvest_file)
    if not args.no_enforce:
        enforce(report)
    print("[4/5] safety gates PASSED")
    if args.stage == "eval":
        return 0

    # 4. Export ONNX + sidecar + parity fixtures.
    export(result, bundle, out_dir=out_dir)
    print(f"[5/5] export complete in {time.monotonic() - started:.1f}s total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
