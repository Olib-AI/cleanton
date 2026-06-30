"""Single deterministic entrypoint: dataset -> train -> evaluate -> export.

Run from the crate directory:

    python -m training.run

or from this directory:

    python run.py
"""

from __future__ import annotations

import os
import sys

# Allow both `python -m training.run` (from the crate root) and `python run.py`
# (from this directory): the sibling modules use flat imports.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import features
from dataset import generate
from evaluate import enforce, evaluate, print_report
from export_onnx import export
from train import SEED, seed_everything, train


def main() -> int:
    print(f"[cleanton-ml] deterministic pipeline (seed={SEED})")

    # 0. Feature-extraction parity self-check (must mirror Rust bit-for-bit).
    features._self_check()
    print("[1/5] feature parity self-check: OK")

    # 1. Dataset.
    seed_everything(SEED)
    dataset = generate(seed=SEED)
    counts = {
        name: int((dataset.labels == i).sum())
        for i, name in enumerate(
            ["keep", "safe-to-remove", "likely-junk", "uncertain"]
        )
    }
    print(f"[2/5] dataset: {len(dataset.labels)} samples, balance={counts}")

    # 2. Train.
    result = train(dataset=dataset, run_cv=True)
    print("[3/5] training complete")

    # 3. Evaluate + enforce safety gate.
    report = evaluate(result)
    print_report(report)
    enforce(report)
    print("[4/5] safety gate PASSED (golden FP rate = 0%)")

    # 4. Export ONNX + sidecar + parity fixtures.
    export(result)
    print("[5/5] export complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
