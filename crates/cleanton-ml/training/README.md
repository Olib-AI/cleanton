# cleanton-ml training pipeline

Deterministic Python framework that trains the file classifier shipped (as
ONNX) inside the `cleanton-ml` Rust crate. The model is an **advisory /
annotation** signal only — the Rust engine never deletes based on it.

## One command

From this directory:

```bash
make            # == cd .. && python -m training.run
```

or directly:

```bash
python -m training.run    # from the crate root (crates/cleanton-ml)
```

This runs, deterministically (seed = 1337):

1. **feature parity self-check** — `features.py` mirrors the Rust
   `extract_features_at` 12-feature schema bit-for-bit.
2. **dataset** — `dataset.py` generates a large, balanced synthetic corpus of
   realistic macOS paths.
3. **train** — `train.py` trains the MLP with a **safety-biased loss** (100x
   penalty for predicting *safe-to-remove* on a true *keep* file, 50x for
   *likely-junk*), 5-fold CV + early stopping.
4. **evaluate** — `evaluate.py` enforces the **0% false-positive gate** on a
   golden keep-set (credentials, documents, source, system, app containers,
   agent histories). The build fails if any keep file is classified cleanable.
5. **export** — `export_onnx.py` writes:
   - `../models/file_classifier_v1.onnx` (opset 13, raw logits)
   - `../models/file_classifier_v1.json` (sidecar: feature/label order,
     standardization mean/std, opset, version `v1`)
   - `../models/parity_cases.json` (raw vectors + ONNX softmax outputs the Rust
     golden test asserts against)

## Labels are grounded, not hand-set

`labeler.py` derives every label from the same rules the engine enforces:

- `crates/cleanton-common/src/safety.rs` protected roots + credential basenames
  → **keep** (safety floor).
- `recipes/*.toml` regenerable caches / build artifacts (rust `target` with a
  lockfile, `node_modules`, `__pycache__`/`*.pyc`, `~/Library/Caches/...`, the
  Claude `statsig` cache, etc.) → **safe-to-remove**; the recipe's own excludes
  (e.g. `~/.claude/projects`) stay **keep**.
- long-unused / orphaned waste → **likely-junk**; everything else (near-miss
  decoys) → **uncertain**.

## Environment

Python 3.12, deps pinned in `requirements.txt`. `make venv` builds an isolated
`.venv`; the libraries (torch, onnx, onnxruntime, numpy) are otherwise expected
on the path.

## Files

| File | Purpose |
|---|---|
| `features.py` | 12-feature extraction (Rust parity) + self-check |
| `labeler.py` | recipe + protected-path label rules |
| `dataset.py` | synthetic balanced dataset + golden keep-set |
| `model.py` | MLP (12→32→16→4) |
| `train.py` | safety-biased loss, CV, early stopping |
| `evaluate.py` | metrics + 0% FP safety gate |
| `export_onnx.py` | ONNX export + sidecar + parity fixtures |
| `run.py` | end-to-end entrypoint |
