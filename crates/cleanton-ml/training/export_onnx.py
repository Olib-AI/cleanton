"""ONNX export v2: model + versioned schema sidecar + Rust parity fixtures.

Writes (to ``--out-dir``, default ``../models`` for full runs; smoke runs
write to a temp dir and never touch the shipped v1 artifacts):

* ``file_classifier_v2.onnx`` — raw logits, opset 13 (ops: Slice, Clip,
  Equal, Cast, MatMul, Concat, Gemm, Relu). Embedding lookups are exported
  as one-hot Equal+MatMul because tract-onnx 0.21.10 (the workspace pin)
  fails ``into_optimized()`` on Gather-from-f32-const on Apple Silicon;
  the Equal/MatMul graph optimizes and runs under tract 0.21.10.
* ``file_classifier_v2.json`` — versioned sidecar: feature order + the FULL
  v2 schema (vocab tables, component sets, hash spec, schema sha256),
  standardization mean/std (identity for the 3 categorical slots), label
  order. The Rust ``Sidecar`` deserializer ignores unknown keys, so the
  extra schema payload is backward-compatible.
* ``parity_cases_v2.json`` — raw feature vectors + the exported model's
  logits/softmax via onnxruntime; the Rust golden test must reproduce them.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch

from . import labeler as L
from .dataset import Bundle
from .features import FEATURE_COUNT, FEATURE_NAMES, schema_dict, schema_hash
from .model import DIR_EMBED_DIM, EXT_EMBED_DIM, HIDDEN1, HIDDEN2
from .train import TrainResult, standardize

OPSET = 13
VERSION = "v2"
DEFAULT_MODELS_DIR = Path(__file__).resolve().parent.parent / "models"

ONNX_NAME = "file_classifier_v2.onnx"
SIDECAR_NAME = "file_classifier_v2.json"
PARITY_NAME = "parity_cases_v2.json"


def export(result: TrainResult, bundle: Bundle, out_dir: Path | None = None) -> dict[str, Path]:
    out = Path(out_dir) if out_dir is not None else DEFAULT_MODELS_DIR
    out.mkdir(parents=True, exist_ok=True)
    onnx_path = out / ONNX_NAME
    sidecar_path = out / SIDECAR_NAME
    parity_path = out / PARITY_NAME

    from .model import ExportClassifierV2

    result.model.eval()
    model = ExportClassifierV2(result.model)
    model.eval()
    dummy = torch.zeros(1, FEATURE_COUNT, dtype=torch.float32)
    torch.onnx.export(
        model,
        dummy,
        os.fspath(onnx_path),
        export_params=True,
        opset_version=OPSET,
        do_constant_folding=True,
        input_names=["features"],
        output_names=["logits"],
        dynamic_axes={"features": {0: "batch_size"}, "logits": {0: "batch_size"}},
        dynamo=False,
    )

    _write_sidecar(result, sidecar_path)
    _write_parity(result, bundle, onnx_path, parity_path)
    _verify_export(result, bundle, onnx_path)
    size = onnx_path.stat().st_size
    print(f"exported {onnx_path} ({size} bytes, opset {OPSET})")
    print(f"wrote sidecar {sidecar_path}")
    print(f"wrote parity fixtures {parity_path}")
    return {"onnx": onnx_path, "sidecar": sidecar_path, "parity": parity_path}


def _write_sidecar(result: TrainResult, path: Path) -> None:
    sidecar = {
        "version": VERSION,
        "opset": OPSET,
        "feature_count": FEATURE_COUNT,
        "feature_order": list(FEATURE_NAMES),
        "label_order": list(L.LABEL_NAMES),
        "input_name": "features",
        "output_name": "logits",
        "normalization": {
            "kind": "standardize",
            "note": "identity (mean=0,std=1) for the 3 categorical slots",
            "mean": [float(v) for v in result.mean],
            "std": [float(v) for v in result.std],
        },
        "model": {
            "ext_embed_dim": EXT_EMBED_DIM,
            "dir_embed_dim": DIR_EMBED_DIM,
            "hidden": [HIDDEN1, HIDDEN2],
        },
        "schema": schema_dict(),
        "schema_sha256": schema_hash(),
    }
    path.write_text(json.dumps(sidecar, indent=2) + "\n")


def _softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - logits.max(axis=1, keepdims=True)
    exp = np.exp(shifted)
    return exp / exp.sum(axis=1, keepdims=True)


def _parity_pool(bundle: Bundle) -> list[tuple[str, np.ndarray]]:
    """~24 representative cases: golden keeps, adversarial decoys, cleanables."""
    pool: list[tuple[str, np.ndarray]] = []
    golden_features = bundle.golden.features()
    for i in range(0, len(bundle.golden.samples), max(1, len(bundle.golden.samples) // 8)):
        pool.append((bundle.golden.samples[i].path, golden_features[i]))
    adv_features = bundle.adversarial.features()
    for i in range(0, min(len(bundle.adversarial.samples), 60), max(1, min(len(bundle.adversarial.samples), 60) // 6)):
        pool.append((bundle.adversarial.samples[i].path, adv_features[i]))
    # Cleanable + uncertain examples straight from the balanced test split.
    per_class_quota = {cls: 3 for cls in range(L.NUM_CLASSES)}
    for x, y in zip(bundle.x_test_balanced, bundle.y_test_balanced):
        if per_class_quota[int(y)] > 0:
            per_class_quota[int(y)] -= 1
            pool.append((f"<balanced-test:{L.LABEL_NAMES[int(y)]}>", x))
        if all(v == 0 for v in per_class_quota.values()):
            break
    return pool[:32]


def _write_parity(result: TrainResult, bundle: Bundle, onnx_path: Path, parity_path: Path) -> None:
    session = ort.InferenceSession(os.fspath(onnx_path), providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name

    cases = []
    for path, raw in _parity_pool(bundle):
        raw = np.asarray(raw, dtype=np.float32)
        normed = standardize(raw.reshape(1, -1), result.mean, result.std)
        logits = session.run(None, {input_name: normed})[0]
        probs = _softmax(logits)[0]
        pred = int(probs.argmax())
        cases.append({
            "path": path,
            "raw": [float(v) for v in raw],
            "logits": [float(v) for v in logits[0]],
            "probs": [float(v) for v in probs],
            "predicted_index": pred,
            "predicted_label": L.LABEL_NAMES[pred],
            "confidence": float(probs[pred]),
        })
    parity_path.write_text(json.dumps({"version": VERSION, "cases": cases}, indent=2) + "\n")


def _verify_export(result: TrainResult, bundle: Bundle, onnx_path: Path) -> None:
    """The exported graph must agree with the torch model on golden inputs."""
    session = ort.InferenceSession(os.fspath(onnx_path), providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    raw = bundle.golden.features()
    normed = standardize(raw, result.mean, result.std)
    onnx_logits = session.run(None, {input_name: normed})[0]
    with torch.no_grad():
        torch_logits = result.model(torch.from_numpy(normed)).numpy()
    if not np.allclose(onnx_logits, torch_logits, atol=1e-4):
        raise SystemExit("ONNX export does not match the torch model within 1e-4")
