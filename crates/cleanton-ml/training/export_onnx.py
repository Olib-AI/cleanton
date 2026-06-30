"""Export the trained MLP to ONNX + write the sidecar and parity fixtures.

* Emits ``models/file_classifier_v1.onnx`` (raw logits, opset 13 — well within
  tract's supported range).
* Emits ``models/file_classifier_v1.json`` sidecar: feature order, label order,
  standardization constants (mean/std), opset, and version "v1".
* Emits ``models/parity_cases.json``: a handful of RAW feature vectors with the
  softmax probabilities produced by the EXPORTED ONNX (via onnxruntime). The
  Rust golden test embeds these and asserts tract reproduces them.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch

import labeler
from dataset import golden_keep_set
from features import FEATURE_COUNT, FEATURE_NAMES, FileSample, extract_features
from train import TrainResult

OPSET = 13
VERSION = "v1"
MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
ONNX_PATH = MODELS_DIR / "file_classifier_v1.onnx"
SIDECAR_PATH = MODELS_DIR / "file_classifier_v1.json"
PARITY_PATH = MODELS_DIR / "parity_cases.json"


def export(result: TrainResult) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model = result.model
    model.eval()

    dummy = torch.zeros(1, FEATURE_COUNT, dtype=torch.float32)
    torch.onnx.export(
        model,
        dummy,
        os.fspath(ONNX_PATH),
        export_params=True,
        opset_version=OPSET,
        do_constant_folding=True,
        input_names=["features"],
        output_names=["logits"],
        dynamic_axes={"features": {0: "batch_size"}, "logits": {0: "batch_size"}},
        dynamo=False,
    )

    _write_sidecar(result)
    _write_parity(result)
    _verify_tract_compatibility(result)
    size = ONNX_PATH.stat().st_size
    print(f"exported {ONNX_PATH} ({size} bytes, opset {OPSET})")
    print(f"wrote sidecar {SIDECAR_PATH}")
    print(f"wrote parity fixtures {PARITY_PATH}")


def _write_sidecar(result: TrainResult) -> None:
    sidecar = {
        "version": VERSION,
        "opset": OPSET,
        "feature_count": FEATURE_COUNT,
        "feature_order": list(FEATURE_NAMES),
        "label_order": list(labeler.LABEL_NAMES),
        "input_name": "features",
        "output_name": "logits",
        "normalization": {
            "kind": "standardize",
            "mean": [float(v) for v in result.mean],
            "std": [float(v) for v in result.std],
        },
    }
    SIDECAR_PATH.write_text(json.dumps(sidecar, indent=2) + "\n")


def _standardize(x: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    return ((x - mean) / std).astype(np.float32)


def _softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - logits.max(axis=1, keepdims=True)
    exp = np.exp(shifted)
    return exp / exp.sum(axis=1, keepdims=True)


def _parity_samples() -> list[FileSample]:
    """Representative raw vectors spanning every class + safety-critical cases."""

    home = labeler.HOME
    paths = [
        # credential -> keep
        FileSample(f"{home}/.ssh/id_rsa", "file", 4096, 365.0, 4, False, False, 8),
        # document -> keep
        FileSample(f"{home}/Documents/thesis.pdf", "file", 8_000_000, 200.0, 3, False, False, 20),
        # source -> keep
        FileSample(
            f"{home}/code/api-server/src/main.rs", "file", 4096, 5.0, 5, True, True, 12
        ),
        # rust target artifact -> safe-to-remove
        FileSample(
            f"{home}/code/api-server/target/release/app.o",
            "file",
            40_000_000,
            10.0,
            6,
            True,
            True,
            400,
        ),
        # node_modules -> safe-to-remove
        FileSample(
            f"{home}/code/web-app/node_modules/react/index.js",
            "file",
            200_000,
            30.0,
            6,
            True,
            True,
            900,
        ),
        # global pip cache -> safe-to-remove
        FileSample(
            f"{home}/Library/Caches/pip/wheels/foo.whl",
            "file",
            5_000_000,
            120.0,
            6,
            False,
            False,
            300,
        ),
        # old venv -> likely-junk
        FileSample(
            f"{home}/code/ml-pipeline/.venv/lib/python3.12/site-packages/numpy/x.py",
            "file",
            500_000,
            200.0,
            8,
            True,
            False,
            500,
        ),
        # old large checkpoint -> likely-junk
        FileSample(
            f"{home}/code/ml-pipeline/checkpoints/epoch-12.ckpt",
            "file",
            2_000_000_000,
            120.0,
            5,
            True,
            False,
            10,
        ),
        # loose decoy target with no evidence -> uncertain
        FileSample(
            f"{home}/scratch/loose/target/blob.bin", "file", 5_000_000, 50.0, 5, False, False, 8
        ),
        # unknown blob -> uncertain
        FileSample(f"{home}/scratch/data.bin", "file", 1_000_000, 100.0, 3, False, False, 4),
    ]
    return paths


def _write_parity(result: TrainResult) -> None:
    session = ort.InferenceSession(os.fspath(ONNX_PATH), providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name

    samples = _parity_samples() + golden_keep_set()[:6]
    cases = []
    for sample in samples:
        raw = extract_features(sample).astype(np.float32)
        normed = _standardize(raw.reshape(1, -1), result.mean, result.std)
        logits = session.run(None, {input_name: normed})[0]
        probs = _softmax(logits)[0]
        pred = int(probs.argmax())
        cases.append(
            {
                "path": sample.path,
                "raw": [float(v) for v in raw],
                "logits": [float(v) for v in logits[0]],
                "probs": [float(v) for v in probs],
                "predicted_index": pred,
                "predicted_label": labeler.LABEL_NAMES[pred],
                "confidence": float(probs[pred]),
            }
        )

    PARITY_PATH.write_text(json.dumps({"cases": cases}, indent=2) + "\n")


def _verify_tract_compatibility(result: TrainResult) -> None:
    """Sanity: ONNX (onnxruntime) and the torch model agree after standardize."""

    session = ort.InferenceSession(os.fspath(ONNX_PATH), providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name

    raw = np.stack([extract_features(s) for s in golden_keep_set()]).astype(np.float32)
    normed = _standardize(raw, result.mean, result.std)
    onnx_logits = session.run(None, {input_name: normed})[0]
    with torch.no_grad():
        torch_logits = result.model(torch.from_numpy(normed)).numpy()
    if not np.allclose(onnx_logits, torch_logits, atol=1e-4):
        raise SystemExit("ONNX export does not match torch model within 1e-4")
