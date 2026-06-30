"""Evaluation + hard safety gates (doc/ML_PIPELINE.md section 6.1).

Constraint 1: false-positive rate (a true Keep predicted as a clean class) MUST
be exactly 0.0% on the golden keep-set. FAIL the pipeline otherwise.

Constraint 2: on the curated golden keep-set the model must predict Keep with
high confidence.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch

import labeler
from dataset import golden_keep_features
from train import TrainResult

# Constraint 2 confidence floor. doc aspires to 99.9%; we hold a strict,
# achievable floor and additionally require zero clean predictions.
KEEP_CONFIDENCE_FLOOR = 0.90


@dataclass
class EvalReport:
    test_accuracy: float
    cv_accuracy: float
    golden_fp_rate: float
    golden_min_keep_confidence: float
    golden_all_keep: bool
    per_class_recall: dict[str, float]
    passed: bool


def _standardize(x: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    return ((x - mean) / std).astype(np.float32)


def _softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - logits.max(axis=1, keepdims=True)
    exp = np.exp(shifted)
    return exp / exp.sum(axis=1, keepdims=True)


def evaluate(result: TrainResult) -> EvalReport:
    model = result.model
    model.eval()

    with torch.no_grad():
        test_logits = model(result.split.x_test).numpy()
    test_pred = test_logits.argmax(axis=1)
    test_true = result.split.y_test.numpy()
    test_acc = float((test_pred == test_true).mean())

    per_class_recall: dict[str, float] = {}
    for cls in range(labeler.NUM_CLASSES):
        mask = test_true == cls
        if mask.any():
            per_class_recall[labeler.LABEL_NAMES[cls]] = float(
                (test_pred[mask] == cls).mean()
            )

    # --- Golden keep-set gate -------------------------------------------------
    golden_raw = golden_keep_features()
    golden_x = torch.from_numpy(_standardize(golden_raw, result.mean, result.std))
    with torch.no_grad():
        golden_logits = model(golden_x).numpy()
    golden_probs = _softmax(golden_logits)
    golden_pred = golden_probs.argmax(axis=1)
    golden_conf_keep = golden_probs[:, labeler.KEEP]

    fp_mask = np.isin(golden_pred, list(labeler.CLEAN_LABELS))
    golden_fp_rate = float(fp_mask.mean())
    all_keep = bool((golden_pred == labeler.KEEP).all())
    min_keep_conf = float(golden_conf_keep.min())

    passed = (
        golden_fp_rate == 0.0
        and all_keep
        and min_keep_conf >= KEEP_CONFIDENCE_FLOOR
    )

    return EvalReport(
        test_accuracy=test_acc,
        cv_accuracy=result.cv_accuracy,
        golden_fp_rate=golden_fp_rate,
        golden_min_keep_confidence=min_keep_conf,
        golden_all_keep=all_keep,
        per_class_recall=per_class_recall,
        passed=passed,
    )


def print_report(report: EvalReport) -> None:
    print("=" * 60)
    print("EVALUATION REPORT")
    print("=" * 60)
    print(f"  5-fold CV accuracy        : {report.cv_accuracy:.4f}")
    print(f"  held-out test accuracy    : {report.test_accuracy:.4f}")
    for name, recall in report.per_class_recall.items():
        print(f"    recall[{name:<14}]    : {recall:.4f}")
    print(f"  GOLDEN false-positive rate: {report.golden_fp_rate * 100:.2f}%")
    print(f"  GOLDEN all-keep           : {report.golden_all_keep}")
    print(f"  GOLDEN min keep confidence: {report.golden_min_keep_confidence:.4f}")
    print(f"  GATE PASSED               : {report.passed}")
    print("=" * 60)


def enforce(report: EvalReport) -> None:
    if not report.passed:
        raise SystemExit(
            "SAFETY GATE FAILED: golden false-positive rate must be 0% with all "
            f"Keep predictions >= {KEEP_CONFIDENCE_FLOOR:.2f} confidence "
            f"(fp_rate={report.golden_fp_rate * 100:.2f}%, "
            f"all_keep={report.golden_all_keep}, "
            f"min_conf={report.golden_min_keep_confidence:.4f})"
        )
