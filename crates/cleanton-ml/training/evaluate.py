"""Evaluation: hard safety gates + calibration + threshold sweep.

Hard gates (FAIL the build):
  G1  golden keep corpus: ZERO cleanable predictions (safe-to-remove or
      likely-junk argmax on any golden keep sample).
  G2  adversarial near-miss suite: ZERO cleanable predictions at or above
      the engine's 0.85 confidence threshold (full mode only; raw rate is
      always reported).
  G3  per-class recall floors on the BALANCED held-out test split, so the
      model is not uselessly conservative.
  G4  calibration: ECE (15 bins, argmax confidence) on the REALISTIC-prior
      split must stay under the ceiling (full mode only) — the engine
      thresholds on confidence 0.85, so confidence must mean something.

Reported: per-class precision/recall/F1 + confusion matrices on both the
balanced and realistic-prior splits, the golden/adversarial/fixture suite
outcomes, and a threshold sweep showing keep-catch rate vs cleanable
nuisance rate at candidate demotion thresholds.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

import numpy as np
import torch

from . import labeler as L
from .dataset import Bundle
from .train import TrainResult, standardize

ENGINE_THRESHOLD = 0.85  # cleanton-engine DEFAULT_ML_CONFIDENCE_THRESHOLD
ECE_BINS = 15

FULL_GATES = {
    "recall_floor": {"keep": 0.90, "safe-to-remove": 0.75, "likely-junk": 0.55, "uncertain": 0.40},
    "ece_ceiling": 0.20,
    "adversarial_gate": True,
    "near_miss_confident_ceiling": 0.05,
}
SMOKE_GATES = {
    "recall_floor": {"keep": 0.60, "safe-to-remove": 0.40, "likely-junk": 0.20, "uncertain": 0.20},
    "ece_ceiling": None,
    "adversarial_gate": False,
    "near_miss_confident_ceiling": None,
}

CLEAN = (L.SAFE_TO_REMOVE, L.LIKELY_JUNK)


@dataclass
class SplitMetrics:
    n: int
    accuracy: float
    per_class: dict[str, dict[str, float]]
    confusion: list[list[int]]
    class_counts: dict[str, int]


@dataclass
class EvalReport:
    balanced: SplitMetrics
    realistic: SplitMetrics
    golden_n: int
    golden_cleanable: int
    golden_cleanable_paths: list[str]
    golden_keep_recall: float
    adversarial_n: int
    adversarial_cleanable: int
    adversarial_cleanable_confident: int
    adversarial_confident_paths: list[str]
    near_miss_n: int
    near_miss_cleanable_rate: float
    near_miss_confident_rate: float
    fixture_n: int
    fixture_cleanable_rate: float
    ece_realistic: float
    threshold_sweep: list[dict[str, float]]
    gates: dict[str, bool] = field(default_factory=dict)
    passed: bool = False


def predict_probs(result: TrainResult, x: np.ndarray) -> np.ndarray:
    if x.shape[0] == 0:
        return np.empty((0, L.NUM_CLASSES), dtype=np.float32)
    normed = standardize(x, result.mean, result.std)
    result.model.eval()
    with torch.no_grad():
        logits = result.model(torch.from_numpy(normed)).numpy()
    shifted = logits - logits.max(axis=1, keepdims=True)
    exp = np.exp(shifted)
    return (exp / exp.sum(axis=1, keepdims=True)).astype(np.float32)


def _split_metrics(probs: np.ndarray, y: np.ndarray) -> SplitMetrics:
    pred = probs.argmax(axis=1)
    n = len(y)
    confusion = np.zeros((L.NUM_CLASSES, L.NUM_CLASSES), dtype=np.int64)
    for true, guessed in zip(y, pred):
        confusion[true, guessed] += 1
    per_class: dict[str, dict[str, float]] = {}
    for cls, name in enumerate(L.LABEL_NAMES):
        tp = float(confusion[cls, cls])
        support = float(confusion[cls].sum())
        predicted = float(confusion[:, cls].sum())
        recall = tp / support if support else 0.0
        precision = tp / predicted if predicted else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        per_class[name] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": int(support),
        }
    return SplitMetrics(
        n=n,
        accuracy=float((pred == y).mean()) if n else 0.0,
        per_class=per_class,
        confusion=confusion.tolist(),
        class_counts={name: int((y == cls).sum()) for cls, name in enumerate(L.LABEL_NAMES)},
    )


def _ece(probs: np.ndarray, y: np.ndarray, bins: int = ECE_BINS) -> float:
    if len(y) == 0:
        return 0.0
    confidence = probs.max(axis=1)
    correct = (probs.argmax(axis=1) == y).astype(np.float64)
    edges = np.linspace(0.0, 1.0, bins + 1)
    ece = 0.0
    for i in range(bins):
        mask = (confidence > edges[i]) & (confidence <= edges[i + 1])
        if not mask.any():
            continue
        ece += (mask.mean()) * abs(correct[mask].mean() - confidence[mask].mean())
    return float(ece)


def _threshold_sweep(probs: np.ndarray, y: np.ndarray) -> list[dict[str, float]]:
    """For candidate keep-demotion thresholds: how often would a confident
    keep verdict fire on true keeps (catch) vs true cleanables (nuisance)?"""
    rows: list[dict[str, float]] = []
    pred = probs.argmax(axis=1)
    keep_conf = probs[:, L.KEEP]
    keep_mask = y == L.KEEP
    clean_mask = np.isin(y, CLEAN)
    for threshold in (0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95):
        confident_keep = (pred == L.KEEP) & (keep_conf >= threshold)
        catch = float(confident_keep[keep_mask].mean()) if keep_mask.any() else 0.0
        nuisance = float(confident_keep[clean_mask].mean()) if clean_mask.any() else 0.0
        rows.append({
            "threshold": threshold,
            "keep_catch_rate": round(catch, 4),
            "cleanable_nuisance_rate": round(nuisance, 4),
        })
    return rows


def evaluate(result: TrainResult, bundle: Bundle, smoke: bool = False) -> EvalReport:
    gates_cfg = SMOKE_GATES if smoke else FULL_GATES

    probs_balanced = predict_probs(result, bundle.x_test_balanced)
    probs_realistic = predict_probs(result, bundle.x_test_realistic)
    balanced = _split_metrics(probs_balanced, bundle.y_test_balanced)
    realistic = _split_metrics(probs_realistic, bundle.y_test_realistic)

    # G1: golden keep corpus.
    golden_probs = predict_probs(result, bundle.golden.features())
    golden_pred = golden_probs.argmax(axis=1)
    golden_clean_mask = np.isin(golden_pred, CLEAN)
    golden_cleanable = int(golden_clean_mask.sum())
    golden_paths = [
        bundle.golden.samples[i].path for i in np.where(golden_clean_mask)[0][:20]
    ]
    golden_keep_recall = float((golden_pred == L.KEEP).mean()) if len(golden_pred) else 0.0

    # G2: adversarial near-miss suite.
    adv_probs = predict_probs(result, bundle.adversarial.features())
    adv_pred = adv_probs.argmax(axis=1)
    adv_conf = adv_probs.max(axis=1)
    adv_clean = np.isin(adv_pred, CLEAN)
    adv_clean_confident = adv_clean & (adv_conf >= ENGINE_THRESHOLD)
    adv_paths = [
        bundle.adversarial.samples[i].path for i in np.where(adv_clean_confident)[0][:20]
    ]

    # Mined near-miss suite (guard failures from held-out worlds): these sit
    # on continuous guard boundaries (age/size), so the gate is a rate ceiling
    # rather than zero tolerance.
    nm_probs = predict_probs(result, bundle.near_miss.features())
    if len(nm_probs):
        nm_pred = nm_probs.argmax(axis=1)
        nm_clean = np.isin(nm_pred, CLEAN)
        nm_clean_rate = float(nm_clean.mean())
        nm_confident_rate = float((nm_clean & (nm_probs.max(axis=1) >= ENGINE_THRESHOLD)).mean())
    else:
        nm_clean_rate = 0.0
        nm_confident_rate = 0.0

    # Fixture suite: recipe should_match examples — the model should agree
    # they are cleanable (reported; not a hard gate, recipes stay authoritative).
    fixture_probs = predict_probs(result, bundle.fixtures.features())
    if len(fixture_probs):
        fixture_clean_rate = float(np.isin(fixture_probs.argmax(axis=1), CLEAN).mean())
    else:
        fixture_clean_rate = 0.0

    ece = _ece(probs_realistic, bundle.y_test_realistic)
    sweep = _threshold_sweep(probs_realistic, bundle.y_test_realistic)

    gates: dict[str, bool] = {}
    # Non-empty-suite guards: a gate must never pass vacuously on an empty set.
    gates["G1_golden_zero_cleanable"] = len(golden_pred) > 0 and golden_cleanable == 0
    if gates_cfg["adversarial_gate"]:
        gates["G2_adversarial_zero_confident_cleanable"] = (
            len(adv_pred) > 0 and int(adv_clean_confident.sum()) == 0
        )
    ceiling = gates_cfg["near_miss_confident_ceiling"]
    if ceiling is not None:
        gates[f"G2b_near_miss_confident<={ceiling}"] = (
            len(nm_probs) > 0 and nm_confident_rate <= ceiling
        )
    for name, floor in gates_cfg["recall_floor"].items():
        recall = balanced.per_class[name]["recall"]
        gates[f"G3_recall_{name}>={floor}"] = recall >= floor
    if gates_cfg["ece_ceiling"] is not None:
        gates[f"G4_ece<={gates_cfg['ece_ceiling']}"] = ece <= gates_cfg["ece_ceiling"]

    return EvalReport(
        balanced=balanced,
        realistic=realistic,
        golden_n=len(golden_pred),
        golden_cleanable=golden_cleanable,
        golden_cleanable_paths=golden_paths,
        golden_keep_recall=round(golden_keep_recall, 4),
        adversarial_n=len(adv_pred),
        adversarial_cleanable=int(adv_clean.sum()),
        adversarial_cleanable_confident=int(adv_clean_confident.sum()),
        adversarial_confident_paths=adv_paths,
        near_miss_n=len(nm_probs),
        near_miss_cleanable_rate=round(nm_clean_rate, 4),
        near_miss_confident_rate=round(nm_confident_rate, 4),
        fixture_n=len(fixture_probs),
        fixture_cleanable_rate=round(fixture_clean_rate, 4),
        ece_realistic=round(ece, 4),
        threshold_sweep=sweep,
        gates=gates,
        passed=all(gates.values()),
    )


def print_report(report: EvalReport) -> None:
    line = "=" * 72
    print(line)
    print("EVALUATION REPORT (v2)")
    print(line)
    for split_name, metrics in (("BALANCED test", report.balanced), ("REALISTIC-prior test", report.realistic)):
        print(f"\n  {split_name}: n={metrics.n} accuracy={metrics.accuracy:.4f} priors={metrics.class_counts}")
        print(f"    {'class':<16}{'prec':>8}{'recall':>8}{'f1':>8}{'support':>9}")
        for name, row in metrics.per_class.items():
            print(f"    {name:<16}{row['precision']:>8.4f}{row['recall']:>8.4f}{row['f1']:>8.4f}{row['support']:>9}")
        print(f"    confusion (rows=true, cols=pred {list(L.LABEL_NAMES)}):")
        for cls, row in enumerate(metrics.confusion):
            print(f"      {L.LABEL_NAMES[cls]:<16}{row}")
    print(f"\n  GOLDEN keep corpus     : n={report.golden_n} cleanable={report.golden_cleanable} keep-recall={report.golden_keep_recall:.4f}")
    if report.golden_cleanable_paths:
        for path in report.golden_cleanable_paths:
            print(f"    VIOLATION: {path}")
    print(f"  ADVERSARIAL (curated)  : n={report.adversarial_n} cleanable={report.adversarial_cleanable} confident@{ENGINE_THRESHOLD}={report.adversarial_cleanable_confident}")
    for path in report.adversarial_confident_paths:
        print(f"    CONFIDENT VIOLATION: {path}")
    print(f"  NEAR-MISS (mined)      : n={report.near_miss_n} cleanable-rate={report.near_miss_cleanable_rate:.4f} confident-rate={report.near_miss_confident_rate:.4f}")
    print(f"  RECIPE fixture suite   : n={report.fixture_n} agreed-cleanable={report.fixture_cleanable_rate:.4f}")
    print(f"  ECE (realistic, {ECE_BINS} bins): {report.ece_realistic:.4f}")
    print("\n  Threshold sweep (confident-keep on realistic split):")
    print(f"    {'threshold':>10}{'keep catch':>12}{'nuisance':>10}")
    for row in report.threshold_sweep:
        print(f"    {row['threshold']:>10.2f}{row['keep_catch_rate']:>12.4f}{row['cleanable_nuisance_rate']:>10.4f}")
    print("\n  Gates:")
    for gate, ok in report.gates.items():
        print(f"    [{'PASS' if ok else 'FAIL'}] {gate}")
    print(f"\n  OVERALL: {'PASSED' if report.passed else 'FAILED'}")
    print(line)


def save_report(report: EvalReport, path) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(asdict(report), handle, indent=2)


def enforce(report: EvalReport) -> None:
    if not report.passed:
        failed = [gate for gate, ok in report.gates.items() if not ok]
        raise SystemExit(f"SAFETY GATE FAILED: {failed}")
