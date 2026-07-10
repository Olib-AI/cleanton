"""Eval-gate integrity: no vacuous passes, and a keep-always model FAILS."""

import numpy as np
import torch
from torch import nn

from training import labeler as L
from training.dataset import Bundle, Suite, _sample
from training.evaluate import evaluate
from training.features import FEATURE_COUNT
from training.train import TrainResult


class _ConstantModel(nn.Module):
    """Always predicts one class with near-total confidence."""

    def __init__(self, cls: int):
        super().__init__()
        self.cls = cls

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        logits = torch.full((x.shape[0], L.NUM_CLASSES), -10.0)
        logits[:, self.cls] = 10.0
        return logits


def _result(cls: int) -> TrainResult:
    return TrainResult(
        model=_ConstantModel(cls),
        mean=np.zeros(FEATURE_COUNT, dtype=np.float32),
        std=np.ones(FEATURE_COUNT, dtype=np.float32),
    )


def _bundle(near_miss_empty: bool = False) -> Bundle:
    rng = np.random.default_rng(0)
    x = rng.normal(0, 1, size=(64, FEATURE_COUNT)).astype(np.float32)
    y = np.asarray([i % L.NUM_CLASSES for i in range(64)], dtype=np.int64)
    golden = Suite("golden-keep")
    golden.add(_sample("/Users/t/.ssh/id_rsa"), L.KEEP, "credential")
    adversarial = Suite("adversarial-curated")
    adversarial.add(_sample("/Users/t/scratch/target", kind="directory"), L.UNCERTAIN, "loose")
    near_miss = Suite("near-miss-mined")
    if not near_miss_empty:
        near_miss.add(_sample("/Users/t/scratch/build"), L.UNCERTAIN, "near-miss")
    fixtures = Suite("recipe-fixtures")
    return Bundle(
        x_train=x, y_train=y, x_val=x, y_val=y,
        x_test_balanced=x, y_test_balanced=y,
        x_test_realistic=x, y_test_realistic=y,
        golden=golden, adversarial=adversarial, near_miss=near_miss,
        fixtures=fixtures, class_counts={},
    )


def test_keep_always_model_fails_the_recall_gates():
    # The safety metric must not be gameable by predicting keep for
    # everything: G3 recall floors for the non-keep classes must fail.
    report = evaluate(_result(L.KEEP), _bundle(), smoke=True)
    assert report.gates["G1_golden_zero_cleanable"]  # trivially safe...
    assert not report.gates["G3_recall_safe-to-remove>=0.4"]
    assert not report.gates["G3_recall_likely-junk>=0.2"]
    assert not report.gates["G3_recall_uncertain>=0.2"]
    assert not report.passed


def test_junk_always_model_fails_the_golden_gate():
    report = evaluate(_result(L.LIKELY_JUNK), _bundle(), smoke=True)
    assert not report.gates["G1_golden_zero_cleanable"]
    assert not report.passed


def test_empty_near_miss_suite_fails_rather_than_passing_vacuously():
    report = evaluate(_result(L.UNCERTAIN), _bundle(near_miss_empty=True), smoke=False)
    gate = next(k for k in report.gates if k.startswith("G2b"))
    assert not report.gates[gate]
    assert not report.passed
