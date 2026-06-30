"""MLP file classifier (mirror of doc/ML_PIPELINE.md section 5.1).

Input(12) -> Linear(32) -> ReLU -> Dropout(0.2) -> Linear(16) -> ReLU
          -> Linear(4) logits.

The exported ONNX graph emits raw logits; softmax/argmax happen in Rust. The
network operates on *standardized* inputs; the standardization constants are
stored in the sidecar and re-applied identically by the Rust inference path.
"""

from __future__ import annotations

import torch
from torch import nn

from features import FEATURE_COUNT
from labeler import NUM_CLASSES

HIDDEN1 = 32
HIDDEN2 = 16


class FileClassifierMLP(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(FEATURE_COUNT, HIDDEN1),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(HIDDEN1, HIDDEN2),
            nn.ReLU(),
            nn.Linear(HIDDEN2, NUM_CLASSES),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)
