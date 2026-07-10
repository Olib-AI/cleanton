"""File classifier v2: categorical embeddings + MLP.

The exported ONNX graph takes ONE float32 tensor ``[batch, 53]`` — the raw
feature vector after elementwise standardization (identical to v1's Rust
inference loop; the sidecar's mean/std are identity for the 3 categorical
slots). Inside the graph the categorical slots are sliced out, clamped to
their vocab range and looked up in the embedding tables. Output is raw
logits; softmax happens in Rust.

Training uses ``nn.Embedding`` (Gather); EXPORT rewrites the lookup as
one-hot ``Equal`` + ``MatMul`` (see :class:`ExportClassifierV2`), which is
mathematically identical. The rewrite is load-bearing: tract-onnx 0.21.10
(the version pinned by the workspace) fails ``into_optimized()`` on Gather
fed by an f32 const on Apple Silicon ("Trying to substitute ... F32 by
... F16" in the versatile-packing codegen pass), while the Equal/MatMul
form optimizes and runs cleanly — verified empirically against tract
0.21.10. Exported ops: Slice, Clip, Equal, Cast, MatMul, Concat, Gemm, Relu
at opset 13.
"""

from __future__ import annotations

import torch
from torch import nn

from .features import CATEGORICAL_COUNT, DIR_VOCAB_SIZE, EXTENSION_VOCAB_SIZE, FEATURE_COUNT
from .labeler import NUM_CLASSES

EXT_EMBED_DIM = 8
DIR_EMBED_DIM = 6
HIDDEN1 = 128
HIDDEN2 = 64
DROPOUT = 0.15

NUMERIC_COUNT = FEATURE_COUNT - CATEGORICAL_COUNT
MLP_INPUT = EXT_EMBED_DIM + 2 * DIR_EMBED_DIM + NUMERIC_COUNT


class FileClassifierV2(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.ext_embedding = nn.Embedding(EXTENSION_VOCAB_SIZE, EXT_EMBED_DIM)
        self.dir_embedding = nn.Embedding(DIR_VOCAB_SIZE, DIR_EMBED_DIM)
        self.net = nn.Sequential(
            nn.Linear(MLP_INPUT, HIDDEN1),
            nn.ReLU(),
            nn.Dropout(DROPOUT),
            nn.Linear(HIDDEN1, HIDDEN2),
            nn.ReLU(),
            nn.Linear(HIDDEN2, NUM_CLASSES),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        ext_ids = torch.clamp(x[:, 0], 0.0, float(EXTENSION_VOCAB_SIZE - 1)).long()
        parent_ids = torch.clamp(x[:, 1], 0.0, float(DIR_VOCAB_SIZE - 1)).long()
        grandparent_ids = torch.clamp(x[:, 2], 0.0, float(DIR_VOCAB_SIZE - 1)).long()
        parts = [
            self.ext_embedding(ext_ids),
            self.dir_embedding(parent_ids),
            self.dir_embedding(grandparent_ids),
            x[:, CATEGORICAL_COUNT:],
        ]
        return self.net(torch.cat(parts, dim=1))


class ExportClassifierV2(nn.Module):
    """Export-only twin of :class:`FileClassifierV2`.

    Shares the trained parameters but expresses each embedding lookup as
    one-hot ``(ids == arange(V))`` + ``MatMul`` so the exported graph carries
    no Gather op (see the module docstring for why tract requires this).
    The categorical ids arrive as exact small integers in f32, so the float
    equality against the f32 arange constant is lossless.
    """

    def __init__(self, trained: FileClassifierV2) -> None:
        super().__init__()
        self.ext_weight = trained.ext_embedding.weight
        self.dir_weight = trained.dir_embedding.weight
        self.register_buffer(
            "ext_range", torch.arange(EXTENSION_VOCAB_SIZE, dtype=torch.float32).unsqueeze(0)
        )
        self.register_buffer(
            "dir_range", torch.arange(DIR_VOCAB_SIZE, dtype=torch.float32).unsqueeze(0)
        )
        self.net = trained.net

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        ext = torch.clamp(x[:, 0:1], 0.0, float(EXTENSION_VOCAB_SIZE - 1))
        parent = torch.clamp(x[:, 1:2], 0.0, float(DIR_VOCAB_SIZE - 1))
        grandparent = torch.clamp(x[:, 2:3], 0.0, float(DIR_VOCAB_SIZE - 1))
        parts = [
            (ext == self.ext_range).float() @ self.ext_weight,
            (parent == self.dir_range).float() @ self.dir_weight,
            (grandparent == self.dir_range).float() @ self.dir_weight,
            x[:, CATEGORICAL_COUNT:],
        ]
        return self.net(torch.cat(parts, dim=1))
