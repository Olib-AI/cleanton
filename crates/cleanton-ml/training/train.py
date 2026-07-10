"""Deterministic training with an asymmetric safety-cost loss.

Loss = class-weighted cross-entropy (label smoothing on NON-keep classes
only) + SAFETY_LAMBDA * expected misclassification cost under the penalty
matrix ``COST[true][pred]``:

                     pred: keep   safe   junk   uncertain
    true keep              0     100     60        1
    true safe-to-remove    2       0      1        1
    true likely-junk       2       1      0        1
    true uncertain         1       8      6        0

Predicting a cleanable class on a true keep is catastrophic (100x / 60x);
calling an uncertain file cleanable is strongly punished (8x / 6x); the
reverse mistakes (keeping something cleanable) cost almost nothing — every
mistake the model makes is pushed toward the "keep" direction.

Determinism: fixed seeds, ``torch.use_deterministic_algorithms(True)``,
seeded permutation batching, CPU by default (MPS kernels are not
deterministic; pass device="mps" explicitly to trade determinism for speed).
Early stopping monitors a SAFETY-WEIGHTED validation metric (expected cost +
a large penalty on keep->cleanable decisions), not raw accuracy.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

import numpy as np
import torch
from torch import nn

from . import labeler as L
from .model import FileClassifierV2

SEED = 1337
DEFAULT_EPOCHS = 60
PATIENCE = 8
BATCH_SIZE = 512
LR = 1.5e-3
WEIGHT_DECAY = 1e-5
SAFETY_LAMBDA = 1.0
LABEL_SMOOTHING = 0.05
STD_FLOOR = 1e-6
MAX_SAFETY_ROUNDS = 3
SAFETY_ROUND_EPOCHS = 6

COST = torch.tensor(
    [
        # keep   safe   junk  uncertain      (predicted)
        [0.0, 100.0, 60.0, 1.0],   # true keep
        [2.0, 0.0, 1.0, 1.0],      # true safe-to-remove
        [2.0, 1.0, 0.0, 1.0],      # true likely-junk
        [1.0, 8.0, 6.0, 0.0],      # true uncertain
    ],
    dtype=torch.float32,
)

CLASS_WEIGHTS = torch.tensor([3.0, 1.0, 1.0, 1.0], dtype=torch.float32)


def seed_everything(seed: int = SEED) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)


@dataclass
class TrainResult:
    model: FileClassifierV2
    mean: np.ndarray
    std: np.ndarray
    history: list[float] = field(default_factory=list)
    safety_rounds: int = 0


def compute_normalization(x_train: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Mean/std over the training split; IDENTITY for categorical slots."""
    from .features import CATEGORICAL_COUNT

    mean = x_train.mean(axis=0).astype(np.float32)
    std = np.maximum(x_train.std(axis=0), STD_FLOOR).astype(np.float32)
    mean[:CATEGORICAL_COUNT] = 0.0
    std[:CATEGORICAL_COUNT] = 1.0
    return mean, std


def standardize(x: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    return ((x - mean) / std).astype(np.float32)


def safety_loss(
    logits: torch.Tensor, targets: torch.Tensor, safety_lambda: float = SAFETY_LAMBDA
) -> torch.Tensor:
    num_classes = logits.shape[1]
    log_probs = torch.log_softmax(logits, dim=1)
    probs = log_probs.exp()

    # Label smoothing on non-keep targets only: a true keep stays a pure
    # one-hot (we never teach probability mass toward cleanable on keeps).
    one_hot = nn.functional.one_hot(targets, num_classes).float()
    smooth = (1.0 - LABEL_SMOOTHING) * one_hot + LABEL_SMOOTHING / num_classes
    keep_mask = (targets == L.KEEP).unsqueeze(1)
    target_dist = torch.where(keep_mask, one_hot, smooth)

    per_sample_ce = -(target_dist * log_probs).sum(dim=1)
    weights = CLASS_WEIGHTS.to(logits.device)[targets]
    ce = (per_sample_ce * weights).sum() / weights.sum()

    cost_rows = COST.to(logits.device)[targets]  # [B, C]
    expected_cost = (probs * cost_rows).sum(dim=1).mean()

    return ce + safety_lambda * expected_cost


def safety_val_metric(logits: torch.Tensor, targets: torch.Tensor) -> float:
    """Early-stopping metric: expected cost + heavy keep->cleanable penalty."""
    probs = torch.softmax(logits, dim=1)
    cost_rows = COST.to(logits.device)[targets]
    expected_cost = (probs * cost_rows).sum(dim=1).mean().item()
    pred = probs.argmax(dim=1)
    keep_mask = targets == L.KEEP
    if bool(keep_mask.any()):
        cleanable = (pred == L.SAFE_TO_REMOVE) | (pred == L.LIKELY_JUNK)
        keep_fp_rate = (cleanable & keep_mask).float().sum().item() / keep_mask.float().sum().item()
    else:
        keep_fp_rate = 0.0
    return expected_cost + 50.0 * keep_fp_rate


def _epoch(
    model: FileClassifierV2,
    optimizer: torch.optim.Optimizer,
    x: torch.Tensor,
    y: torch.Tensor,
    generator: torch.Generator,
    safety_lambda: float,
) -> None:
    model.train()
    n = x.shape[0]
    perm = torch.randperm(n, generator=generator)
    for start in range(0, n, BATCH_SIZE):
        batch = perm[start:start + BATCH_SIZE]
        optimizer.zero_grad()
        loss = safety_loss(model(x[batch]), y[batch], safety_lambda)
        loss.backward()
        optimizer.step()


def train(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_val: np.ndarray,
    y_val: np.ndarray,
    epochs: int = DEFAULT_EPOCHS,
    seed: int = SEED,
    device: str = "cpu",
) -> TrainResult:
    seed_everything(seed)
    mean, std = compute_normalization(x_train)

    dev = torch.device(device)
    xt = torch.from_numpy(standardize(x_train, mean, std)).to(dev)
    yt = torch.from_numpy(y_train).to(dev)
    xv = torch.from_numpy(standardize(x_val, mean, std)).to(dev)
    yv = torch.from_numpy(y_val).to(dev)

    model = FileClassifierV2().to(dev)
    optimizer = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    generator = torch.Generator()
    generator.manual_seed(seed)

    best_metric = float("inf")
    best_state = {k: v.clone() for k, v in model.state_dict().items()}
    stale = 0
    history: list[float] = []

    for _ in range(epochs):
        _epoch(model, optimizer, xt, yt, generator, SAFETY_LAMBDA)
        model.eval()
        with torch.no_grad():
            metric = safety_val_metric(model(xv), yv)
        history.append(metric)
        if metric < best_metric - 1e-5:
            best_metric = metric
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            stale = 0
        else:
            stale += 1
            if stale >= PATIENCE:
                break
    model.load_state_dict(best_state)

    # Safety fine-tune: if the model still calls any validation KEEP sample
    # cleanable, run bounded extra rounds with a boosted safety term. The
    # golden gate stays a held-out check in evaluate.py.
    safety_rounds = 0
    for round_index in range(MAX_SAFETY_ROUNDS):
        model.eval()
        with torch.no_grad():
            pred = model(xv).argmax(dim=1)
        keep_mask = yv == L.KEEP
        cleanable = (pred == L.SAFE_TO_REMOVE) | (pred == L.LIKELY_JUNK)
        violations = int((cleanable & keep_mask).sum().item())
        if violations == 0:
            break
        safety_rounds += 1
        boosted = SAFETY_LAMBDA * (2.0 ** (round_index + 1))
        for _ in range(SAFETY_ROUND_EPOCHS):
            _epoch(model, optimizer, xt, yt, generator, boosted)

    model.eval()
    return TrainResult(
        model=model.cpu(), mean=mean, std=std, history=history, safety_rounds=safety_rounds
    )


def save_result(result: TrainResult, path) -> None:
    torch.save(
        {
            "state_dict": result.model.state_dict(),
            "mean": result.mean,
            "std": result.std,
            "history": result.history,
            "safety_rounds": result.safety_rounds,
        },
        path,
    )


def load_result(path) -> TrainResult:
    payload = torch.load(path, weights_only=False)
    model = FileClassifierV2()
    model.load_state_dict(payload["state_dict"])
    model.eval()
    return TrainResult(
        model=model,
        mean=payload["mean"],
        std=payload["std"],
        history=payload["history"],
        safety_rounds=payload["safety_rounds"],
    )
