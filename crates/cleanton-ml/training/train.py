"""Deterministic training with a safety-biased loss.

The loss is a class-weighted cross-entropy plus an explicit safety penalty that
heavily punishes predicting a *clean* class on a true ``Keep`` file:

    L = CE_weighted(logits, y) + lambda * mean_over_keep( 100*p_safe + 50*p_junk )

This directly drives down the false-positive probability mass on Keep files,
implementing doc/ML_PIPELINE.md section 5.2 (100x / 50x penalties).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

import numpy as np
import torch
from torch import nn

import labeler
from dataset import Dataset, generate
from model import FileClassifierMLP

SEED = 1337
EPOCHS = 120
PATIENCE = 15
BATCH_SIZE = 256
LR = 1e-3
WEIGHT_DECAY = 1e-5
SAFETY_LAMBDA = 1.0
FP_PENALTY_SAFE = 100.0
FP_PENALTY_JUNK = 50.0
STD_FLOOR = 1e-6


def seed_everything(seed: int = SEED) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)


@dataclass
class Split:
    x_train: torch.Tensor
    y_train: torch.Tensor
    x_val: torch.Tensor
    y_val: torch.Tensor
    x_test: torch.Tensor
    y_test: torch.Tensor


@dataclass
class TrainResult:
    model: FileClassifierMLP
    mean: np.ndarray
    std: np.ndarray
    split: Split
    cv_accuracy: float = 0.0
    history: list[float] = field(default_factory=list)


def _stratified_indices(
    labels: np.ndarray, rng: np.random.Generator, fracs: tuple[float, float, float]
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    train_idx, val_idx, test_idx = [], [], []
    for cls in np.unique(labels):
        idx = np.where(labels == cls)[0]
        rng.shuffle(idx)
        n = len(idx)
        n_train = int(n * fracs[0])
        n_val = int(n * fracs[1])
        train_idx.extend(idx[:n_train])
        val_idx.extend(idx[n_train : n_train + n_val])
        test_idx.extend(idx[n_train + n_val :])
    return (
        np.array(sorted(train_idx)),
        np.array(sorted(val_idx)),
        np.array(sorted(test_idx)),
    )


def _normalization(x: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    mean = x.mean(axis=0).astype(np.float32)
    std = x.std(axis=0).astype(np.float32)
    std = np.maximum(std, STD_FLOOR).astype(np.float32)
    return mean, std


def safety_biased_loss(
    logits: torch.Tensor, targets: torch.Tensor, class_weights: torch.Tensor
) -> torch.Tensor:
    ce = nn.functional.cross_entropy(logits, targets, weight=class_weights)

    probs = torch.softmax(logits, dim=1)
    keep_mask = targets == labeler.KEEP
    if keep_mask.any():
        p_safe = probs[keep_mask, labeler.SAFE_TO_REMOVE]
        p_junk = probs[keep_mask, labeler.LIKELY_JUNK]
        penalty = (FP_PENALTY_SAFE * p_safe + FP_PENALTY_JUNK * p_junk).mean()
    else:
        penalty = logits.new_zeros(())
    return ce + SAFETY_LAMBDA * penalty


def _class_weights() -> torch.Tensor:
    # Up-weight Keep so the network is conservative; classes are already
    # balanced so the rest are equal.
    w = torch.ones(labeler.NUM_CLASSES, dtype=torch.float32)
    w[labeler.KEEP] = 3.0
    return w


def _train_one(
    x_train: torch.Tensor,
    y_train: torch.Tensor,
    x_val: torch.Tensor,
    y_val: torch.Tensor,
    seed: int,
) -> tuple[FileClassifierMLP, list[float]]:
    torch.manual_seed(seed)
    model = FileClassifierMLP()
    optimizer = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    weights = _class_weights()

    generator = torch.Generator()
    generator.manual_seed(seed)
    n = x_train.shape[0]

    best_val = float("inf")
    best_state = {k: v.clone() for k, v in model.state_dict().items()}
    epochs_without_improvement = 0
    history: list[float] = []

    for _ in range(EPOCHS):
        model.train()
        perm = torch.randperm(n, generator=generator)
        for start in range(0, n, BATCH_SIZE):
            batch = perm[start : start + BATCH_SIZE]
            optimizer.zero_grad()
            logits = model(x_train[batch])
            loss = safety_biased_loss(logits, y_train[batch], weights)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            val_loss = safety_biased_loss(model(x_val), y_val, weights).item()
        history.append(val_loss)

        if val_loss < best_val - 1e-5:
            best_val = val_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= PATIENCE:
                break

    model.load_state_dict(best_state)
    return model, history


def _cross_validate(x: torch.Tensor, y: torch.Tensor, folds: int = 5) -> float:
    n = x.shape[0]
    rng = np.random.default_rng(SEED)
    order = rng.permutation(n)
    fold_sizes = np.full(folds, n // folds, dtype=int)
    fold_sizes[: n % folds] += 1

    accuracies = []
    cursor = 0
    for f in range(folds):
        size = fold_sizes[f]
        val_idx = order[cursor : cursor + size]
        train_idx = np.concatenate([order[:cursor], order[cursor + size :]])
        cursor += size

        model, _ = _train_one(
            x[train_idx], y[train_idx], x[val_idx], y[val_idx], seed=SEED + f
        )
        model.eval()
        with torch.no_grad():
            pred = model(x[val_idx]).argmax(dim=1)
        accuracies.append((pred == y[val_idx]).float().mean().item())
    return float(np.mean(accuracies))


def train(dataset: Dataset | None = None, run_cv: bool = True) -> TrainResult:
    seed_everything(SEED)
    if dataset is None:
        dataset = generate(seed=SEED)

    rng = np.random.default_rng(SEED)
    train_idx, val_idx, test_idx = _stratified_indices(
        dataset.labels, rng, (0.7, 0.15, 0.15)
    )

    mean, std = _normalization(dataset.features[train_idx])
    normed = ((dataset.features - mean) / std).astype(np.float32)

    x = torch.from_numpy(normed)
    y = torch.from_numpy(dataset.labels)

    split = Split(
        x_train=x[train_idx],
        y_train=y[train_idx],
        x_val=x[val_idx],
        y_val=y[val_idx],
        x_test=x[test_idx],
        y_test=y[test_idx],
    )

    cv_acc = 0.0
    if run_cv:
        cv_acc = _cross_validate(x[train_idx], y[train_idx])

    model, history = _train_one(
        split.x_train, split.y_train, split.x_val, split.y_val, seed=SEED
    )

    return TrainResult(
        model=model,
        mean=mean,
        std=std,
        split=split,
        cv_accuracy=cv_acc,
        history=history,
    )


if __name__ == "__main__":
    result = train()
    result.model.eval()
    with torch.no_grad():
        pred = result.model(result.split.x_test).argmax(dim=1)
    acc = (pred == result.split.y_test).float().mean().item()
    print(f"5-fold CV accuracy: {result.cv_accuracy:.4f}")
    print(f"held-out test accuracy: {acc:.4f}")
