"""cleanton-ml training framework v2.

Deterministic pipeline that generates coherent synthetic macOS home
directory TREES, derives every label from the safety floors + the full
130-recipe DSL corpus (never hand-set), trains a small embedding-MLP with
an asymmetric safety-cost loss, enforces hard eval gates (0% cleanable on
the golden keep corpus, adversarial near-miss suite, per-class recall
floors, calibration), and exports ``file_classifier_v2.onnx`` + sidecar +
parity fixtures for the pure-Rust ``tract`` inference path.

The model is ADVISORY ONLY: the engine never deletes because of it, and
training is biased so mistakes always fall in the "keep" direction.
"""
