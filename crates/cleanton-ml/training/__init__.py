"""cleanton-ml training framework.

Deterministic, reproducible pipeline that generates a synthetic but realistic
macOS path dataset, derives labels grounded in the cleanton recipe corpus and
protected-path rules, trains a small safety-biased MLP, enforces a 0%
false-positive gate on a golden keep-set, and exports an ONNX model that the
pure-Rust ``cleanton-ml`` crate runs with ``tract``.
"""
