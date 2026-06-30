# Cleanton — Machine Learning Pipeline Spec

> Detailed specification for the Python-based ML training framework.
> This framework is responsible for dataset generation, labeling, feature engineering,
> model training, and exporting the pre-trained ONNX file classification model.

---

## 1. Overview & Objectives

The `cleanton-ml` crate provides intelligent file classification for ambiguous items that are not covered by static cleanup recipes. To support this, we maintain a Python framework located in `crates/cleanton-ml/training/` that enables developer-focused model iteration.

### Key Objectives:
1. **Zero-Drift Feature Extraction**: Feature extraction logic in Python must match Rust's `cleanton-ml` implementation exactly.
2. **False Positive Prevention**: A false positive (marking a critical file as `SafeToRemove`) is catastrophic. The pipeline must heavily penalize false positives.
3. **Reproducible ONNX Export**: Complete training and exporting pipeline that outputs a lightweight (<5MB) ONNX model.
4. **Validation Guardrails**: Automatically verify the exported ONNX model against a golden dataset prior to integration.

---

## 2. Framework Directory Structure

The Python framework is structured as follows:

```
crates/cleanton-ml/training/
├── README.md               # Pipeline usage and developer guide
├── requirements.txt        # Python package dependencies
├── features.py             # Feature extraction and encoding (Shared schemas)
├── dataset.py              # File system scanning and raw dataset generation
├── labeler.py              # Interactive semi-automated data labeling tool
├── model.py                # PyTorch neural network definition (MLP)
├── train.py                # Model training, cross-validation, and hyperparameter tuning
├── evaluate.py             # Accuracy metrics and false-positive safety checks
└── export_onnx.py          # PyTorch to ONNX converter and sanity checker
```

---

## 3. Dataset Generation (`dataset.py` & `features.py`)

A dataset consists of file metadata vectors representing both developer waste and important source files. 

### 3.1 Feature Vector Specification
The feature vector contains 12 core values, designed for fast extraction without reading file contents:

| Index | Feature Name | Type | Scaling / Encoding | Description |
|---|---|---|---|---|
| `0` | `extension_id` | `int` | Integer (0-255) | Category code for file extensions (mapped in `features.py`) |
| `1` | `size_log10` | `float` | Log scale | `log10(file_size_bytes + 1)` |
| `2` | `age_days` | `float` | Min-max scaled | Days since last modification date |
| `3` | `depth` | `int` | Raw integer | Depth level from the scan root |
| `4` | `parent_id` | `int` | Integer (0-255) | Category code for parent folder name (e.g., target, build, src) |
| `5` | `has_gitignore` | `float` | Binary `[0.0, 1.0]` | Presence of a `.gitignore` file in the directory hierarchy |
| `6` | `has_lockfile` | `float` | Binary `[0.0, 1.0]` | Presence of a package lockfile (e.g., `Cargo.lock`, `package-lock.json`) |
| `7` | `is_hidden` | `float` | Binary `[0.0, 1.0]` | File name begins with a dot (`.`) |
| `8` | `sibling_count` | `float` | Log scale | `log10(number_of_files_in_directory + 1)` |
| `9` | `in_build_dir` | `float` | Binary `[0.0, 1.0]` | Path matches known build patterns (`build/`, `dist/`, `out/`, etc.) |
| `10` | `is_source_ext` | `float` | Binary `[0.0, 1.0]` | Extension belongs to source code (e.g., `.rs`, `.swift`, `.ts`, `.py`) |
| `11` | `in_cache_dir` | `float` | Binary `[0.0, 1.0]` | Directory name contains "cache" or "tmp" |

### 3.2 Dataset Generation Pipeline
The script `dataset.py` crawls directories on developer workstations to build the dataset:

```python
# dataset.py high-level flow
def generate_dataset(scan_root: str, output_csv: str):
    """
    1. Walk the filesystem starting at scan_root (respecting gitignore)
    2. For each file encountered, extract the 12 features using features.py
    3. Output raw feature data along with the absolute path (for labeling)
    4. Save to CSV format: path, feat_0, feat_1, ..., feat_11, label (default: -1 for unlabeled)
    """
```

---

## 4. Interactive Labeler (`labeler.py`)

To quickly generate high-quality labeled datasets, `labeler.py` provides a semi-automated labeling CLI.

### 4.1 Target Labels
The classifier uses a 4-class categorization:

| Label ID | Classification | Action Class | Description |
|---|---|---|---|
| `0` | `Keep` | Safe / Do Not Clean | Critical files: Source code, user documents, keys |
| `1` | `SafeToRemove` | Regenerable waste | Build artifacts, caches, logs |
| `2` | `LikelyJunk` | Probable waste | Long-unused venvs, orphaned config directories |
| `3` | `Uncertain` | Manual review required | Ambiguous files requiring user choice |

### 4.2 Semi-Automated Assistant
To reduce manual labeling time:
1. **Rule-Based Pre-labeling**: Applies static recipes to label obvious files (e.g., matching `node_modules` or `.pyc` automatically receives `SafeToRemove`).
2. **LLM Labeling Assistant**: Optional training-only tooling may use an LLM API to analyze redacted path metadata, size, and sibling summaries. This is never part of the shipped app.
3. **Interactive Terminal Triage**: Developer verifies the pre-labeled items and manually tags ambiguous cases via keyboard bindings (`k`=Keep, `s`=SafeToRemove, `l`=LikelyJunk, `u`=Uncertain).

LLM-assisted labeling must redact usernames, repository names when requested, secrets, tokens, and absolute paths before any network call. Raw datasets containing local paths must stay out of git.

---

## 5. Model Architecture & Training (`model.py` & `train.py`)

Because the model runs locally within a terminal utility, inference must be fast and CPU-efficient. We use a Multilayer Perceptron (MLP) architecture.

### 5.1 Model Architecture (`model.py`)
A feedforward PyTorch neural network:
* **Input Layer**: 12 units (corresponding to features)
* **Hidden Layer 1**: 32 units, ReLU activation, Dropout (0.2)
* **Hidden Layer 2**: 16 units, ReLU activation
* **Output Layer**: 4 units (logits for each classification label)

### 5.2 Loss Function (Safety-Biased)
To enforce the safety model, we use a custom weighted loss function that heavily penalizes false positives (predicting `SafeToRemove` (1) or `LikelyJunk` (2) when the true label is `Keep` (0)):

$$\mathcal{L} = -\sum_{i} w_{y_i} \cdot \log(\hat{y}_{i, y_i}) + \lambda \mathcal{L}_{\text{safety\_penalty}}$$

Where the safety penalty is calculated as:
* If True Label = `Keep` and Predicted Label = `SafeToRemove`, apply a **100x weight penalty**.
* If True Label = `Keep` and Predicted Label = `LikelyJunk`, apply a **50x weight penalty**.

### 5.3 Training Script (`train.py`)
Features:
1. **Cross-Validation**: 5-fold cross-validation to ensure model generalization.
2. **Class Imbalance Handling**: Uses weighted sampling and explicit hard-negative sets. Do not use synthetic oversampling that can blur categorical/path semantics unless validated by the safety suite.
3. **Early Stopping**: Halts training once validation loss plateaus to prevent overfitting.

---

## 6. Evaluation & ONNX Export (`evaluate.py` & `export_onnx.py`)

### 6.1 Safety Assertions (`evaluate.py`)
Before export, the model must pass a suite of hardcoded safety assertions:
* **Constraint 1**: False Positive Rate (predicting cleanable for `Keep` files) must be exactly **0.0%** on the golden safety set and below the release threshold on the validation set.
* **Constraint 2**: In a synthetic test set of critical system files, credentials, source files, user documents, app containers, and agent histories, the model must predict `Keep` with > 99.9% confidence.
* **Constraint 3**: No model output may create an executable cleanup action by itself. The Rust engine treats ML as annotation-only unless the user explicitly selects an item.
* If any constraint fails, the script exits with an error and halts the build pipeline.

### 6.2 ONNX Export (`export_onnx.py`)
Converts the PyTorch model to ONNX representation for execution in Rust:

```python
import torch
import torch.onnx
from model import FileClassifierMLP

def export():
    model = FileClassifierMLP()
    model.load_state_dict(torch.load("best_model.pt"))
    model.eval()
    
    # Dummy input representing one feature vector (1, 12)
    dummy_input = torch.randn(1, 12, dtype=torch.float32)
    
    # Export to ONNX
    torch.onnx.export(
        model,
        dummy_input,
        "../models/file_classifier_v1.onnx",
        export_params=True,
        opset_version=15,
        do_constant_folding=True,
        input_names=['features'],
        output_names=['logits'],
        dynamic_axes={'features': {0: 'batch_size'}, 'logits': {0: 'batch_size'}}
    )
    print("Model successfully exported to ONNX format.")
```

---

## 7. Verification and Integration

```
+------------------+     +--------------------+     +-------------------+
|  Generate Raw    | --> | Interactive Triage | --> | Training Pipeline |
|  Dataset (CSV)   |     |    (labeler.py)    |     | (train.py, PyTorch|
+------------------+     +--------------------+     +-------------------+
                                                              |
                                                              v
+------------------+     +--------------------+     +-------------------+
| Rust ml Crate    | <-- | Verification test  | <-- | ONNX Export       |
| (ONNX runtime)   |     | (evaluate.py)      |     | (export_onnx.py)  |
+------------------+     +--------------------+     +-------------------+
```

1. The output `file_classifier_v1.onnx` is saved directly into `crates/cleanton-ml/models/`.
2. The Rust `cleanton-ml` crate embeds this file using `include_bytes!("models/file_classifier_v1.onnx")`.
3. During compilation, the Cargo build script (`build.rs`) performs a test inference pass using the `ort` ONNX Runtime library to ensure runtime compatibility.
