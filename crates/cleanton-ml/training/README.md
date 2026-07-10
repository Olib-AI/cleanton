# cleanton-ml training pipeline (v2)

Deterministic Python framework that trains the file classifier shipped (as
ONNX) inside the `cleanton-ml` Rust crate. The model is **advisory only** —
the engine never deletes based on it — and training is biased so that every
mistake the model makes falls in the *keep* direction.

## Commands

From the crate root (`crates/cleanton-ml`), or via `make` in this directory:

```bash
make venv                      # isolated .venv with pinned deps + pytest
make test                      # labeler / recipe-DSL / feature unit tests
make smoke                     # full pipeline end-to-end in seconds,
                               # artifacts to a temp dir (never ../models)
make                           # FULL run: exports ../models/*_v2.* artifacts
```

Direct invocations (all deterministic, seed 1337):

```bash
python3 -m training.run            # full pipeline -> ../models
python3 -m training.run --smoke    # fast proof run  -> temp dir
python3 -m training.run --stage dataset --out-dir training/artifacts   # cached stages
python3 -m training.features       # schema self-check + schema sha256
python3 -m training.features --schema   # full machine-readable schema (for the Rust port)
python3 -m training.harvest --out h.npz # OPTIONAL read-only local metadata harvest
python3 -m training.run --harvest-file h.npz   # adds a real-world advisory report
```

## Architecture

| Module | Purpose |
|---|---|
| `vocab.py` | real-world name vocabularies (npm/crates/PyPI/Go/brew/apps/HF models/doc names) |
| `fstree.py` | virtual filesystem trees; context (siblings, markers, sizes) derived from the ACTUAL tree |
| `generator.py` | coherent macOS home-dir worlds: per-ecosystem projects, ~/Library, user data, credentials, systematic decoys |
| `recipes_dsl.py` | Python mirror of the recipe TOML DSL + matcher semantics (`any_of`, excludes, guards, glob semantics, safety floors) |
| `labeler.py` | grounded labels: floors -> recipe excludes -> recipe matches (descendants inherit) -> keep evidence -> near-miss -> uncertain |
| `features.py` | 53-feature schema v2 (formulas + vocab tables + schema hash); the Rust port's parity anchor |
| `dataset.py` | world-level splits, balanced train + realistic-prior eval, golden keep corpus, adversarial suites, recipe-fixture mining |
| `model.py` | embeddings (extension, parent, grandparent) + MLP, single f32 input tensor |
| `train.py` | asymmetric safety-cost loss, deterministic training, safety fine-tune rounds |
| `evaluate.py` | hard gates, calibration (ECE), threshold sweep, confusion matrices |
| `export_onnx.py` | `file_classifier_v2.onnx` + sidecar + `parity_cases_v2.json` |
| `harvest.py` | optional read-only local metadata calibration (protected roots skipped entirely) |

## Dataset: coherent worlds, grounded labels

The generator builds entire simulated home directories (a Rust project has
`Cargo.toml` + `Cargo.lock` + `src/*.rs` + a populated `target/`; node
projects carry real npm package layouts inside `node_modules`; ML projects
have checkpoints, wandb runs, HF caches), plus non-dev life (`~/Documents`,
`~/Library` caches AND their keep-shaped siblings, credentials dotfiles,
Containers). Sizes are log-normal per file class; ages have project-level
locality (active / dormant / abandoned); `has_gitignore` / `has_lockfile` /
sibling counts are read from the generated tree, never sampled independently.

Labels are derived — never hand-set — from the same rules the engine
enforces, in priority order: safety floors (`safety.rs` protected roots +
sensitive basenames), recipe `[match.exclude]` author-declared keeps (only
excludes on path-anchored selectors count — broad reroutes like
`~/.cache/**` on `**/*.pt` never manufacture keeps), full recipe matches
under the complete 130-recipe DSL with the engine's first-match-wins
priority order (safe -> safe-to-remove, cautious/aggressive -> likely-junk;
descendants of a matched directory inherit), keep evidence (.git internals,
manifests, source/docs/media), near-miss guard failures -> uncertain.

Splits are WORLD-level (no leakage). Training is class-balanced
(oversampling scarce classes); the realistic-prior split keeps the natural
distribution so reported numbers are honest.

## Loss (asymmetric penalty matrix)

`CE (class-weighted, label smoothing on non-keep targets only) + λ·E[cost]`:

|            | pred keep | pred safe | pred junk | pred uncertain |
|------------|-----------|-----------|-----------|----------------|
| true keep  | 0         | **100**   | **60**    | 1              |
| true safe  | 2         | 0         | 1         | 1              |
| true junk  | 2         | 1         | 0         | 1              |
| true uncertain | 1     | **8**     | **6**     | 0              |

λ = 1.0; keep is 3x class-weighted in the CE. After early stopping (on a
safety-weighted validation metric) up to 3 bounded fine-tune rounds with a
boosted λ run if any validation keep is still predicted cleanable.

## Eval gates (FAIL the build)

* **G1** golden keep corpus (credentials, active source, documents, mail /
  messages / Containers shapes, .git internals, live venvs, agent history,
  plus mined recipe `should_not_match` fixtures): **zero** cleanable
  predictions.
* **G2** curated adversarial decoys (loose `target`, `node_modules` without
  `package.json`, `checkpoint-*` without `trainer_state.json`, tiny `.pt`,
  fresh `.venv`, non-Unity `Library`, ...): zero cleanable at confidence
  >= 0.85 (the engine threshold).
* **G2b** mined near-miss suite (guard failures from held-out worlds — these
  sit on continuous age/size boundaries): confident-cleanable rate <= 5%.
* **G3** per-class recall floors on the balanced test split (keep >= 0.90,
  safe >= 0.75, junk >= 0.55, uncertain >= 0.40) so the model is not
  uselessly conservative.
* **G4** ECE (15 bins) on the realistic split <= 0.20.

The report also includes both confusion matrices, a threshold sweep
(keep-catch vs cleanable-nuisance at 0.5–0.95), and the recipe
`should_match` fixture agreement rate. Smoke mode keeps G1 and relaxed G3.

## Feature schema v2 (53 features)

Indices 0–2 are integer categorical ids (extension, parent dir,
grandparent dir) consumed by in-graph embeddings; 3–9 numeric
(log10 size/age/siblings/name-length, depth, digit ratio, size-vs-siblings);
10–36 binary path/context flags (`in_node_modules`, `in_library_caches`,
`in_containers`, `ancestor_has_lockfile`, extension classes, ...);
37–52 FNV-1a hashed basename-token buckets. Exact formulas and vocab tables
live in `features.py` and are exported by `--schema`; the sidecar embeds the
schema plus its sha256 so the Rust port can verify parity bit-for-bit.

Rust portability: everything is computable from `FileEntry` + a cheap
`FileContext`. v2 needs three context additions (computable from scan data
alone, same as the existing `build_contexts`): `sibling_total_bytes`,
`ancestor_has_lockfile`, `ancestor_has_project_marker`.

## Export

`../models/file_classifier_v2.onnx` (~130 KB, opset 13, raw logits;
Slice/Clip/Equal/Cast/MatMul/Concat/Gemm/Relu — embeddings are exported as
one-hot Equal+MatMul because tract-onnx 0.21.10, the workspace pin, fails
`into_optimized()` on Gather-from-f32-const on Apple Silicon; the exported
graph is verified to load, optimize and reproduce the parity cases under
tract-onnx 0.21.10), `file_classifier_v2.json` sidecar
(feature order, mean/std with identity for the categorical slots, label
order, full schema + hash), `parity_cases_v2.json` (raw vectors + expected
logits/softmax for the Rust golden test). The Rust crate embeds the v2
model + sidecar (`src/lib.rs` / `src/inference.rs`); `src/features.rs` is
the port of `features.py`, with unit tests asserting its tables and the
schema hash against the sidecar and `tests/inference.rs` asserting golden
parity against `parity_cases_v2.json`. The v1 artifacts were removed when
the port landed — nothing references them.

## Environment

Python 3.12 (macOS arm64), deps pinned in `requirements.txt`
(torch 2.9.0, onnx 1.18.0, onnxruntime 1.23.2, numpy 2.1.3) plus
`dev-requirements.txt` (pytest). Training is CPU-deterministic; pass
`--device mps` only if you accept non-deterministic kernels.
