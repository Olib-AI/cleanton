# Prefer the pinned virtualenv when it exists (make venv), else system python3.
PYTHON ?= $(shell [ -x .venv/bin/python ] && echo $(CURDIR)/.venv/bin/python || echo python3)

.PHONY: all venv install dataset train eval export smoke test parity clean

# Full deterministic pipeline: dataset -> train -> evaluate -> export to
# ../models/file_classifier_v2.{onnx,json} + parity_cases_v2.json.
all:
	cd .. && $(PYTHON) -m training.run

# Isolated virtualenv with pinned deps (+ pytest for `make test`).
venv:
	$(PYTHON) -m venv .venv
	./.venv/bin/pip install --upgrade pip
	./.venv/bin/pip install -r requirements.txt -r dev-requirements.txt

install:
	$(PYTHON) -m pip install -r requirements.txt -r dev-requirements.txt

# Fast end-to-end proof (seconds): small dataset, few epochs, temp-dir
# artifacts; never touches ../models.
smoke:
	cd .. && $(PYTHON) -m training.run --smoke

# Individual stages, cached under training/artifacts (full-size settings).
ARTIFACTS := training/artifacts
dataset:
	cd .. && $(PYTHON) -m training.run --stage dataset --out-dir $(ARTIFACTS)
train:
	cd .. && $(PYTHON) -m training.run --stage train --out-dir $(ARTIFACTS)
eval:
	cd .. && $(PYTHON) -m training.run --stage eval --out-dir $(ARTIFACTS)
export:
	cd .. && $(PYTHON) -m training.run --stage export --out-dir $(ARTIFACTS)

# Feature schema v2 self-check + schema hash (Rust port parity anchor).
parity:
	cd .. && $(PYTHON) -m training.features

# Labeler / recipe-DSL / feature unit tests.
test:
	cd .. && $(PYTHON) -m pytest training/tests -q

clean:
	rm -rf __pycache__ tests/__pycache__ .venv .pytest_cache
