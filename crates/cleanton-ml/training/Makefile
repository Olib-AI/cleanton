PYTHON ?= python3

.PHONY: all venv install parity train clean

# Run the full deterministic pipeline: dataset -> train -> evaluate -> export.
# Executed from the crate root so `training` is importable as a package.
all:
	cd .. && $(PYTHON) -m training.run

# Create an isolated virtualenv under training/.venv and install pinned deps.
venv:
	$(PYTHON) -m venv .venv
	./.venv/bin/pip install --upgrade pip
	./.venv/bin/pip install -r requirements.txt

install:
	$(PYTHON) -m pip install -r requirements.txt

# Feature-extraction parity self-check only.
parity:
	$(PYTHON) features.py

clean:
	rm -rf __pycache__ .venv
