# NetGuard — developer convenience targets.
# These are thin wrappers; everything also works with plain pip/pytest/python.

PYTHON ?= python3

.PHONY: help setup samples test lint build demo clean

help:
	@echo "NetGuard make targets:"
	@echo "  make setup    - create venv deps and install the package (editable, with dev extras)"
	@echo "  make samples  - (re)generate the synthetic sample PCAPs into samples/"
	@echo "  make test     - run the pytest suite"
	@echo "  make lint     - run ruff over the package and tests"
	@echo "  make build    - build the sdist + wheel"
	@echo "  make demo     - regenerate samples and replay them through the detectors"
	@echo "  make clean    - remove build/test artifacts and generated samples"

setup:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"

samples:
	$(PYTHON) scripts/gen_samples.py --out samples

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check netguard tests scripts

build:
	$(PYTHON) -m build

# End-to-end offline demo: no Docker, no root. Build the sample PCAPs and run
# each detector over its matching capture so a reviewer sees alerts fire.
demo: samples
	$(PYTHON) scripts/run_pcap_demo.py

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache htmlcov .coverage coverage.xml
	rm -f samples/*.pcap
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
