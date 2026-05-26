.PHONY: all lint test test-files cov check clean

VENV := .venv
PYTHON := $(VENV)/bin/python
RUFF := $(VENV)/bin/ruff
PYTEST := $(VENV)/bin/pytest

all: check

check: lint test

lint:
	$(RUFF) check src/ tests/

test:
	$(PYTEST) tests/ -v

test-files:
	$(PYTEST) $(FILES) -v

cov:
	$(PYTEST) tests/ -v --cov=substrate --cov-report=term-missing

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
