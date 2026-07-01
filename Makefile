.PHONY: all lint typecheck test test-files cov check clean

VENV := .venv
PYTHON := $(VENV)/bin/python
RUFF := $(VENV)/bin/ruff
MYPY := $(VENV)/bin/mypy
PYTEST := $(VENV)/bin/pytest

all: check

check: lint typecheck test

lint:
	$(RUFF) check src/ tests/

typecheck:
	$(MYPY)

test:
	$(PYTEST) tests/ -v

test-files:
	$(PYTEST) $(FILES) -v

cov:
	$(PYTEST) tests/ -v --cov=regista --cov-report=term-missing

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
