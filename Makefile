.PHONY: all lint typecheck test test-files cov check clean

VENV := .venv
all: check
check: lint typecheck test
lint:
	$(VENV)/bin/ruff check src/ tests/ examples/ scripts/
typecheck:
	$(VENV)/bin/mypy
test:
	$(VENV)/bin/python -m pytest tests/ -v
test-files:
	$(VENV)/bin/python -m pytest $(FILES) -v
cov:
	$(VENV)/bin/python -m pytest tests/ --cov=regista --cov-report=term-missing
clean:
	find src tests examples scripts -type d -name __pycache__ -exec rm -rf {} +
