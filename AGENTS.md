# Regista — Stage B agent guide

Plan 032 F1 promotes the PostgreSQL kernel. The public API is exported explicitly
from `src/regista/__init__.py`; transition and reduction live only in
`src/regista/kernel.py`. Package resources load with `importlib.resources`.

Use `.venv/bin/ruff check src/ tests/ examples/ scripts/`, `.venv/bin/mypy`,
and `REGISTA_TEST_DSN=<disposable-postgres-dsn> .venv/bin/python -m pytest tests/ -q`.
CI and `REGISTA_REQUIRE_DB=1` fail without a DSN. Never point tests at production.

Initialization requires an empty destination or this baseline. No in-place
upgrade or reset is supported. Actor names are attribution; the consistency
chain is not authentication. Leases persist until explicit release.

Keep commits attributed and use `git -c core.hooksPath="$PWD/githooks" commit`.
Do not publish or push tags without separate authorization. Keep tracker writes
within the user's explicit authorization.

The previous agent guide is [historical](docs/pre-0.8/AGENTS.md).
The [Plan 032 decisions](plans/032-open-decisions.md) and
[closed protection ledger](plans/032-f0-inventory/F1-protection-ledger.md)
record the cutover. F4 owns the full documentation rewrite.
