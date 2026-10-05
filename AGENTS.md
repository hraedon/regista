# Regista — 0.8.0 agent guide

[spec.md](spec.md) is normative for the reduced coordination kernel. The public
API is exactly `src/regista/__init__.py::__all__`; the current references are
[API](docs/api.md), [CLI](docs/cli.md), and [operations](docs/operations.md).
Transition and reduction live only in `src/regista/kernel.py`. Load schema and
workflow resources with `importlib.resources`; keep installed artifacts usable
without a checkout or private configuration.

Use `.venv/bin/ruff check src/ tests/ examples/ scripts/`, `.venv/bin/mypy`,
and `REGISTA_TEST_DSN=<disposable-postgres-dsn> .venv/bin/python -m pytest tests/ -q`.
CI tests Python 3.11–3.14 on PostgreSQL 15 and 3.14 on PostgreSQL 16 and 17.
CI and `REGISTA_REQUIRE_DB=1` fail
without a DSN. Never point tests at production. Qualify both wheel and sdist,
installed examples, restart and a separate-database restore followed by a valid
write. Run mutation checks, build/render/smoke checks and the schema/artifact guard.
Generate references with `.venv/bin/python scripts/generate_reference.py`.

Initialization requires an empty destination or schema baseline 1. There is no
in-place upgrade from 0.7.2 or earlier, converter or reset. Actor names are
attribution; caller-presented role checks require a trusted host. Unkeyed hashes
provide consistency checking and no authenticity evidence. Document replay's
exclusions (leases, attempt counters, links and idempotency keys).

Leases persist through transitions until explicit release. Callers validate
before transitions: no synchronous validator registry ships. Operators create
service roles, schedule `expire-leases`, and manually drop project schemas.
Do not reintroduce suite configuration, signing/trust governance, sidecar,
in-memory/async engines, callbacks, recurrence or workflow composition.

Keep commits attributed and use `git -c core.hooksPath="$PWD/githooks" commit`.
Do not publish, dispatch the publish workflow, upload artifacts or create/push
tags without separate authorization. Keep tracker writes within explicit user
authorization. The maintenance commitment is 90 days from publication for release
regressions and serious security/data-loss reports, with no feature promise/SLA.

The [previous agent guide](docs/pre-0.8/AGENTS.md) and other pre-0.8 documents are
historical. [Plan 032 decisions](plans/032-open-decisions.md) and the
[closed protection ledger](plans/032-f0-inventory/F1-protection-ledger.md) record
the cutover; dated rulings override earlier adopted defaults.
