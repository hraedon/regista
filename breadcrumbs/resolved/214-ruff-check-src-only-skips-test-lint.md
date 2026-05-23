---
number: "214"
title: "ruff check src/ only skips lint errors in tests/ across multiple sessions"
severity: low
status: implemented
kind: improvement
author: kimi-k2.6
date: "2026-05-23"
tags: [ci, lint, tooling]
related: []
---

# BC-214 — `ruff check src/` only skips lint errors in tests/

## Problem

Sessions 30–32 appeared to run `ruff check src/` (or similar) prior to commit, leaving latent lint errors accumulating in `tests/`. In Session 33, `.venv/bin/ruff check src/ tests/` surfaced:

- `E501` line-too-long SQL strings in `test_replay_coverage.py`
- `F401` unused imports in `test_plan010.py` and `test_replay_coverage.py`
- `RUF059` unused unpacked variables in `test_plan010.py`, `test_replay_coverage.py`, `test_plan010_integration.py`, `test_recurrence_postgres.py`

These are minor but add friction to every future session because an innocent change triggers noisy lint output.

## Fix

Ran full `.venv/bin/ruff check src/ tests/` and fixed all errors:
- Fixed via `ruff --fix --unsafe-fixes` for underscore-prefix renames (RUF059).
- Removed unused imports (F401) manually.
- Split SQL strings to satisfy E501.

All touched files verified: 74 targeted tests pass. Full lint is now clean.

## Mitigation

No code or CI change needed — just agent convention. Always run `ruff check src/ tests/` (or `make check` if it includes tests) before committing.
