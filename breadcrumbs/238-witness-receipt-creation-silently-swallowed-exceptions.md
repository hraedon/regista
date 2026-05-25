---
number: "238"
title: Witness receipt creation silently swallowed exceptions
severity: high
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [witness, error-handling, data-loss]
related: ["233"]
---

## Problem

`_try_create_witness_receipts` in `__init__.py` wrapped `create_receipts()` in `except Exception: pass` — database failures, migration gaps, and all other errors were silently discarded with no log, metric, or re-raise. The InMemory counterpart had NO exception handling at all, so a failure in receipt creation would crash the entire `create_work_item`/`transition`/`append_event` call.

## Fix

- Postgres backend: Changed `except Exception: pass` to `except Exception as exc:` with structured log warning including project and event_id.
- InMemory backend: Wrapped `_try_create_witness_receipts` in `try/except` with structured log warning.