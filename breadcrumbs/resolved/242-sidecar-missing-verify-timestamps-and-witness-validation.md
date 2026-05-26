---
number: "242"
title: Sidecar missing verify_timestamps and max_failures/max_retries validation
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [sidecar, validation, witness]
related: []
---

## Problem

1. `ReplayRequest` model was missing `verify_timestamps` parameter — consumers could never trigger timestamp verification through the HTTP API.
2. `RegisterWitnessRequest` model accepted negative/zero values for `max_failures` and `max_retries` without validation — `max_failures=0` would immediately auto-pause witnesses, `-1` would bypass the check entirely.
3. Core `register_witness` (both Postgres and InMemory) had no validation of `max_failures`/`max_retries` bounds either.

## Fix

- Added `verify_timestamps: bool = False` to `ReplayRequest` model and wired through sidecar route.
- Added `ge=1` constraint to `max_failures` and `max_retries` in `RegisterWitnessRequest`.
- Added validation in `_witness.register_witness()` and `InMemorySubstrate.register_witness()`.