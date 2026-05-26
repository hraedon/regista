---
number: "257"
title: No CLI or test helper for running targeted test subsets by file path
severity: low
status: implemented
kind: improvement
author: glm-5.1
date: "2026-05-25"
tags: [dx, testing, cli]
related: []
---

## Problem

Running tests currently requires either the full suite (`pytest tests/ -v`, ~3 min) or manually constructing a specific file path. There is no convenient way to say "run tests related to the files I just changed" or "run tests for the replay subsystem only." This slows down the develop-verify loop, especially for agents that must verify changes before committing.

## Resolution

Added `make test-files FILES=tests/test_replay_coverage.py` target to Makefile.
