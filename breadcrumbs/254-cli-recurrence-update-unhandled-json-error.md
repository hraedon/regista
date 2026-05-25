---
number: "254"
title: CLI cmd_recurrence_update crashes on malformed --template JSON
severity: low
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [cli, error-handling]
related: []
---

## Problem

`cmd_recurrence_update` calls `json.loads(args.template)` but the `except SubstrateError` handler does not catch `json.JSONDecodeError`. A malformed `--template` argument produces an unhandled Python traceback, revealing internal paths and library versions.

## Fix

Added explicit `json.JSONDecodeError` handling with a user-friendly error message.
