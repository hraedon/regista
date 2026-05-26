---
number: "262"
title: CLI write commands for work items and transitions
severity: low
status: resolved
kind: improvement
author: adversarial-review
date: "2026-05-26"
tags: [cli, usability]
related: []
---

## Problem

The CLI was read-only by design. Operators debugging workflows had to write Python or use the sidecar.

## Fix

Added `substrate work-item create` and `substrate work-item transition` commands. Both gated by `--confirm` flag. Without `--confirm`, prints what would happen. With `--confirm`, executes. Supports `--custom-fields`, `--payload`, `--actor-metadata` as JSON strings.
