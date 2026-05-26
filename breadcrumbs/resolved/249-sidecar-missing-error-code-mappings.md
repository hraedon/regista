---
number: "249"
title: Sidecar missing error code mappings for DELEGATION_CHAIN_EXPIRED and RESERVED_TRANSITION_NAME
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [sidecar, error-handling]
related: ["241"]
---

## Problem

The sidecar's `_STATUS_MAP` did not include `DELEGATION_CHAIN_EXPIRED` or `RESERVED_TRANSITION_NAME`. Both are client errors that should return 400 but instead defaulted to 500, confusing clients and potentially triggering false alerts.

## Fix

Added both error codes to `_STATUS_MAP` with 400 status.
