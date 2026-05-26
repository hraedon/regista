---
number: "247"
title: Recurrence rule update skips schedule_expr and template validation
severity: high
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [recurrence, validation]
related: []
---

## Problem

`update_recurrence_rule()` accepted `schedule_expr` and `template` parameters without calling `validate_schedule()` or `validate_template()`. An invalid RRULE string or malformed template could be stored, causing an unhandled exception at fire time during the maintenance cycle.

## Fix

Added `validate_schedule()` and `validate_template()` calls in `update_recurrence_rule()` before storing the new values.
