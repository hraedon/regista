---
number: "273"
title: "Webhook resume does not reset failure_count — auto-repauses on next failure"
severity: medium
status: proposed
kind: bug
author: design-review
date: "2026-05-26"
tags: [webhooks, state-management]
related: ["269"]
---

## Problem

`resume_webhook` sets `status = 'active'` but does not reset `failure_count`. A webhook that auto-pauses at 10 failures, then is manually resumed, still has `failure_count = 10`. The next failure increments to 11 and immediately re-pauses.

Witness `reactivate_witness` correctly resets `consecutive_failures = 0`.

## Fix

Reset `failure_count = 0` in `resume_webhook`. Will be resolved as part of webhook→witness unification.
