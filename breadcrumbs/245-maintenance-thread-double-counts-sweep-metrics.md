---
number: "245"
title: Maintenance thread double-counts sweep metrics
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [metrics, maintenance, observability]
related: ["185"]
---

## Problem

`MaintenanceThread._run()` incremented `maintenance_claims_swept` and `maintenance_hook_leases_swept` after calling `sweep_expired_claims()` and `sweep_expired_hook_leases()`. However, the underlying facade methods (`ClaimOps.sweep_expired()` and `HookOps.sweep_expired_leases()`) already emitted these same metrics. Prometheus counters reported 2x actual swept counts.

## Fix

Removed the duplicate metric increments from `_maintenance.py`, keeping only the ones in `_ops.py` facades.
