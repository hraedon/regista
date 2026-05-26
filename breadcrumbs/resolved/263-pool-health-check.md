---
number: "263"
title: Connection pool health in maintenance_healthy
severity: low
status: resolved
kind: improvement
author: adversarial-review
date: "2026-05-26"
tags: [operations, monitoring]
related: []
---

## Problem

`maintenance_healthy` only reflects the maintenance thread's running state. It does not verify that the connection pool is functional.

## Fix

Added `pool_healthy` property to `Substrate` class that executes `SELECT 1` via the connection pool and returns `True`/`False`. Returns `False` if the instance has been closed.
