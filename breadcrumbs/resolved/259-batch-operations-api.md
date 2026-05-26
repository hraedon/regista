---
number: "259"
title: Batch operations API for work items and transitions
severity: medium
status: resolved
kind: improvement
author: adversarial-review
date: "2026-05-26"
tags: [api, performance, batching]
related: []
---

## Problem

Agent pipelines often fan out dozens of work items atomically. The current API requires N round-trips.

## Fix

Added `create_work_items_batch(items, actor_id, actor_kind)` to `WorkItemOps` and `Substrate` class. Executes all creates in a single transaction. Returns list of `(WorkItem, Event)` tuples. Sidecar: `POST /v1/create_work_items_batch`.
