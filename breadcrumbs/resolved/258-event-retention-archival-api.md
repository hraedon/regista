---
number: "258"
title: Event retention / archival API
severity: medium
status: resolved
kind: improvement
author: adversarial-review
date: "2026-05-26"
tags: [events, operations, storage]
related: []
---

## Problem

The `events` table is append-only with no retention policy. It will grow indefinitely.

## Fix

Added `archive_events(before_timestamp, dry_run=False)` to `Substrate` class and `ArchiveOps` facade. Migration 024 creates `events_archive` table (same schema as `events`). The method moves events older than the timestamp to the archive table in a single transaction. Dry-run mode returns the count without moving rows. CLI: `substrate events archive --before <ts> [--dry-run]`. Sidecar: `POST /v1/archive_events`.
