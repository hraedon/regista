---
number: "268"
title: "Webhook delivery has no retry or dead-letter mechanism"
severity: medium
status: implemented
kind: improvement
author: reflection
date: "2026-05-26"
tags: [webhooks, reliability]
related: ["261"]
---

## Problem

Webhook delivery in `_webhooks.py` makes a single synchronous HTTP POST. If it fails (timeout, 5xx, connection error), the event is logged as a warning and lost. Unlike the hook system (which has retry with exponential backoff, dead-letter queue, and requeue), webhooks have no reliability mechanism.

## Resolution

Added failure tracking with auto-pause. The `webhook_registrations` table gains `failure_count` and `max_failures` columns. On delivery failure, `failure_count` increments; when it reaches `max_failures` (default 10), the webhook is auto-paused. On successful delivery, `failure_count` resets to 0. Full retry with dead-letter is deferred — webhooks are a simpler push model than the witness system.
