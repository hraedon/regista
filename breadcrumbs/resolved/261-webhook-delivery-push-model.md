---
number: "261"
title: Webhook delivery for events (push model)
severity: medium
status: resolved
kind: improvement
author: adversarial-review
date: "2026-05-26"
tags: [hooks, integration, webhooks]
related: []
---

## Problem

The hook system requires a consumer thread or out-of-process polling. Simple integrations need push-model delivery.

## Fix

New `_webhooks.py` module with `register_webhook`, `list_webhooks`, `unregister_webhook`, `pause_webhook`, `resume_webhook`, `deliver_webhooks`. Migration 024 creates `webhook_registrations` table. Webhooks filter by transitions, work_item_types, and workflows. HTTP POST delivery with 10s timeout. `WebhookOps` facade on `Substrate`. Sidecar: `POST /v1/webhooks`, `GET /v1/webhooks`, `DELETE /v1/webhooks/{id}`, `POST /v1/webhooks/{id}/pause`, `POST /v1/webhooks/{id}/resume`. CLI: `substrate webhook register/list/remove`.
