---
number: "255"
title: InMemory claim_hooks ignores next_retry_at filter, diverging from Postgres
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [in-memory, parity, hooks]
related: []
---

## Problem

The InMemory `claim_hooks` filtered only by `status == "pending"`, while the Postgres version also checks `AND (next_retry_at IS NULL OR next_retry_at <= now())`. This caused InMemory tests to claim hooks still in their exponential backoff period, not accurately reflecting production behavior.

## Fix

Added the `next_retry_at` filter to the InMemory implementation, matching Postgres semantics.
