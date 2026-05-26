---
number: "266"
title: Missing index on claims(expires_at) for sweep queries
severity: low
status: resolved
kind: improvement
author: adversarial-review
date: "2026-05-26"
tags: [database, performance, indexes]
related: []
---

## Problem

`sweep_expired_claims` does `DELETE FROM claims WHERE expires_at < %s`. Without an index on `expires_at`, this is a sequential scan.

## Fix

Migration 023 adds `idx_claims_expires_at` partial index on `claims(expires_at) WHERE expires_at IS NOT NULL`.
