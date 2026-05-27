---
number: "274"
title: "Webhook delivery uses WITNESS_NOT_FOUND error code — wrong domain"
severity: low
status: resolved
kind: bug
author: design-review
date: "2026-05-26"
tags: [webhooks, error-codes]
related: ["269"]
---

## Problem

`_webhooks.py:117` raises `ErrorCode.WITNESS_NOT_FOUND` when a webhook registration is not found. Copy-paste from witness code. The error code leaks the wrong domain.

## Fix

Will be resolved as part of webhook→witness unification (shared ENDPOINT_NOT_FOUND or unified under witness codes).
