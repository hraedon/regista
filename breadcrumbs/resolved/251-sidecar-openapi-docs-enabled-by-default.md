---
number: "251"
title: Sidecar OpenAPI docs and docs URL enabled by default — unauthenticated information leakage
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [sidecar, security, info-leak]
related: []
---

## Problem

`create_app()` defaulted to `docs_url="/docs"` and `openapi_url="/openapi.json"`, exposing the full API schema to unauthenticated users. An attacker could enumerate all endpoints, request/response models, field names, and error codes without authentication.

## Fix

Changed defaults to `docs_url=None, openapi_url=None`. Operators who want docs must explicitly opt in via `create_app(..., docs_url="/docs")` or the `SUBSTRATE_DISABLE_DOCS` env var (inverted logic: now docs are disabled by default, set to enable).
