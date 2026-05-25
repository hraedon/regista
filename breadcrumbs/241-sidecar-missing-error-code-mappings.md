---
number: "241"
title: Sidecar missing error code mappings for witness and other error codes
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [sidecar, error-handling]
related: []
---

## Problem

The sidecar `error_to_status` mapping was missing `WITNESS_NOT_FOUND` (should map to 404), `WITNESS_DELIVERY_FAILED` (500), `WITNESS_PAUSED` (409), and several other error codes that were added in recent plans. These would default to 500 instead of the correct HTTP status. Also, `INVALID_CUSTOM_FIELD_VALUE` was in the mapping but doesn't exist in the ErrorCode enum.

Additionally, `_parse_uuid` and `_parse_datetime` in routes.py could raise `ValueError` on bad input, resulting in unhandled 500s instead of proper 400 responses. The `witness_receipts` `limit` parameter had no validation (could crash on non-integer input or be used for unbounded queries).

## Fix

- Added missing error codes to sidecar error mapping.
- Removed phantom `INVALID_CUSTOM_FIELD_VALUE`.
- Added `ValueError` handling in `_parse_uuid` and `_parse_datetime` returning 400.
- Added bounds validation for `limit` query param (1–10000).