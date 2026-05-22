---
number: "205"
title: "No input validation on actor_id, role, actor_metadata"
severity: medium
status: proposed
kind: bug
author: adversarial-review
date: "2026-05-22"
tags: [validation, input, actor, role]
related: ["177", "181"]
---

# BC-205 — No input validation on actor_id, role, actor_metadata

## Problem

Multiple input validation gaps at the API boundary:

1. `actor_id` (`_contract.py:486-492`): Only checks max length (255). Empty strings, whitespace-only, control characters, and SQL-special characters are all accepted. Empty actor_ids corrupt audit trails and log readability.

2. `role` (`__init__.py:1060-1105`): No length check, no character validation, no empty-string check. Passed directly to `_actor_roles.py` for database insertion.

3. `actor_metadata` (throughout): Accepted as an opaque dict with no schema enforcement. Consumers pack arbitrary fields. No size limit on the dict.

4. `transition_name` and `workflow_name`: Validated against regex in `_contract.py` but the regex is permissive (allows most printable characters).

## Proposed fix

- `actor_id`: Reject empty/whitespace-only strings, enforce printable character set
- `role`: Add max length (255), reject empty strings
- `actor_metadata`: Add max size limit (e.g., 64KB serialized)
- Consider a shared `_validate_identifier(name, max_len=255)` helper
