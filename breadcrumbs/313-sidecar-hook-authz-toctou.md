---
number: "313"
title: "Sidecar hook authorization TOCTOU — workflow check and complete/fail run in separate transactions"
severity: medium
status: proposed
kind: bug
author: adversarial-review (BC-235 GLM review)
date: "2026-06-26"
tags: [sidecar, hooks, auth, toctou]
related: ["235"]
---

## Problem

`_authorize_hook_workflow_access()` in `routes_hooks.py` reads the hook's
`work_item_id` and looks up its workflow in a separate transaction from
`complete_hook`/`fail_hook`. Between the authorization check and the actual
operation:

1. The hook's lease could expire
2. `sweep_expired_hook_leases` could requeue it
3. Another consumer could claim and process it
4. The original consumer's complete/fail then affects the wrong hook

This is partly pre-existing (the hook lifecycle never checked ownership), but
the new scoping code (BC-235) adds another read-before-write window.

## Fix

Add an ownership/actor check inside `complete_hook` and `fail_hook` themselves
(not just in the sidecar route). The hook's `claimed_by` actor should match the
caller's `actor_id`. Alternatively, pass the actor_id through and enforce it at
the core API level.
