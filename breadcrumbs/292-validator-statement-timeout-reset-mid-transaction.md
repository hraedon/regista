---
number: "292"
title: "validator statement_timeout reset to 0 mid-transaction; no real wall-clock bound on validators"
severity: medium
status: proposed
kind: bug
author: adversarial-review
date: "2026-05-31"
tags: [validators, transactions, fr-13]
related: ["192"]
---

## Problem

In `transition()` (`src/regista/_transition.py:145-159`) the sync validator is
bounded by `SET LOCAL statement_timeout = '5s'`, then on success the code
immediately runs `SET LOCAL statement_timeout = 0`, **re-disabling the timeout
for the rest of the same transaction** — the event INSERT, projection UPDATE,
claim DELETE, and hook enqueue, all while holding `FOR UPDATE` on the
work-item row (`work_items_current ... FOR UPDATE`, line 67-72).

Two issues:

1. `statement_timeout` bounds a single SQL statement, not the validator as a
   whole. A validator doing slow Python, sleeps, or multiple quick queries is
   never actually bounded. `run_validator` (`src/regista/_hooks.py:22-57`) and
   the BC-192 comment (`_transition.py:153-157`) both concede there is "no
   Python-side wall-clock bound." So the advertised protection against a hung
   validator only covers one blocking SQL statement.

2. Resetting to `0` means the remainder of the transaction runs with no
   statement timeout while holding the row lock, so a slow or contended write
   can pin the work-item lock indefinitely and block all other mutations on
   that item (queue head-of-line stall).

## Suggested fix

Set a non-zero `statement_timeout` once at transaction start and leave it in
force for the whole transaction (don't reset to 0 mid-tx). If a true validator
wall-clock bound is desired, enforce it in Python (run handler in a thread and
join with timeout), not via `statement_timeout`.
