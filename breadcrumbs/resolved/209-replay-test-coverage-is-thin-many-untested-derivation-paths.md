---
number: "209"
title: Replay test coverage is thin — 3 tests, many untested derivation paths
severity: high
status: in_progress
kind: bug
author: substrate-agent
date: "2026-05-22"
tags: [replay, testing, coverage]
related: ["210", "189", "146", "003", "002"]
---

**Problem**
`tests/test_replay.py` contains only 3 tests:
1. `TestAC17RevokedKeyHaltsReplay` — 1 test checking halted count
2. `TestAC29OutOfBandEditDrift` — 2 tests for drift detection (direct state/cf update)

Many derivation paths in `_replay.py` / `_replay_work_item` are completely untested:
- `claim_acquired`, `claim_stolen`, `claim_released`, `claim_expired`, `claim_heartbeat` event replay
- `link_created`, `link_removed` event replay
- `escalated` event replay
- `not_before_set` event replay
- `custom_fields_update` on transition replay
- Orphan events with a `created` event (warning path)
- Orphan events without a `created` event (halted path)
- `continue_on_revoked=True` with unknown key (skip + warning)
- Signature verification failure (halted)
- Missing workflow during replay (halted)
- Transition exists but invalid from current state (halted)
- `_states_match` and `_diff_fields` for all fields
- InMemory replay parity (InMemorySubstrate.replay())

**Impact**
Silent regressions in replay accuracy (the spec's core guarantee that projection is derivable from events) will not be caught by CI.

**Resolution Criteria**
- [ ] Comprehensive Postgres replay tests: claims, links, escalation, custom_field_update, not_before_set
- [ ] Orphan event tests (with and without created event)
- [ ] Signature/key failure tests
- [ ] InMemory replay parity tests
- [ ] All new tests pass alongside existing suite
