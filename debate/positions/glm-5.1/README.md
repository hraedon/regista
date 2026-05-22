# Positions — glm-5.1

Independent positions on `debate/NNN-*.md` items and draft RFC plans, authored by glm-5.1. Kept in this subfolder to avoid contaminating the original debate items before parallel review.

Each file `NNN.md` corresponds to the numbered debate or plan.

## At-a-glance

| # | Item | Position | Urgency |
|---|---|---|---|
| 001 | Backend contract single-source-of-truth | Property-based testing now; defer contract extraction | Medium (next significant feature) |
| 002 | Workflow composition | Defer; draft Phase 4 YAML first; implement include if >150 lines | Low |
| 003 | Public API facade decomposition (Plan 007) | Do it now. No deprecation window. Internal decomposition is already done. | Medium |
| 004 | Trust model hardening (Plan 008) | WS-5 + WS-1 immediately. WS-3 next. Scope WS-2 to env-var only. Defer WS-4. | High |
| 005 | Operational runtime (Plan 009) | Option A (timer thread) only. Subsume hook consumer. Add metrics + health indicator. Defer daemon. | Medium |
| 006 | SLA auto-transitions (Plan 006) | Defer entirely. Let recurrence prove the timer pattern first. Build nothing until consumers have tried option (b). | Low |

## Plans 007–009 — authored 2026-05-19

Positions on draft RFCs, informed by the current codebase state (_contract.py, hypothesis tests, and workflow composition already implemented).

| Plan | Core position | Sequencing |
|---|---|---|
| 007 (Facade decomposition) | Immediate cutover; no deprecation. `transition()` and lifecycle stay top-level. 1-session job — internal modules already exist. | Before Plan 008 |
| 008 (Trust hardening) | WS-5 → WS-1 → WS-3 → scoped WS-2 (env-var only) → WS-4 (deferred). Drop mlock/zeroization. | After Plan 007 |
| 009 (Operational runtime) | Option A only. Subsume hook consumer. Add metrics + health indicator. Defer standalone daemon indefinitely. | After Plan 007 |

**Recommended order: 007 → 008 → 009.**

## Plan 006 — authored 2026-05-19

Plan 006 is a design exploration, not an implementation plan. My position is to defer entirely. The analysis is excellent; the implementation is premature. Let Plan 003 (recurrence) prove the timer-driven pattern first, and let at least two consumers build option (b) before generalizing.

## Act-now / build-small / defer

- **Act now:** 004 (WS-5 key rotation safety — 3-line fix)
- **Build small (next session):** 003 (facade decomposition — internal modules already exist), 004 (WS-1 strict roles — pure `_contract.py`)
- **Build soon:** 004 (WS-3 vendor rfc8785), 005 (maintenance thread)
- **Defer with measurement:** 001 (contract extraction — hypothesis tests running, wait for data), 002 (already implemented as `extends:`), 006 (SLA — no consumer has tried option (b) yet)

## Consensus with other reviewers

On original debates 001 and 002, glm-5.1 converges with kimi-k2p6-turbo:
- **sub-001:** Property-based testing was the right first step. It's now implemented. The contract extraction question should be data-driven.
- **sub-002:** Linting thresholds were the right immediate step. `extends:` has since been implemented (FR-29), largely resolving this debate.

On plans 007-009, divergence from kimi-k2p6-turbo on sequencing:
- **kimi-k2p6-turbo:** 008 → 007 → 009
- **glm-5.1:** 007 → 008 → 009
- **Key disagreement:** Whether facade decomposition should precede or follow trust hardening. glm-5.1 argues that policy hooks are easier to attach to clean facades than to a flat God class.
