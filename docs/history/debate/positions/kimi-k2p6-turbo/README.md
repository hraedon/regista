# Positions — kimi-k2p6-turbo

Independent positions on substrate `debate/NNN-*.md` items, authored 2026-05-09 by kimi-k2p6-turbo.

## At-a-glance

| # | Item | Position | Urgency |
|---|---|---|---|
| 001 | Backend contract single-source-of-truth | **Measure first (hypothesis), contract only if data justifies** | Medium |
| 002 | Workflow composition | **Defer until measured — linting threshold now** | Low |
| 003 | Public API facade decomposition | **Immediate cutover, no deprecation window. Defer until after Plan 008.** | Medium |
| 004 | Trust model hardening | **Implement WS-1 + WS-5 now. Scope down WS-2. WS-3 needs CI-gated cross-validation.** | High |
| 005 | Operational runtime | **Option A (timer thread) only. Defer Option B. Add maintenance metrics + health indicator.** | Medium |

## Plans 007–009 — authored 2026-05-18

Positions on draft RFCs. No other reviewer positions exist yet for these plans.

| Plan | Core position | Sequencing |
|---|---|---|
| 007 (Facade decomposition) | Immediate cutover; no deprecation window. `transition()` and lifecycle stay top-level. | After Plan 008 |
| 008 (Trust hardening) | WS-1 + WS-5 first. Scope WS-2 down to env-var only. WS-3 cross-validation must be CI-gated. | First |
| 009 (Operational runtime) | Option A (timer thread) only. Defer standalone daemon. Add metrics + health indicator. | After Plan 007 |

**Recommended order: 008 → 007 → 009.**

## Consensus with other reviewers

On both substrate debates, kimi-k2p6-turbo converges with glm-5.1 and deepseek-v4-pro:
- **sub-001:** Property-based testing is the right first step. Defer declarative contract until hypothesis data justifies it.
- **sub-002:** Linting threshold is the right immediate step. Build `include` only when Phase 4 YAML exceeds the threshold.
