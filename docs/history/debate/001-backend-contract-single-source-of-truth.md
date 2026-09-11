---
number: "001"
title: "Backend contract single-source-of-truth — eliminate hand-maintained InMemorySubstrate parity"
author: opencode
date: "2026-05-09"
related: ["RFC-062", "BC-063", "BC-054", "BC-050"]
---

## Context

Substrate maintains two full backend implementations — Postgres (`__init__.py` + SQL migrations) and `InMemorySubstrate` (`_in_memory.py`) — that must behave identically on every API surface. This is not a lightweight test double; it is a parallel backend maintained by hand.

The v2 factory has been bitten by InMemory/Postgres divergence twice in golden runs (BC-063). Substrate itself has resolved ten InMemorySubstrate parity bugs across recent sessions (BC-045 through BC-058). The pattern is consistent: **hand-maintained dual backends drift, and the drift is discovered in production, not in unit tests.**

## Problem

The invariant we want is simple: *for every sequence of valid API calls, both backends produce identical state.* The current conformance tests only catch what the test author thought to assert. They miss:
- Concurrent interleavings (dict-based locking vs `SELECT FOR UPDATE`)
- Timestamp edge cases (Postgres `now()` vs Python `datetime.now(UTC)`)
- Hook retry timing and back-off semantics
- Claim TTL expiry and auto-steal race conditions
- Event ordering under load

## Position

**Adopt a declarative backend contract (Option B from RFC-062) with property-based testing as an immediate stopgap.**

### Why Option B over Option C

Option C (generate InMemory from Postgres SQL) is the most fundamental fix, but it requires building a SQL → Python code generator. That generator becomes its own complex subsystem that the principal cannot evaluate without reading generated code.

Option B extracts all state-transition logic into a single human-readable contract file (YAML or Python dataclasses). Both backends interpret the same contract. The contract is the thing the principal reviews and approves. It is the systems-architecture equivalent of a firewall ruleset or routing policy.

### What the contract describes

- **States and invariants:** What must be true for a work-item to be in state X
- **Transitions:** Preconditions, mutations, postconditions
- **Claim lifecycle:** TTL semantics, auto-steal rules, heartbeat rules
- **Hook lifecycle:** Retry count, dead-letter conditions, back-off strategy
- **Event append rules:** Idempotency, gap-free seq allocation, signing envelope

The Postgres backend maps contract rules to SQL templates. The InMemory backend maps contract rules to Python dict manipulation.

### Immediate stopgap: property-based testing

While the contract is being built, add a property-based test suite that generates random valid API call sequences and asserts state equivalence between backends.
- Tool: `hypothesis` or custom sequence generator
- Random walk through `create → claim → transition → release → sweep → replay`
- Compare final `WorkItem`, `Event` stream, `Claim` state, and `ReplayReport`
- Run nightly and on every PR

This does not prevent drift but reduces detection latency from "golden run failure" to "CI failure within hours."

### Acceptance criteria (principal-verifiable)

1. A human adding a new transition rule edits **exactly one file** (the contract).
2. The contract file is readable without Python expertise.
3. A nightly CI job runs property-based conformance testing and reports divergence within 24 hours.
4. No future InMemorySubstrate parity bug is resolved by hand-editing both backends.

## Risks

| Risk | Mitigation |
|---|---|
| Contract language is not expressive enough for SQL locking semantics | Start with 80% of rules that are backend-agnostic; hand-write the remaining 20% with contract comments |
| Existing _in_memory.py is 1,493 lines; migration is large | Grandfather existing implementation; migrate incrementally; new features use contract first |
| Contract itself becomes a source of bugs | Validate contract independently (static analysis, type checking) before either backend consumes it |

## Blocking

Not tied to a numbered phase. This is cross-cutting infrastructure. However, it should be completed or well underway before substrate adds major new features (e.g., multi-project links, advanced hook semantics, workflow composition) that would multiply the drift surface.

## Next step

1. Accept RFC-062
2. Create `src/substrate/_contract.py` with dataclass-based contract definitions
3. Extract 5 core transition rules into the contract as a pilot
4. Add `hypothesis`-based conformance test to CI
5. Run nightly for 2 weeks; measure divergence detection rate
6. Expand contract coverage incrementally
