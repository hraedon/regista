---
number: "299"
title: "_validate_delegation_chain timestamp diverges from the persisted event timestamp"
severity: low
status: accepted
kind: defect
author: deepseek-v4-pro adversarial review
date: "2026-06-22"
tags: [delegation, plan-010, timestamps, validation]
related: ["197"]
---

## Problem

`_validate_delegation_chain` is called with `event_timestamp` near the top of
both transition implementations and the public `Regista.transition()` /
`InMemoryRegista.transition()` shims:

```python
_validate_delegation_chain(
    on_behalf_of, event_timestamp=datetime.now(UTC).isoformat()
)
```

This timestamp is read **before** the transaction and the event append. The
actual event timestamp is `datetime.now(UTC)` read inside the transaction
(`_events.py` append path), potentially seconds later. When `on_behalf_of`
carries `authenticated_at` and `expires_at`, the temporal bound check uses a
different clock reading than the one persisted on the event.

This is a **pre-existing Plan 010 issue** (BC-197), not introduced by Plan 021.
Plan 021's docstring says the chain is "validated by `_validate_delegation_chain`"
which is technically true but slightly misleading: the validation runs against
a pre-transaction timestamp, not the event's authoritative timestamp.

## Impact

In practice the divergence is sub-second and `authenticated_at` / `expires_at`
checks are coarse-grained (typically minute- or hour-granularity), so a
sub-second clock skew is unlikely to permit a meaningful attack. The risk is
that a chain valid at the validation moment could be invalid at the
event-persistence moment (or vice versa), producing a signed event whose chain
would not re-validate against the event's own timestamp.

## Resolution

Accepted as low. The clean fix would be to read the event timestamp first,
_then_ validate the delegation chain against it (rearranging the transition
sequence), or to re-validate post-append. Either changes Plan 010's sequencing
and is out of scope for the Plan 021 session. Worth picking up if a consumer
ever relies on tight `authenticated_at` bounds or reports a re-validation
mismatch.
