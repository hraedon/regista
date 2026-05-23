---
number: "221"
title: "No checkpoint / log compaction primitive; append-only logs grow forever"
severity: medium
status: implemented
kind: design
author: external-review-r3
date: "2026-05-23"
tags: [retention, compliance, gdpr, log-compaction]
related: ["198"]
---

## Resolution

Added `"checkpoint"` to `_RESERVED_TRANSITIONS` in `_contract.py`. `check_reserved_transition` and `check_append_blocked` now reject manual use of the transition name. `DelegationChain` dataclass updated to include `expires_at` and `session_grant_event_id` fields. Payload shape is documented as reserved-for-v2; no runtime Merkle implementation landed. 24 new tests pass (845 total).

# BC-221 — No checkpoint / log compaction primitive

## Problem

Substrate's event log is append-only by design. Verifier tools
(agent-provenance and any future consumer) reconstruct state by
replaying events from genesis. This is correct for integrity but has
two collisions with real-world requirements:

1. **Retention boundaries.** SOX requires 7-year retention; HIPAA has
   its own retention rules; internal IT policy may demand log
   destruction after a defined period. There is currently no
   mechanism to truncate the log without breaking signature chains
   and verifier replay.
2. **GDPR Article 17 (right to erasure).** Personal data captured in
   tool arguments, file paths, or event payloads is subject to
   erasure requests. The signed envelope makes such cleartext
   immutable. There is no design hook for erasable fields.

Round-3 reviewers (Kimi, Gemini, Deepseek, Qwen) raised these as
distinct but related concerns. The unifying primitive is a *signed
checkpoint*: a periodic event that carries a Merkle root over a
window of prior events, anchored externally (RFC 3161), such that
subsequent verifiers can trust the checkpoint and truncate everything
before it without losing verification continuity.

## Proposed fix

Reserve a `checkpoint` event transition with the following payload
shape:

```json
{
  "transition": "checkpoint",
  "actor_id": "<operator>",
  "payload": {
    "checkpoint_id": "<uuid>",
    "covers_event_seq_from": 1000,
    "covers_event_seq_to": 5000,
    "merkle_root": "sha256:...",
    "previous_checkpoint_id": "<uuid|null>",
    "tsa_token": "<base64 RFC 3161 token>",
    "checkpoint_at": "2026-05-23T00:00:00Z"
  }
}
```

A verifier consuming a log can:

- Verify the latest checkpoint's signature and TSA token.
- Trust the Merkle root as the state of the log up to that point.
- Skip replay of events before the checkpoint (they may have been
  truncated).
- Replay only events after the most recent checkpoint.

Erasure under GDPR works as redaction-by-hash (agent-provenance
schema): the personal-data field's hash is in the signed envelope,
the cleartext lives in a separately-erasable store. Erasing the
cleartext does not break the signature; the verifier marks the field
`[REDACTED]` in its report. This is a consumer-layer pattern, not a
substrate primitive, but it composes with the checkpoint mechanism
(checkpoints don't require cleartext fields to remain).

For v1: reserve the `checkpoint` transition name. Document the
intended semantics. Implementation of the truncation/archival flow is
v2+.

## Dependencies

- **Depends on BC-198 Layer 1** for the TSA token in the checkpoint.
  Layer 1 is implementable today against HMAC, so this can move in
  parallel.
- **Independent of BC-196.** Checkpoints work under HMAC (with the
  caveat that an operator with the HMAC secret can forge
  checkpoints too — but this is the same threat as any HMAC-signed
  event).
- **Composes with GDPR redaction-by-hash** in agent-provenance.
  Substrate provides the integrity primitive; agent-provenance
  provides the erasure pattern.

## Timing

Schema reservation (transition name + payload shape) can land now.
Full implementation is v2.
