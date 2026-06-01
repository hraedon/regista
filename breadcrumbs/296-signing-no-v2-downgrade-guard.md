---
number: "296"
title: "verify_event accepts downgraded v2 envelopes for v3-chained events (no downgrade guard)"
severity: medium
status: proposed
kind: bug
author: adversarial-review
date: "2026-06-01"
tags: [signing, hash-chain, downgrade]
related: []
---

## Problem

`verify_event` (`src/regista/_signing.py:253-296`) accepts v3, v2, v1, and bare
envelopes interchangeably. An event that was originally minted as a v3 chained
envelope (carrying `prev_event_hash` / `global_seq`) can be re-presented as a
v2 envelope that drops the chain field, and the signature still verifies,
because the verifier does not require the envelope version to match the event's
chaining status.

This is the regista-side complement to the cairn-side fix for **cairn BC-010**:
cairn's verifier now *refuses* a v3-chained event presented without its
`prev_event_hash` (`agent-provenance/src/cairn/verifier.py::_check_chain_contiguity`,
`kind="v2_downgrade"`). But regista itself — the library every other consumer
verifies through — still validates the downgraded envelope as authentic. Any
consumer that is not cairn (or a future cairn that trusts regista's verdict)
remains exposed to chain-field stripping.

## Suggested fix

In `verify_event` (or the envelope-version dispatch), once an event's stored
record indicates v3 chaining (`global_seq IS NOT NULL` and/or
`prev_event_hash` present for `event_seq > 1`), refuse to verify a v2/v1/bare
envelope for it — stop minting and stop accepting downgraded envelopes for
chained events. Add a test that a v3 event re-encoded as v2 fails verification.

## Provenance

Raised during the cairn BC-010 fix (the fixing agent explicitly flagged this as
the out-of-scope regista-side follow-up). See cairn BC-010 resolution note.
