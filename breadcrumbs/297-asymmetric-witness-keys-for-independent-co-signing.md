---
number: "297"
title: "witness co-signing uses HMAC — no asymmetric witness keys, so witnessing is not independently verifiable"
severity: medium
status: proposed
kind: design
author: adversarial-review
date: "2026-06-01"
tags: [witness, signing, ed25519, audit]
related: []
---

## Problem

Witness co-signing (Plan 013) creates witness receipts using HMAC-SHA256, the
same symmetric scheme as the primary signer. For a witness to add *independent*
assurance it must hold its own key material that the auditee does not control,
and an auditor must be able to verify the witness signature without that
secret. With HMAC, whoever can verify can also forge — so a witness receipt
proves nothing an operator who holds the (shared) secret could not have minted
themselves.

This blocks **cairn BC-016**: cairn's verifier counts witness coverage but
cannot cryptographically verify witness signatures, precisely because regista
witnesses are HMAC-based. cairn cannot store and check witness public keys that
do not exist.

## Suggested fix

Give witnesses asymmetric keys (Ed25519, reusing the `SigningScheme` protocol
from Plan 011): witnesses sign receipts with a private key; registration stores
the witness *public* key; verification checks the receipt signature against the
registered public key with no secret required. Then cairn BC-016 can store
witness pubkeys and verify `witness_signature` before counting coverage.

## Provenance

Raised during the cairn verify-path hardening (cairn BC-016 is filed in
agent-provenance and is blocked on this). See cairn BC-016.
