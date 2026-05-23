---
number: "218"
title: "KeyEntry has no role/capability field; auditor keys can sign action events"
severity: medium
status: implemented
kind: design
author: external-review-r3
date: "2026-05-23"
tags: [keys, identity, auditor, role-gate]
related: ["215", "216", "217"]
---

# BC-218 — KeyEntry has no role/capability field

## Problem

In the agent-provenance use case, three role classes of keys exist:

- **Actor keys** — sign `tool_call`, state transition, and other
  operational events.
- **Auditor keys** — sign `auditor_attestation` events (verdicts on
  reviewed log segments).
- **Recovery keys** — sign `key_rotation` events when the primary key
  is lost.

`_keys.py:KeyEntry` at line 17-20 has no field to express this. An
auditor's key, if it exists in the same `KeySet`, can sign any event
type — including forged `tool_call` events. A compromised auditor key
becomes equivalent to a compromised actor key, despite having a
different threat profile (auditor compromise can whitewash forged
actions, which is worse than actor compromise).

Round 3 unanimously (6/6 reviewers) endorsed adding a `role` /
`capability` field on `KeyEntry` as the middle path between "auditors
are just identities" (round-1 consensus) and "separate keyring for
auditors" (Kimi/GLM round-2 dissent).

## Proposed fix

Add `role: str = "actor"` to `KeyEntry`:

```python
@dataclass(frozen=True)
class KeyEntry:
    key_id: str
    secret: bytes
    status: str
    role: str = "actor"   # "actor" | "auditor" | "recovery"
    # plus other fields from BC-215, BC-216, BC-217
```

Add `validate_key_role()` to `_contract.py`:

```python
def validate_key_role(role: str) -> None:
    if role not in {"actor", "auditor", "recovery"}:
        raise SubstrateError(
            ErrorCode.INVALID_KEY_ROLE,
            f"unknown key role: {role}",
        )
```

Add policy enforcement at signing or verification time. The simplest
form is a sign-time check: `sign_event()` accepts an optional
`expected_role` parameter that gates which transitions a key can
sign. Verifier-side enforcement is the durable check (the verifier
walks the log and rejects role violations).

Policy table:

| Transition | Allowed roles |
|---|---|
| `tool_call`, workflow transitions | `actor` |
| `auditor_attestation` | `auditor` |
| `key_rotation` | `actor` (rotating their own key) or `recovery` |
| `scope_attestation`, `key_declaration` | `actor` (operator) |
| `session_grant`, `session_revocation` | `actor` (human identity) |

The `role` field is a one-line schema addition. Enforcement is ~20
lines in `_contract.py` and the verifier tool.

## Dependencies

- **Couples with BC-216.** Both modify `KeyEntry`; should land
  together.
- **Independent of BC-196.** The role gate works under HMAC; it's a
  policy check, not a cryptographic primitive. Under Ed25519 it
  remains a policy check, just with strong key separation.
- **Composes with `ActorRole` at `_types.py:651`.** Existing
  `ActorRole` is workflow-scoped role assignment. `KeyEntry.role` is
  key-scoped signing capability. Different layers, both can coexist.

## Timing

Small additive change. Can land independently of BC-196.
