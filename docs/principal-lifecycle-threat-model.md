# Principal lifecycle contract threat model

This document scopes the public contract foundation in
`regista.principal_lifecycle`. It is not a claim that durable lifecycle commit,
custody isolation, approval policy, or multi-project reconciliation is complete.

## Trust boundaries

Regista accepts an authenticated consumer's stable principal and actor IDs; it
does not infer authorization from display names or email addresses. A custody
provider or Windows helper owns private material. Regista receives a public key
and verifies a signature over an operation-bound challenge. The database and
registry commit path are outside this foundation and remain the authority for
key state.

The current challenge store is explicitly process-local. Restarting loses all
issued challenges, causing submitted proofs to fail closed as unknown. It does
not make replay prevention durable across workers and therefore exposes no
commit operation. Durable, transactional challenge consumption is required
before a web or multi-worker deployment may rely on it to authorize mutation.

## Threats and required controls

| Threat | Foundation control | Remaining v1 work |
|---|---|---|
| Compromised dossier | No private key parameter or response; exact operation digest | Step-up evidence, least-privilege commit API, external audit |
| Compromised Windows helper | Proof binds key, principal, project, operation, digest, and nonce | Helper signing and attestation policy; client-effective receipt |
| Malicious administrator | Actor, authority, reason, policy, and protected options are digested | Typed approval evidence and genuine dual control |
| Malicious DBA | No database mutation in this phase | Signed lifecycle events, external witness, atomic commit locks |
| Provider administrator | Custody mode is explicit and covered by the digest | Provider audit receipt and provider-specific assurance statement |
| Proof replay | Random, short-lived, one-use process-local challenge | Durable one-use storage shared by every verifier worker |
| Proof substitution | Challenge binds operation ID/digest, project, principal, fingerprint, and scheme | State-machine and concurrency qualification around commit |
| Stale approval | Creation and expiry are covered by the digest | Typed approval expiry and optimistic expected digest/state |
| Weak identity binding | Optional immutable binding digest is covered by the digest | Consumer authentication policy and mandatory binding for humans |
| Duplicate active key | Preparation does not mutate registry | Existing unique active-key constraint plus atomic lifecycle commit |
| Cross-project confusion | Project is constructor-bound and included in digest and challenge | Multi-project coordinator with one receipt per project |
| Partial fan-out | Single-project contract makes no distributed-transaction claim | Deterministic retry and roll-forward coordinator |
| Key loss/backend outage | No custody call occurs during preparation or proof verification | Named provider health, recovery, and unsupported results |
| Rollback | No simulated commit or rollback exists | Append-only evidence and forward repair |
| False non-repudiation | Contract proves control of a key only | Reports must state custody and authorization assurance actually evidenced |

## Security invariants

- Unknown lifecycle enum values and signing schemes fail closed.
- Only registered asymmetric schemes can satisfy possession.
- Canonical RFC 8785 bytes and a versioned domain separator are signed.
- A successful proof advances only ephemeral operation state; it never changes
  the registry.
- Invalid proofs do not consume a challenge, while successful proofs do.
- No method accepts private, wrapped, provider-authentication, or bearer-secret
  material.
- Registry commit remains unavailable until durable operation and challenge
  state, approval validation, idempotency, and atomic evidence are implemented.
