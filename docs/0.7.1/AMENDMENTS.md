# Regista 0.7.1 Contract Amendments

**Status:** Normative for regista 0.7.1. All other 0.7.0 and earlier v6 rules
remain in force.

## 1. Principal-lifecycle authority

Durable principal enrollment, rotation, and revocation are admitted only with
an operator-pinned trust-genesis document. The prepared operation records the
exact authority binding used for its digest:

- enrollment and revocation require a live, scoped, unexpired `registrar`
  delegation;
- routine rotation requires that delegation plus a detached signature from the
  superseded key over the canonical rotation authorization bytes;
- recovery rotation requires current root-threshold detached signatures and
  uses `root` authority rather than registrar authority.

The trust-log append and the rebuildable `principal_keys` projection are applied
in one database transaction. The append path re-resolves the authority under
the chain-head lock, so delegation revocation, expiry, scope changes, key
changes, and exhausted operation limits fail closed between prepare and commit.

## 2. Canonical genesis configuration

`REGISTA_TRUST_GENESIS_PATH` is the only supported environment variable for the
operator-pinned trust-genesis document.

## 3. Durable schema

Migration 050 adds durable authority binding, deterministic replacement-key
identity, root signatures, and superseded-key signatures to lifecycle
operations. Historical rows without an authority binding are never upgraded by
inference and cannot commit through the 0.7.1 durable lifecycle path.

## 4. Public offline verification surface

`regista.verification` (re-exported from the package root) is the stable,
narrow surface for embedding consumers that verify stored events offline.
Three callables and the types needed to consume their results:

- `bundle_referents(manifest, events, action_delegation_credentials=None)` —
  presents a bundle's manifest and events as the referent material a v6
  verdict resolves key-binding anchors, workflow registrations, and epoch
  position against. The completeness claim (`complete-store` vs
  `contiguous-range`) is derived from the manifest's `since_seq`/`until_seq`,
  never asserted by the caller.
- `chain_head_hash(canonical_envelope, signature)` — the version-aware
  hash-chain link an event contributes: the domain-separated, length-framed
  v6 formula for v6 envelopes, the legacy SHA-256 concatenation for v1-v5.
- `verify_event_with_referents(event, key_material, *, referents, scheme_id=None)`
  — the structured `VerificationResult` for one stored event under
  caller-supplied key material and caller-presented referents. `referents` is
  a required keyword: a call site that cannot say what material it is
  presenting cannot get a v6 verdict, and the honest spelling of "one row, no
  chain" is `NO_REFERENTS` by name.

The consumer honesty contract, normative for anything built on this surface:

- `Applicability.INVALID` is a proven defect of the artifact — a signature that
  does not verify, or a row rewritten under an intact signature (WI-267).
- `Applicability.UNVERIFIABLE` is an evidentiary gap, most commonly a v6 event
  whose referents the presented material does not contain, or the v6 genesis
  event itself, whose authority is the external trust-domain enrolment rather
  than anything a bundle can carry. Not proven is not proven false; the two
  must not be collapsed in either direction.

This is an addition, not a amendment of 0.7.0 behaviour: the private
primitives are unchanged, and the wrapper is the same call graph rather than a
second verifier.

## 5. Public online trust-log verification

`Regista.verify_trust_log()` is the narrow read-only online seam for consumers
that need to check the configured estate trust log. It runs the same
authority-checked chain walk used by lifecycle writes, inside a read-only
transaction, and returns a `TrustLogVerificationReport` containing the exact
count of every stored row visited by the verified chain walk (genesis,
governance/delegation, and lifecycle rows), the trust-domain id, and the genesis
event hash. A missing pinned genesis
or any chain failure raises a typed `RegistaError`; an unpinned or unavailable
log is never reported as verified.
