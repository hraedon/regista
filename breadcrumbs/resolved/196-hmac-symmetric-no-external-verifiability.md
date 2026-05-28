---
number: "196"
title: HMAC signing is symmetric — no external/adversarial verifiability
severity: medium
status: accepted
kind: design
author: claude
date: "2026-05-22"
tags: [trust-model, signing, audit, asymmetric, transparency-log]
related: ["100", "101", "172", "174"]
---

## Failure mode

Substrate signs every event with HMAC-SHA256 over an RFC 8785 canonical-JSON
payload (FR-15). HMAC is symmetric: the same key that signs also verifies. This
means an auditor verifying the event log must hold a copy of the signing key,
which in turn means the operating organization can sign anything it wants and
the auditor cannot distinguish a genuine historical event from one fabricated
five minutes ago and inserted with a backdated `timestamp`.

This is acceptable for the homelab/single-operator threat model documented in
spec §17.9 and Plan 008, where the auditor *is* the operator. It is not
acceptable for the use cases substrate is starting to be considered for:

1. **External regulatory audit** (HIPAA, SOC 2, HITRUST, FedRAMP). Auditors are
   adversarial to the auditee by design — "trust the auditee's HMAC key" is
   not a posture they can accept. compliance-substrate's pitch (tamper-evident
   audit trail) is materially weakened by this gap.
2. **Agent-action provenance for regulated buyers.** If substrate is repositioned
   as a cryptographic audit layer for agentic workflows (the conversation that
   produced this BC), the buyer's question "can you prove *you* didn't edit
   it" has no good answer under symmetric signing.
3. **Multi-party workflows with non-aligned principals.** Two organizations
   sharing a workflow (e.g., vendor + customer co-attestation) cannot today
   produce a log that either party can verify without trusting the other's
   custody of the shared key.

Related but distinct gaps already on file:

- BC-100: key material in plaintext memory — orthogonal; affects both symmetric
  and asymmetric schemes.
- BC-101: `actor_metadata.role` is self-attested — orthogonal; about *who*
  signed, not whether the signature is externally verifiable.
- BC-172: rfc8785 SPOF — canonicalization correctness; relevant to any signing
  scheme.
- BC-174: unknown key status silently skipped — key registry hygiene;
  orthogonal.

The "multiple signers / impersonation" gap discussed alongside this one is
separately tracked (or should be — file as a sibling BC if not yet present).
That gap is about *who is allowed to sign as whom*; this one is about *who can
verify a signature without trusting the signer's key custody*.

## Evidence

- `src/substrate/_signing.py` (or equivalent): HMAC-SHA256 is the sole signing
  primitive. No asymmetric path exists.
- spec.md §FR-15 specifies HMAC-SHA256 as the signature algorithm; there is no
  pluggable signature scheme abstraction.
- compliance-substrate/README.md §"Why this exists" sells "an auditor can
  verify the chain offline" — true only if the auditor has the key, which
  collapses the trust story for any non-cooperative audit relationship.
- No transparency-log / Merkle-root publication mechanism exists, so even
  under symmetric signing there is no out-of-band integrity anchor an external
  party could pin to.

## Proposed remedies (sketch — not a commitment)

Order roughly cheapest-to-most-defensible; a real design pass belongs in a
follow-on plan (probably an extension of Plan 008).

1. **Pluggable signature scheme.** Introduce a signer/verifier interface so
   HMAC remains the default but Ed25519 (or ECDSA P-256) can be slotted in.
   Event payload gains an `alg` field; existing HMAC events keep working.
   This is the structural prerequisite for everything below.

2. **Asymmetric signing with org-held private key + auditor-held public key.**
   Auditor verifies offline using only the public key. Solves the
   external-verifiability gap for the common case (single auditee, single
   external auditor). Does not solve "auditee forges events with their own
   private key" — only "auditor doesn't need custody of signing material."

3. **Co-signature / multi-signature events.** For transitions requiring
   independent attestation (e.g., risk acceptance by an executive approver
   who is *not* the same principal as the security officer who verified),
   require N-of-M signatures over the canonical payload. Composes with (2).
   Overlaps with the "multiple signers / impersonation" gap and should be
   designed jointly with it.

4. **Transparency-log anchor.** Periodically publish a Merkle root of the
   event log to an append-only external log (Sigstore Rekor, a public
   blockchain, a notary service, or even a customer-controlled S3 bucket
   with object-lock). An auditor can then pin a historical root and detect
   any later rewrite of events whose hashes are covered by that root. This
   defends against the "auditee forges with own private key" residual risk
   from (2). Highest defensibility, highest operational cost.

The minimum credible offering for regulated-buyer use cases is (1) + (2). (4)
is the differentiator versus a hypothetical competitor that ships only
asymmetric signing.

## Acceptance criteria

- [x] Signing primitive is abstracted behind an interface; HMAC-SHA256 is one
      implementation, not the only one. (Plan 011: `_signing_scheme.py` SigningScheme protocol)
- [x] Event payloads carry an `alg` (or equivalent) discriminator so a verifier
      can dispatch to the right scheme. Existing HMAC events remain verifiable
      with no replay/migration required (back-compat for the homelab default).
      (`scheme_id` column on events, migration 015; replay resolves per-event)
- [x] At least one asymmetric scheme (recommend Ed25519) ships with full
      sign/verify/key-rotation parity with the current HMAC path.
      (`Ed25519Scheme` in `_signing_scheme.py`, optional via `pip install regista[ed25519]`)
- [x] Spec §FR-15 and §17.9 are updated to describe the trust model under
      asymmetric signing and the residual "auditee forges with own private
      key" risk that asymmetric signing alone does not eliminate.
      (§17.9.1 added: signing scheme trust implications, HMAC vs Ed25519
      audit posture, residual operator-forgery risk, transparency-log note.)
- [ ] compliance-substrate's README and any agent-provenance positioning
      documents are revisited to make accurate claims about who can verify
      and under what trust assumptions.
- [ ] (Stretch) A design note exists for transparency-log anchoring, even if
      implementation is deferred.

## Resolution note

Plan 011 (pluggable signing, Ed25519) implemented the core technical
acceptance criteria (AC 1–3). BC-216 (KeyEntry restructure) and BC-217
(per-actor key resolution) landed in the same session. 18 tests in
`tests/test_bc214_216_217_218.py`. Spec update (AC 4) and
compliance-substrate positioning (AC 5) remain open.

## Non-goals

- Hardware-backed key custody (HSM, KMS) — orthogonal; tracked under BC-100
  and Plan 008's key-management workstream.
- Replacing HMAC for the homelab default. HMAC stays as the zero-config path;
  asymmetric is opt-in for deployments that need external verifiability.
- Rewriting historical events. Migration is forward-only — new events under
  the new scheme, old events verifiable under HMAC as long as the legacy key
  is retained.
