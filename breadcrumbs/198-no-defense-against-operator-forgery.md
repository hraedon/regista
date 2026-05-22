---
external_refs:
  plans:
  - 008
  related:
  - '100'
  - '101'
  - '172'
  - '174'
  - '196'
  - '197'
  tags:
  - trust-model
  - signing
  - timestamping
  - transparency-log
  - witness
  - rfc3161
  - opentimestamps
  - agent-provenance
identifier: '198'
kind: design
severity: medium
status: proposed
title: No defense against operator forgery — single key holder can rewrite or fabricate
  signed events with no external detection path
---
## Failure mode

BC-196 establishes that HMAC is symmetric and therefore an external auditor
cannot verify substrate's event log without holding the same secret the
operator holds. BC-196 proposes pluggable asymmetric signing (Ed25519) as the
structural fix for *external verifiability*.

But asymmetric signing alone does not defend against the operator-forgery
case: an entity that holds the private key can sign anything it wants — a
fabricated event with a backdated timestamp is indistinguishable from a
genuine historical event signed at the time it claims to have occurred. The
auditor with the public key can confirm "this signature is valid"; they
cannot confirm "this signature was produced when the event claims it was."

This is a category of risk separate from BC-196 and BC-197, and the fixes
compose with both rather than substituting for either. The fix space is also
narrower than people expect — there is no purely-local cryptographic
construction that solves it. Every credible answer involves binding the
event log to an external entity whose clock and integrity the operator does
not control.

## Why this matters

For the homelab/single-operator threat model (spec §17.9, Plan 008), this
gap is acceptable because the auditor is the operator. For every threat
model substrate is being repositioned toward — compliance-substrate's
external-auditor story, the agent-provenance project's regulated-buyer
story, any multi-party workflow — the gap is structural: a tamper-evident
log that the auditee can rewrite at will is *not* the property the auditor
needs.

The honest framing is that substrate today provides *integrity against
external tampering* (an attacker without the key cannot modify the log) but
not *integrity against operator forgery* (the operator with the key can
modify it freely). These are different properties and substrate currently
delivers only one.

## Constraints on the fix

- Must not require operating a private blockchain. Permissioned ledgers
  collapse trust to whoever runs consensus and add operational complexity
  without solving the underlying problem.
- Must remain a library, not a daemon, in spirit. Anything that requires
  substrate to run a long-lived network service complicates the deployment
  story.
- Must support a layered adoption path. Operators using substrate as a
  homelab tool should not be forced to provision external infrastructure;
  operators serving external audit should be able to opt in incrementally.
- Must compose with BC-196 (pluggable signing) and BC-197 (delegation
  chain). The signed payload must remain canonical-JSON over RFC 8785;
  external anchoring is *on top of* that signed payload, not a replacement
  for it.

## Proposed layered remedy (cheapest → most defensible)

Each layer is independently useful and strictly additive. None is required
for the homelab default; each can be opt-in via configuration.

### Layer 1 — RFC 3161 trusted timestamp tokens on event batches

Periodically (every N events, or every M seconds) hash the latest event
sequence and submit the hash to one or more RFC 3161 Time Stamping
Authorities. Store the returned TimeStampToken in substrate as a
first-class artifact (e.g., a `timestamp_anchor` event) referencing the
covered event range.

- **Defends against:** operator backdating events with their own key,
  for any event covered by a token.
- **Trust assumption:** the TSA's clock and the TSA's signing key. Cheap
  to diversify by submitting to multiple TSAs (FreeTSA, DigiCert public,
  industry-specific TSAs).
- **Cost:** ~free for public TSAs, pennies per stamp for commercial.
  Round-trip is a single HTTP call.
- **Limitation:** the operator still chooses *what* to timestamp and
  *when*. Events not covered by a token remain forgeable in their
  timestamp dimension.

### Layer 2 — Merkle tree of events + witness federation

Hash events into a binary Merkle tree as they are written. Periodically
(e.g., hourly) publish the current tree head to a configurable list of
witnesses (auditor endpoints, customer-controlled object storage with
object-lock, federated peer substrate instances). Witnesses return
signed observations of the tree head. Verifiers compare the substrate-
internal tree head against witness attestations; divergence is
detectable.

- **Defends against:** operator rewriting history *before* a witness
  observation, for any prefix of the log covered by witness signatures.
- **Trust assumption:** the operator cannot compromise all configured
  witnesses simultaneously without detection. Trust scales with the
  number and independence of witnesses.
- **Cost:** depends on witness operators. Single-witness mode (the
  auditor runs one endpoint) is the minimum viable form. Multi-witness
  is the defensible form.
- **Composes with:** Layer 1 (witnesses can also stamp the tree head
  via their own TSA, double-binding the head).

### Layer 3 — Optional OpenTimestamps anchoring of Merkle tree heads

For operators whose customers explicitly require public-blockchain-grade
immutability, batch tree heads and submit them via OpenTimestamps. OTS
aggregates submissions across many users into a single Bitcoin
transaction per batch period, so substrate does not need to run a
Bitcoin node, hold BTC, or care about transaction fees.

- **Defends against:** all operator-controlled rewrites of any event
  covered by an OTS proof, full stop. Bitcoin's economic security is
  the trust anchor.
- **Trust assumption:** Bitcoin's continued operation. The operator
  has no influence on this trust anchor.
- **Cost:** free at the OTS client side; latency for full proof
  upgrade can be hours (OTS publishes intermediate proofs immediately
  but they harden as Bitcoin confirmations accumulate).
- **Procurement note:** some regulated buyers will not accept any
  dependency on a public blockchain even when the dependency is
  one-way and the operator does not hold cryptocurrency. Ship as
  opt-in for the customers who want it; do not put it on the
  critical path.

## Non-goals

- Solving missing events. None of the above defends against
  "the operator chose not to record event X in the first place." That
  problem is structural and belongs to the consumer (agent-provenance,
  compliance-substrate) at the harness/capture layer, not to substrate
  at the signing layer. Document the gap explicitly so consumers can
  reason about it.
- Replacing HMAC for homelab use. Layer 1+ are opt-in. The homelab
  default remains HMAC + canonical JSON.
- Hardware key custody. Tracked under BC-100 and Plan 008's
  key-management workstream; orthogonal here.

## Acceptance criteria

- [ ] A `timestamp_anchor` (or equivalent) event type exists, carrying
      RFC 3161 token bytes and the event-sequence range covered. Stored
      and signed as part of the event log; verifiable offline against
      the TSA's certificate chain.
- [ ] Substrate exposes a configurable batching policy (every N events,
      every M seconds, on-demand) for Layer 1 anchoring.
- [ ] Multiple TSAs can be configured; substrate stores tokens from each
      and the verifier accepts any one of them.
- [ ] Merkle-tree construction over the event log is implemented; tree
      heads are computable at any historical event_seq.
- [ ] Witness submission protocol is specified (recommend: HTTP POST of
      `{tree_head, event_seq, timestamp}` to configured witness URLs,
      witness returns signed observation). At least one witness
      implementation exists for testing.
- [ ] Replay reconstructs Merkle heads byte-for-byte; drift detection
      includes "tree head at event_seq N differs from witness-observed
      head" as a first-class failure mode.
- [ ] (Layer 3 — optional) OpenTimestamps client integration exists
      behind a feature flag; substrate can submit and store OTS proofs;
      the verifier can upgrade incomplete proofs.
- [ ] spec.md §FR-15 / §17.9 are updated to describe the new threat
      model under each layer and explicitly state which layer of
      external trust is required for each property.

## Sequencing

Layer 1 is implementable today against the existing HMAC primitive and
should land first; it is materially useful even before BC-196's
asymmetric signing is in place. Layer 2 design should be drafted
alongside BC-196 since both touch the canonical signing surface. Layer 3
is a follow-on once Layer 2 is stable.
