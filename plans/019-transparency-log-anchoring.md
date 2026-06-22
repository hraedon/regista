# Plan 019 — Transparency-Log Anchoring (operator-forgery defense)

**Status:** proposed 2026-05-28
**Author:** Opus 4.8 (portfolio review)
**Closes:** BC-196 remedy #4 (the residual gap AC 1–3 explicitly do *not* solve)
and BC-196 AC-5 (positioning-doc accuracy) + stretch (transparency-log design note).

## Why this is the one regista feature worth grant resource

regista is "nearly done" and over-built relative to its consumers — adding
breadth would be gold-plating. But BC-196's own resolution note names a gap that
Ed25519 signing does **not** close:

> "Asymmetric signing... does not solve 'auditee forges events with their own
> private key' — only 'auditor doesn't need custody of signing material.'"

For the regulated-workplace pitch, that residual gap is the auditor's *first*
question: "you hold the private key — prove you didn't sign a backdated event
five minutes ago." Today there is no answer. BC-196 remedy #4 (transparency-log
anchor) is the only structural one, and it is flagged there as "the
differentiator versus a competitor that ships only asymmetric signing." It is
also cheap: OpenTimestamps anchors to Bitcoin with no account and no trusted
third party.

This converts the provenance bundle's caveat from "trust the operator's key
custody" to "any rewrite of events covered by a published root is externally
detectable." That is the difference between a demo and a defensible artifact.

## Goal

Periodically publish a Merkle root of the event log to an append-only external
log, and let the verifier check a historical root so any later rewrite of
covered events is detectable without trusting the operator.

## Design

regista already has Merkle batching for RFC 3161 timestamping (Plan 012). Reuse
that tree; add a second anchor target.

### WI-1 — Anchor provider interface
- Add an `AnchorProvider` protocol mirroring the existing signing-scheme
  pluggability: `submit(merkle_root: bytes) -> AnchorReceipt` and
  `verify(root: bytes, receipt: AnchorReceipt) -> AnchorStatus`.
- Ship two implementations:
  - `OpenTimestampsProvider` (default for the public-anchor story; uses the
    `opentimestamps` library; receipt is a `.ots` proof). Optional dep:
    `pip install regista[anchoring]`.
  - `RFC3161Provider` (wraps the Plan 012 TSA path under the same interface, so
    "anchor" and "timestamp" share one surface).
- A `FileAnchorProvider` (writes roots to an operator-controlled append-only
  location, e.g. S3 object-lock) as a no-network escape hatch for air-gapped
  regulated deployments.

### WI-2 — Anchor scheduling
- Extend the maintenance thread (already runs sweep / recurrence / TSP batching)
  to submit the current Merkle root on an interval, and to upgrade pending
  OpenTimestamps proofs (Bitcoin attestation lands asynchronously — the proof
  starts as a calendar-server commitment and is upgraded to a block-anchored
  proof later; the maintenance thread polls for the upgrade).
- Store receipts in a new `anchor_receipts` table keyed by `(merkle_root,
  provider)` with `status` (pending | committed | confirmed).

### WI-3 — Verifier integration
- `regista verify` (and the CLI `regista timestamp status`-adjacent surface)
  gains anchor verification: given a bundle + its anchor receipts, confirm the
  bundle's events hash into a root that the external log attests, and report
  per-root status. No DB or signing key required.
- Exit non-zero if a covered event's hash is not reproducible from the anchored
  root (the tamper signal).

### WI-4 — Bundle export carries anchor proofs
- The event-bundle export format (consumed by agent-provenance `cairn export`)
  includes the relevant `anchor_receipts` so a third party can verify offline.

### WI-5 — Close BC-196 documentation ACs
- Update spec §17.9 trust-model section to describe the anchoring posture and
  what residual risk remains (e.g., the window between an event and its next
  anchor; pre-anchor events are only HMAC/Ed25519-defensible).
- Revisit the positioning docs (BC-196 AC-5) — agent-provenance bundle caveat
  and any compliance-substrate prose — so claims match what anchoring actually
  proves. No over-claiming.

## Acceptance

- `AnchorProvider` interface with OpenTimestamps + RFC3161 + File implementations;
  HMAC/Ed25519 signing path unchanged.
- Maintenance thread submits roots and upgrades pending OTS proofs; receipts
  persisted with status transitions.
- `regista verify` confirms a bundle against its anchor receipts with only the
  bundle + receipts (no DB, no key), and fails on a tampered covered event.
- Export format carries anchor receipts.
- spec §17.9 updated; BC-196 AC-5 positioning docs corrected; BC-196 closed.

## Sequencing & dependencies

- Reuses Plan 012 Merkle batching — confirm that code path before WI-1.
- **Composes with agent-provenance Plan 006** but does not block it: Plan 006's
  bundle ships with the weaker caveat if 019 hasn't landed, the stronger one if
  it has. Run them concurrently.
- Background-tempo work; does not need the operator's daily attention.

## Non-goals

- HSM/KMS key custody (BC-100, orthogonal).
- A blockchain of regista's own. We *anchor to* an existing public log; we do
  not operate one.
- Real-time anchoring. Interval batching is the model; the anchor latency
  (OTS confirmation is ~hours) is documented, not engineered away.
