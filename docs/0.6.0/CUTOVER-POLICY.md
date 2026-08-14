# regista S1 — Cutover and Legacy Policy

> **RANK 4 — still correct for v1–v5 semantics; four rules corrected for the two-epoch world.**
> `CUTOVER-CLASSIFICATION.md` §8 names the four (§2.1(b) anchor-receipt dating, §2.2's re-signing
> cascade, §3's `global_seq` watermark, §7's estate snapshot) and everything not listed there
> remains in force. `RECONCILIATION.md` governs both documents. Line citations in this document
> are pre-overlay; the specifications it points at have since been amended in place.

**Status:** design input for S1 remediation. Not a code change.
**Companions:** `FIELD-MATRIX.md` (what is signed), `RESULT-MODEL.md` (how a result is shaped),
`preflight_check.py` (how an operator measures their own store first).

---

## 1. The order of operations

S1's first engineering action is not code, and its first *operational* action is not a
migration. It is a measurement.

```
1. Run preflight_check.py, read-only, against every store.        (no code change)
2. Classify every finding using §2 / §4 below.                    (operator judgement)
3. Remediate or quarantine each INVALID / UNVERIFIABLE event.     (operator action)
4. Only then set the cutover watermark and ship the verifier.     (§3)
```

Step 1 exists because **the set of events that will newly fail is not assumed empty — it is
measured.** For the estate store as of this document it happens to be empty (§7), but that is a
result, not a premise, and it does not generalise to other deployments.

---

## 2. A mismatch in a genuinely signed field

**Definition.** `applicability = INVALID` with `mismatched_fields` non-empty, on an event whose
envelope version *does* sign the mismatched field (FIELD-MATRIX §1). The stored envelope
verifies under a trusted key; the row disagrees with it.

This is not a data-quality problem. The signature proves what the signer committed to. A row
that disagrees was written by something other than the append path.

### 2.1 The three permitted responses

**(a) Restore the row from the signed envelope.** Preferred when the envelope verifies under a
trusted key and the mismatched fields are all signed by that version. The envelope *is* the
record; the row is a projection that has drifted or been rewritten. Restoration rewrites only
projection columns — no signature, no chain hash, no seal, no anchor changes, because none of
them commit to the row.

Constraints:
- Only fields the envelope actually signs may be restored from it. Restoring `global_seq` or
  `scheme_id` from an envelope is meaningless (neither is ever signed) and restoring a v4 row's
  `actor_kind` is impossible (v4 does not sign it).
- Derived columns must be recomputed consistently: `entity_id` from the signed value, and
  `work_item_id` set equal to it (FIELD-MATRIX §2.1).
- The restoration itself must be recorded — outside the event log, in an operator audit trail.
  A silent `UPDATE events` is indistinguishable from the attack it is repairing.
- Re-run preflight afterwards and require zero mismatches on the affected events.

**(b) Restore from trusted backup.** Preferred when the envelope does **not** verify, when more
than the row was altered, or when the blast radius is unclear. Restore the whole row (or the
whole table) from a backup taken before the divergence, then re-run preflight over the restored
range. Choosing the backup point requires knowing *when* the divergence happened, which the
event log cannot tell you — use the anchor receipts (`anchor_receipts.submitted_at` +
`target_global_seq`) to bound it: any event at or below a confirmed anchor's
`target_global_seq` had its envelope and signature fixed at that anchor's time.

**(c) Quarantine.** The correct answer when neither (a) nor (b) is safe. Mark the event
range as quarantined **outside** the events table, refuse to serve it as authenticated, and
have every consumer treat it as `INVALID`. A quarantined range is an evidentiary loss that is
*recorded*, which is strictly better than an unrecorded one.

### 2.2 What is forbidden

**Never silently accept.** There is no policy flag, environment variable, or CLI option that
turns a signed-field mismatch into a pass (RESULT-MODEL §6.1). If such a flag existed it would
be used, and its existence would restore the exact defect S1 removes.

**Never routinely re-sign.** Re-signing an event to make the row and envelope agree is not a
migration; it is a cryptographic history rewrite. A new signature over new bytes changes, in
cascade:

| What changes | Why | Where |
|---|---|---|
| `canonical_envelope`, `signature`, `payload_canonical_hash` | new bytes, new signature, new hash | `_signing.py:261-262` |
| the event's **head hash** | `sha256(canonical_envelope ‖ signature)` | `_events.py:318-321`, `_event_store.py:99-104` |
| the **successor's** `prev_event_hash` | it commits to the predecessor's head hash — and it is a **signed** field in v3+ | `_events.py:214-228`; `_signing.py:131-132` |
| every subsequent event in that entity's chain | each link commits to the one before | — |
| the **global** chain from that point forward | `prev_global_event_hash` is signed in v3+ and links every event across all work items | `spec.md` §17.11; `_events.py:230`, `030_global_event_chain.sql` |
| every **segment seal** covering the range | the seal signs `head_hash` of the last event in the segment | `_archive_segments.py:436-448`, `039_event_segments.sql:14-29` |
| every **witness receipt** over those events | the witness countersignature covers `canonical_envelope` bytes | `spec.md` §17.14; `_witness.py:709-725` |
| every **anchor receipt** covering the range | `merkle_root` is the chain head, `sha256(canonical_envelope ‖ signature)` | `042_anchor_content_commit.sql:3-7`; `_anchoring.py:129-150` |

For an externally anchored batch this is worse than data loss: the anchored root no longer
matches the live events, so the anchor now *proves* that the log was rewritten after
anchoring — and a third party cannot distinguish a well-intentioned repair from the attack.
Re-signing to fix a mismatch destroys the property the system exists to provide.

The single narrow exception is §4's reconstruction of a **missing** envelope, where nothing is
being replaced and the reconstruction must be *proved* by the pre-existing signature.

### 2.3 Mismatch in a field the version does not sign

`applicability = LEGACY_PARTIAL` and the field is in `unsigned_fields`. There is nothing to
restore *from* — no signed value exists. The correct response is: record it, treat the field as
untrusted everywhere (which the result model already forces), and do **not** attempt repair. A
v4 event's `actor_kind` is unauthenticated forever; that is a property of v4, not a defect in
the row.

---

## 3. Where the cutover sits

The cutover is a pair, per project: **an envelope version floor and a `global_seq` watermark.**

```
policy.accept_legacy_versions          = {v4}     # and only v4
policy.accept_legacy_before_global_seq = <W>      # per-project integer, recorded once
```

**Chosen floor: v5.** Justification: v5 is the only version that signs `actor_kind` and
`actor_metadata` (`_signing.py:140-191`), which are the fields the review gate and assurance
actually make decisions from. It is also what every writer in 0.5.6 already emits — all four
sign sites pass a non-None `actor_kind` (`_events.py:251`, `:451`, `_event_store.py:130`,
`_archive_segments.py:472`), so `sign_event` always takes the v5 branch (`_signing.py:221-241`).
No new event should ever be v4, and the cutover makes that a checked invariant rather than an
emergent behaviour.

**Watermark `W`: set once per project, at S1 deployment, to `max(global_seq) + 1` at the moment
preflight last reported clean.** Recorded in the project catalog (or a new
`verification_policy` row), not in code, and never moved forward afterwards. Semantics:

| Event | Envelope | Result |
|---|---|---|
| `global_seq < W` | v5 | `FULLY_AUTHENTICATED` |
| `global_seq < W` | v4 | `LEGACY_PARTIAL` with `unsigned_fields ⊇ {actor_kind, actor_metadata, global_seq, scheme_id, work_item_id}` |
| `global_seq < W` | v1/v2/v3 | `LEGACY_PARTIAL` **only if** explicitly added to `accept_legacy_versions` for that project; otherwise `INVALID` |
| `global_seq ≥ W` | v5 | `FULLY_AUTHENTICATED` |
| `global_seq ≥ W` | anything below v5 | **`INVALID`** — a legacy envelope written after the cutover is a regression, not history |

**`global_seq` is an administrative bound, not a cryptographic one.** It is unsigned by design
(FIELD-MATRIX §3.1) and was backfilled by a `(timestamp, event_id)` proxy for pre-017 rows
(`017_events_global_seq.sql:8-14`), so an attacker who can write rows can move an event across
the watermark. This is acceptable **only** because crossing the watermark can never turn
`INVALID` into a pass — it can only turn `LEGACY_PARTIAL` into `INVALID` or the reverse, and
the reverse still requires the signature and every signed field to reconcile. The policy's
docstring and the CLI output must state this so nobody reads the watermark as a security
boundary.

**Default `accept_legacy_versions` for a store with no v1/v2/v3 events is `{v4}`.** Empty is
not a valid value while v4 history exists; the estate has 18,695 v4 events (§7) and setting
`{}` would make 5.3% of the log `INVALID` overnight for no security gain — v4 events are
correctly signed, they simply sign less.

**Sunsetting.** `accept_legacy_versions` is expected to shrink, never grow. Removing `v4` from
it becomes possible only when every v4 event has been archived out of the live query path
(segments, `events_archive`) or the deployment accepts them as `INVALID`. Growing the set for
any reason other than discovering genuine v1/v2/v3 history in a store is a policy regression
and should require the same review as a schema change.

---

## 4. Missing envelopes

`canonical_envelope IS NULL` — pre-`002_add_canonical_envelope.sql` rows. The column was added
nullable with no `DEFAULT` and no backfill (`002:1`), so those rows have a `signature` and a
`payload_canonical_hash` but nothing to verify them against.

Classification: **`UNVERIFIABLE`**, never `INVALID`. Nothing failed; there is nothing to check.

### 4.1 Reconstruction

An operator may attempt to reconstruct the envelope offline:

1. Build candidate envelopes from the row using the historical builders — v1
   (`_signing.py:12-28`) and v2 (`:31-57`) are the plausible shapes for a pre-002 row, plus the
   `on_behalf_of`-dropped v1 variant that `_signing.py:548-552` documents as having existed.
2. For each candidate compute `hash_alg(candidate)` and compare to the stored
   `payload_canonical_hash`, **and** verify the stored `signature` over the candidate under a
   trusted key.
3. Persist the candidate into `canonical_envelope` **only if exactly one candidate satisfies
   both checks.**

Rules that make this safe rather than a re-introduction of the escape hatch:

- **Both checks, not either.** The canonical hash alone is a hash over bytes the operator just
  chose; the signature alone is checked in the same breath. Requiring both, under a key from
  the trusted registry, is what makes the reconstruction a *proof* that these were the original
  bytes rather than a *guess* that happens to verify.
- **Uniqueness is required.** If two candidates both verify, the reconstruction is ambiguous
  and the event stays `UNVERIFIABLE`. (In practice a collision is implausible, but "implausible"
  is not the standard for writing into a cryptographic column.)
- **Offline and explicit.** Reconstruction is a deliberate operator command, never something the
  verify path does on the fly. The verify path has no envelope-reconstruction branch at all
  (RESULT-MODEL §4) — that is the whole point of S1.
- **Write-once.** Persisting the envelope is the only write S1 ever makes to a signed column,
  it applies only where the column was `NULL`, and it must be recorded in the operator audit
  trail with the candidate version chosen and the checks that passed.
- **If no candidate verifies:** the event remains `UNVERIFIABLE` permanently. Do not write a
  best-effort envelope. A written envelope that does not match the signature is worse than
  none — it converts an honest gap into a false `INVALID`, or, if someone later relaxes a
  check, into a false pass.

### 4.2 Consumers

An `UNVERIFIABLE` event must not be replayed as authenticated, must not contribute an
authenticated `actor_kind` to the review gate, and must be counted separately in every report.
Exit code `3` (RESULT-MODEL §6.5) exists so an operator can distinguish "old evidentiary gap"
from "active tamper" in CI without parsing text.

---

## 5. The InMemory backend

### 5.1 It needs the same reconciliation

`InMemoryEventStore` (`_event_store.py:169-...`) is not a toy: it backs `InMemoryRegista`,
tests, and local development, and it has its own replay (`_in_memory_replay.py:168`) and its own
verify surface (`_in_mem_ops.py:23-39`). If the strict verifier applies only to Postgres, the
two backends diverge in what "verified" means — and the InMemory one becomes the place where a
reconciliation bug hides until it reaches production.

**Rule.** `verify_event_strict` takes an `EventRow`-shaped input, not a `psycopg` row. The
InMemory backend supplies the same shape from its `Event` objects and runs the same
reconciliation. `_in_memory_replay.py`'s current behaviours must be corrected in the same
change:
- `verify_principal_binding` is a documented no-op (`_in_memory_replay.py:184-190`) and
  `principal_binding_verified=False` is hardcoded (`:483`). Under the result model that must
  become an explicit `trusted_key_source = NONE` with `UNVERIFIABLE`, not a silent skip that
  still reports `replayed_ok`.
- `_in_memory_replay.py:290` gates verification on `key_set` being present, so a keyless replay
  skips signature checks entirely and reports success with no indication that nothing was
  checked. That must become `UNVERIFIABLE` per §5.2.

### 5.2 Keyless mode must report UNSIGNED, not fail the strict verifier

When `key_set is None`, the store writes zero-byte dummy crypto material
(`_event_store.py:134-139`, constants at `:25-27`):

```python
else:
    key_id = _DUMMY_KEY_ID          # "in-memory"
    signature = _DUMMY_SIG          # b"\x00" * 32
    canonical_hash = _DUMMY_HASH    # b"\x00" * 32
    canonical_envelope = _DUMMY_SIG # the SAME 32 zero bytes as the signature
    _scheme_id = "hmac-sha256"      # a false claim of a real scheme
```

Feeding that to a strict verifier produces the wrong story: `canonical_envelope` is not JSON,
so it parses as `UNPARSEABLE` → `INVALID` → "this event was tampered with". It was not. It was
never signed.

**Rule.** Keyless events are detected **before** envelope parsing and classified
`EnvelopeVersion.KEYLESS_DUMMY` with `applicability = UNVERIFIABLE` and reason
`UNSIGNED_EVENT`. Detection criteria, all of which must hold (any subset is suspicious rather
than conclusive):

- `key_id == "in-memory"`, and
- `signature == canonical_envelope == payload_canonical_hash == b"\x00" * 32`, and
- the store is the InMemory backend.

The last clause matters: **a Postgres row exhibiting the dummy pattern is not a keyless event,
it is an attack** (or a corrupted import) and must remain `INVALID`. The keyless exemption is a
property of the backend, not of the byte pattern, and must not be inferable from the bytes
alone.

`policy.accept_unsigned_keyless` (default `False`) governs whether such an event may be
*processed* at all. Even when `True`, its applicability stays `UNVERIFIABLE` — the flag permits
use, it does not manufacture authentication. Tests that rely on keyless mode set it explicitly,
which also makes them greppable.

### 5.3 Two further keyless facts worth recording

- `_in_mem_ops.py:29` returns `False` from `verify_event_signature` when `self._key_set is
  None`, i.e. the API reports *"signature invalid"* for an event that was never signed. Under
  the result model this becomes `UNVERIFIABLE` / `UNSIGNED_EVENT`.
- The chain hash is computed over the dummies (`_event_store.py:99-104`, `:227-229`, `:245-247`,
  `:452-454`), so every keyless event chains from `sha256(b"\x00" * 64)` — a **constant**. The
  keyless "chain" is not a chain. The result must never report `prev_event_hash_ok = True` for
  a keyless event; it reports `None` (not evaluated).
- `scheme_id = "hmac-sha256"` on a keyless event is a false claim that has live consequences
  today: `_replay.py:953` exempts `hmac-sha256` events from the principal-binding requirement,
  and `_assurance.py:211-217` reads it to emit `"asserted"`. Deriving the scheme from key
  metadata (FIELD-MATRIX §3.2) removes the first; the second is fixed by consuming the result.

---

## 6. Operator runbook

```
# 0. never write to the store you are measuring
export REGISTA_DSN=...

# 1. measure — read-only, aggregate output, no payload content printed
python preflight_check.py --all-schemas \
    --key-file ~/.config/regista/keys.json \
    --json preflight.json

# exit 0 = nothing would newly fail
# exit 1 = at least one INVALID or would-newly-fail event  -> §2
```

Then, per finding class:

| preflight status | Meaning | Action |
|---|---|---|
| `fully-reconciled` | v5, signature valid, row agrees | none |
| `legacy-partial` | v4 (or older), signature valid, every signed field agrees | record; set `accept_legacy_versions` accordingly (§3); plan sunset |
| `would-newly-fail`, `mismatched_fields` in signed set | row disagrees with a signed field | **§2** — restore from envelope, restore from backup, or quarantine. Never accept, never re-sign |
| `would-newly-fail`, `<schema>` | envelope matches no known schema strictly | treat as §2; note that the *current* code would classify it `v1` and let it through — this is the escape hatch, so expect these to be the interesting findings |
| `unverifiable`, `no-stored-envelope` | pre-002 row | **§4** — optional offline reconstruction, else permanent `UNVERIFIABLE` |
| `unsigned`, `keyless-dummy-envelope` | InMemory keyless | **§5** — not a failure; must never be reported as signed |
| `invalid` (signature bad) | stored bytes do not verify under the resolved key | §2(b)/(c); (a) is not available because the envelope itself is not trustworthy |

Only when every finding is dispositioned: set `W`, set `accept_legacy_versions`, ship the
verifier, and re-run preflight as a post-deployment check.

---

## 7. What the estate actually looks like

Measured with `preflight_check.py`, read-only, all 26 project schemas, with real HMAC key
material loaded from `~/.config/regista/keys.json`:

| Finding | Count |
|---|---|
| Events scanned | **351,371** |
| Signature valid | 351,371 (100%) |
| Row↔envelope mismatches in signed fields | **0** |
| Would newly fail under the strict verifier | **0** |
| `fully_authenticated` (v5) | 332,676 (94.7%) |
| `legacy_partial` (v4 — unsigned `actor_kind`/`actor_metadata`) | 18,695 (5.3%) |
| `unverifiable` (missing envelope) | 0 |
| Unknown / unparseable envelope schemas | 0 |
| Strict vs permissive classifier disagreements | 0 |
| Affected segments | 0 (no `event_segments` rows exist in any schema) |
| Affected anchor receipts | 0 (no `anchor_receipts` rows exist in any schema) |

**Consequences for this estate specifically:**

- Step 2 of §1 is a no-op. No restoration, no quarantine, no reconstruction is required.
- The cutover can be set immediately, per project, at current `max(global_seq) + 1`.
- `accept_legacy_versions = {v4}` is required and sufficient. Setting `{}` would make 18,695
  correctly-signed events `INVALID` for no gain.
- Because no segments and no anchor receipts exist anywhere, the seal/anchor cascade described
  in §2.2 is currently hypothetical here — which is *fortunate timing*, since it means the
  window in which a re-sign would have been merely expensive rather than externally detectable
  is still open. It will close the first time anchoring is enabled. That is an argument for
  landing S1 before anchoring is turned on, not after.

**This result does not generalise.** It says the estate is clean; it says nothing about a store
carrying pre-002, pre-017 or pre-031 history, which is exactly the population the backfill
analysis in FIELD-MATRIX §4 is about. Every deployment runs preflight for itself.
