# regista S1 — Authenticated-Field Matrix

> **RANK 4 — unamended.** This matrix describes what v1–v5 envelopes authenticate, and the
> overlay changes none of it: v6 is a new envelope version, not a re-interpretation of the old
> ones. Two reading notes: its §9 counts belong to the **S1 snapshot** (`preflight-s1.json`,
> 351,371 events) and not to the current estate (`preflight-live.json`, 353,985); and
> `RECONCILIATION.md` governs wherever a v6 question arises.

**Status:** design input for S1 remediation. Not a code change.
**Scope:** what the stored `canonical_envelope` actually authenticates, per envelope
version, and what the `events` row column of the same name may legitimately hold.
**Repo:** the shared `rc-build` regista checkout @ `release/0.5.6` (source identical to
`origin/main` at the time this matrix was frozen; check citations with
`git show <ref>:<path>`, never against a working tree).

The governing rule, already design-reviewed and not relitigated here:

> The stored canonical envelope is the cryptographic artifact. The row is its indexed
> projection. Verify the exact stored bytes; then require every field that envelope
> version signs to agree with its row representation before any consumer reads the row.

Everything below exists to make "every field that envelope version signs" a closed,
enumerated set rather than an implementer's guess.

---

## 0. Sources of truth

| Thing | Where |
|---|---|
| v1 envelope | `src/regista/_signing.py:12-28` (`build_signing_envelope`) |
| v2 envelope | `src/regista/_signing.py:31-57` (`build_signing_envelope_v2`) |
| v3 envelope | `src/regista/_signing.py:60-95` (`build_signing_envelope_v3`) |
| v4 envelope | `src/regista/_signing.py:98-137` (`build_signing_envelope_v4`) |
| v5 envelope | `src/regista/_signing.py:140-191` (`build_signing_envelope_v5`) |
| Version classifier (permissive, to be replaced) | `src/regista/_signing.py:305-323` |
| Declared field sets | `src/regista/_signing.py:276-302` |
| Canonicalisation | `src/regista/_jcs.py:1-10` → `regista._vendor.rfc8785.dumps` (RFC 8785 JCS) |
| Row shape | `migrations/001_initial.sql` + 002, 014, 015, 017, 018, 030, 031 |
| Row → `Event` | `src/regista/_events.py:35-62`; duplicate at `src/regista/_archive_segments.py:301-330`; JSON variant at `src/regista/_bundle.py:1641` |
| `Event` model | `src/regista/_types.py:102-135` |

Two structural facts that shape the whole matrix:

1. **The `events` row has 23 columns; no envelope version signs more than 18 of them,
   and v1 signs 6.** Verified against the live estate store: 23 columns, none generated,
   none a view (`information_schema.columns`, and see §4).
2. **Every current writer emits v4 or v5 only.** `sign_event`
   (`src/regista/_signing.py:194-262`) can only produce v4 (when `actor_kind is None`) or
   v5 (otherwise); v1/v2/v3 envelopes exist only as history. All three write paths
   (`_events.py:233`, `_events.py:433`, `_event_store.py:112`, plus the segment seal at
   `_archive_segments.py:455`) pass a non-None `actor_kind`, so **new events are always
   v5**. The 18,695 v4 events measured in the estate are pre-WI-208 history.

---

## 1. Per-version signed field sets (normative)

`R` = always emitted by that builder. `O` = emitted only when the argument is not None
(a **presence-significant** field — see §5). `—` = not in that version's envelope.

| Envelope field | v1 | v2 | v3 | v4 | v5 |
|---|---|---|---|---|---|
| `event_id` | R | R | R | R | R |
| `work_item_id` | R | R | R | — | — |
| `entity_kind` | — | — | — | R | R |
| `entity_id` | — | — | — | R | R |
| `actor_id` | R | R | R | R | R |
| `actor_kind` | — | — | — | — | R |
| `actor_metadata` | — | — | — | — | R |
| `key_id` | — | R | R | R | R |
| `event_seq` | — | R | R | R | R |
| `workflow_name` | — | R | R | R | R |
| `workflow_version` | — | R | R | R | R |
| `timestamp` | — | R | R | R | R |
| `hash_alg` | — | — | — | R | R |
| `on_behalf_of` | R | R | R | R | R |
| `transition` | R | R | R | R | R |
| `payload` | R | R | R | R | R |
| `prev_event_hash` | — | — | O | O | O |
| `global_seq` | — | — | O | O | O |
| `prev_global_event_hash` | — | — | O | O | O |

Counts: v1 = 6 fields, v2 = 11, v3 = 11 + up to 3, v4 = 13 + up to 3, v5 = 15 + up to 3.

**v2 and v3 are the same schema when no chain field is present.** `build_signing_envelope_v3`
with all three chain arguments `None` emits byte-identical output to
`build_signing_envelope_v2` (compare `_signing.py:76-88` with `_signing.py:44-56`). The
verifier must treat "v2" and "chain-less v3" as one schema; the distinction is not
recoverable from the bytes and does not need to be.

---

## 2. The matrix: envelope field ↔ row column

Legend for **Row name identical?**: ✔ same column name; ✖ different name or no column.
"Legitimate divergence" means row and envelope may differ *without* that being tamper.

### 2.1 Identity

| Field | In envelope | Row column | Name identical? | Legitimate divergence | Migration backfill | Verifier must |
|---|---|---|---|---|---|---|
| `event_id` | v1–v5 | `events.event_id` UUID PK (`001_initial.sql:2`) | ✔ | **None.** Compared case-insensitively as a UUID string; the envelope holds `str(uuid)` (`_signing.py:21`) and the row holds a `uuid` type. Textual case/format is a representation artefact, the value is not. | none | Normalise both to canonical lowercase UUID text and require equality. A mismatch is fatal — this is the primary key binding the envelope to the row. |
| `work_item_id` | v1–v3 only | `events.work_item_id` UUID NOT NULL (`001_initial.sql:3`) | ✔ | none in v1–v3 | none | v1–v3: require equality. v4/v5: **not signed** — see `entity_id` below. |
| `entity_kind` | v4, v5 | `events.entity_kind` TEXT NOT NULL DEFAULT `'work_item'` (`031_entity_generalization.sql:12`) | ✔ | none in v4/v5 | **Yes — 031.** `ADD COLUMN NOT NULL DEFAULT 'work_item'` stamps every pre-031 row with a value that row's v2/v3 envelope never signed. | v4/v5: require equality. v1–v3: report as **unsigned/backfilled**; never treat as authenticated. |
| `entity_id` | v4, v5 | `events.entity_id` UUID NOT NULL (`031:13`, NOT NULL at `031:18`) | ✔ | none in v4/v5 | **Yes — 031:16**, `UPDATE events SET entity_id = work_item_id;` — unconditional, no `WHERE`. | v4/v5: require equality. v1–v3: report as **unsigned/backfilled**. |
| `work_item_id` ↔ `entity_id` alias | (derived) | both real columns | — | none observed | see 031 | For any event whose envelope signs `entity_id` (v4/v5), **require `row.work_item_id == row.entity_id`**. Both live writers set them equal (`_events.py:271-273`, `_archive_segments.py:539-542`), including for `entity_kind='segment'`. Without this check the *unsigned* `work_item_id` column can steer a consumer to a different work item than the one the signature covers. |

**Note on the alias direction.** The task brief describes `work_item_id` as "a compatibility
alias per migrations/031". The dependency actually runs the other way: `work_item_id` is the
original 001 column and is retained NOT NULL; `entity_id` is the *derived* one, filled from
`work_item_id` by the `events_set_entity_id` BEFORE INSERT trigger
(`031_entity_generalization.sql:34-47`). The security consequence is unchanged and is what
matters: **from v4 onward the signature covers `entity_id`, and `work_item_id` is
unauthenticated**, so equality must be enforced rather than assumed.

### 2.2 Actor and delegation

| Field | In envelope | Row column | Name identical? | Legitimate divergence | Migration backfill | Verifier must |
|---|---|---|---|---|---|---|
| `actor_id` | v1–v5 | `events.actor_id` TEXT NOT NULL (`001:5`) | ✔ | none | none | Require exact string equality in every version. |
| `actor_kind` | **v5 only** (`_signing.py:145,173`) | `events.actor_kind` TEXT NOT NULL, CHECK in (`agent`,`human`,`system`) (`001:6`) | ✔ | none in v5 | none (present since 001) | v5: require equality. **v1–v4: UNSIGNED legacy provenance.** Must be reported as unsigned, never silently trusted. This is the exact gap WI-208 opened v5 to close (`_signing.py:160-167`); v4 events remain permanently exposed. |
| `actor_metadata` | **v5 only** | `events.actor_metadata` JSONB NULL (`001:7`) | ✔ | none in v5 | none | v5: compare on **canonical JCS bytes** (§6). v1–v4: report unsigned. |
| `on_behalf_of` | v1–v5, always emitted (may be JSON `null`) | `events.on_behalf_of` JSONB NULL (`014_on_behalf_of.sql:2`) | ✔ | none | none (nullable, no backfill) | Compare on canonical JCS bytes, with envelope-`null` ⇔ row `NULL`. Because the key is *always* present in every version, this is a **value** comparison, not a presence one (contrast §5). Pre-014 rows have `NULL`, which matches the `null` their v1/v2 envelope signed. |

### 2.3 Key, sequence, workflow, time

| Field | In envelope | Row column | Name identical? | Legitimate divergence | Migration backfill | Verifier must |
|---|---|---|---|---|---|---|
| `key_id` | v2–v5 | `events.key_id` TEXT NOT NULL (`001:8`) | ✔ | none in v2–v5 | none | Require equality. **And resolve the verification key from the *envelope's* `key_id`, not the row's.** Today the row's `key_id` selects the key (`_signing.py:814`, `_replay.py:1034` path), so a row-only rewrite of `key_id` changes which key is tried and turns a tamper signal into "unknown key". v1: `key_id` is unsigned — key selection for v1 events is unauthenticated and must be reported as such. |
| `event_seq` | v2–v5 | `events.event_seq` INTEGER NOT NULL (`001:4`) | ✔ | none | none | Require equality. Uniqueness is enforced by `events_entity_event_seq_key` (`031:28-29`) but uniqueness is not authenticity. v1: unsigned. |
| `workflow_name` | v2–v5 | `events.workflow_name` TEXT NOT NULL (`001:9`) | ✔ | none | none | Require equality. v1: unsigned. |
| `workflow_version` | v2–v5 | `events.workflow_version` INTEGER NOT NULL (`001:10`) | ✔ | none | none | Require equality. v1: unsigned. |
| `timestamp` | v2–v5, as `timestamp.isoformat()` (`_signing.py:52`, `:84`, `:125`, `:179`) | `events.timestamp` TIMESTAMPTZ NOT NULL DEFAULT `now()` (`001:11`; 019 is documentation-only, `019_explicit_event_timestamp.sql:11` says "Idempotent: no-op") | ✔ | **Yes — textual rendering.** The envelope stores a fixed ISO-8601 string; the row stores an instant. `psycopg` renders that instant in the *session* time zone, so the same row yields `...T19:10:50.123456+00:00` under `TZ=UTC` and `...T12:10:50.123456-07:00` under `TZ=America/Phoenix`. **This is not tamper.** Measured: with `PGTZ=America/Phoenix` all 14 `switchboard` events report a textual difference and zero instant differences. | none | Compare **instants**, not strings: parse the envelope string with `datetime.fromisoformat` and require `==` against the tz-aware row value. Report a textual-rendering difference as an informational note, never as a mismatch. Reject naive/aware mixes rather than coercing. |
| `hash_alg` | v4, v5 | `events.hash_alg` TEXT NOT NULL DEFAULT `'sha-256'` (`031:14`) | ✔ | none in v4/v5 | **Yes — 031:14**, default materialised onto every pre-031 row. | v4/v5: require equality, **and take the hash algorithm used for the signature check from the envelope, not the row.** Today `_verify_once` is called with the row's `hash_alg` (`_signing.py:463`), so a row-only rewrite turns a reconciliation failure into an ambiguous signature failure. v1–v3: unsigned and backfilled — the row value is a migration artefact; the effective algorithm for those versions is `sha-256` by construction (`_signing.py:463`: `candidate_hash_alg = hash_alg if ver >= 4 else "sha-256"`). |

### 2.4 Content

| Field | In envelope | Row column | Name identical? | Legitimate divergence | Migration backfill | Verifier must |
|---|---|---|---|---|---|---|
| `transition` | v1–v5, always emitted (may be `null`) | `events.transition` TEXT NULL (`001:12`) | ✔ | none | none | Require equality including the null case. |
| `payload` | v1–v5, always emitted (may be `null`) | `events.payload` JSONB NULL (`001:13`) | ✔ | **Representation only.** `jsonb` does not preserve key order, insignificant whitespace, or duplicate keys; JCS re-serialises deterministically, so a byte comparison of raw JSON is meaningless. | none | Compare on **canonical JCS bytes** of the two parsed values (§6). Never compare raw text. Never compare with Python `==` alone: `1 == 1.0` and `True == 1` are Python-true but produce different signed bytes. |

### 2.5 Chain fields (presence-significant — see §5)

| Field | In envelope | Row column | Name identical? | Legitimate divergence | Migration backfill | Verifier must |
|---|---|---|---|---|---|---|
| `prev_event_hash` | v3–v5, **only when not None** (`_signing.py:89-90`, `:131-132`, `:185-186`); hex-encoded | `events.prev_event_hash` BYTEA NULL (`018_prev_event_hash.sql:2-3`) | ✔ | none | none (nullable, **no backfill** — pre-018 rows are permanently `NULL`) | Reconcile by **presence and value**: envelope-absent ⇔ row `NULL`; envelope-present ⇒ `bytes.fromhex(env) == row`. A row that gains a non-NULL `prev_event_hash` where the envelope omitted it is a mismatch, not a benign upgrade. |
| `prev_global_event_hash` | v3–v5, only when not None; hex-encoded | `events.prev_global_event_hash` BYTEA NULL (`030_global_event_chain.sql:13`) | ✔ | none | none (nullable, no backfill) | Same presence+value rule. This is the field the global chain and the content anchor both depend on (`spec.md` §17.11; `_anchoring.py:227`). |
| `global_seq` | v3–v5 **schema permits it**, but no writer ever emits it | `events.global_seq` BIGINT NOT NULL DEFAULT `nextval(...)` (`017_events_global_seq.sql:2-3,16,32`) | ✔ | **Yes, by design — see §3.** | **Yes — 017:8-14**, a synthetic ordering proxy | See §3. |

### 2.6 Derived cryptographic artifacts — NOT recursive envelope fields

| Column | Signed? | Verifier must |
|---|---|---|
| `canonical_envelope` BYTEA NULL (`002_add_canonical_envelope.sql:1`) | It **is** the signed artifact | Verify the exact stored bytes. Never rebuild-and-substitute (see §7). Nullable with **no backfill**, so pre-002 rows have no envelope at all and are `unverifiable`, not `invalid`. |
| `signature` BYTEA NOT NULL (`001:15`) | The signature *over* the envelope | Not an envelope field. Verified by the scheme (`_signing_scheme.py:104-123` HMAC, `:148-190` Ed25519). |
| `payload_canonical_hash` BYTEA NOT NULL (`001:14`) | Derived: `hash_alg(envelope)` | Not an envelope field, and — despite the name — it is a hash of the **envelope**, not of `payload` (`_signing_scheme.py:108-110`). Both shipped schemes already check it inside `verify` (`_signing_scheme.py:121-123`, `:188-190`), so it is covered by the signature check; the verifier must not treat it as an independently trusted value. |
| `scheme_id` TEXT NOT NULL DEFAULT `'hmac-sha256'` (`015_event_scheme_id.sql:2`) | **Never, in any version** | See §3. |

---

## 3. The fields that need an explicit ruling

### 3.1 `global_seq` — UNSIGNED BY DESIGN

- The spec is explicit: *"`global_seq` is assigned **post-signing** and is NOT in the signed
  envelope … External verification must pass `prev_global_event_hash` but NOT `global_seq`"*
  (`spec.md` §17.11, and §17.12 for `verify_event_with_public_key`).
- The column is `BIGSERIAL`-backed and assigned by the `INSERT … RETURNING global_seq`
  (`_events.py:266-292`), i.e. strictly after `sign_event` returned at `_events.py:233`.
- `build_signing_envelope_v3/v4/v5` each *accept* a `global_seq` argument and would emit it
  (`_signing.py:91-92`, `:133-134`, `:187-188`) — but **no caller ever passes one.** Verified
  across the tree: the four sign sites (`_events.py:233`, `:433`, `_event_store.py:112`,
  `_archive_segments.py:455`) pass no `global_seq`. Confirmed empirically: **0 of 351,371
  live estate envelopes contain a `global_seq` key.**
- It was **backfilled** by `017_events_global_seq.sql:8-14` using
  `ROW_NUMBER() OVER (ORDER BY timestamp, event_id)` — the migration's own comment (`017:5-7`)
  calls it "the closest stable proxy for arrival order". Ties break on a random UUID, so the
  backfilled order is not true append order.

**Ruling.** `global_seq` is validated **structurally**, never cryptographically:
- If the envelope omits it (the universal case), the verifier performs no value
  reconciliation and must report `global_seq` in the **unsigned** field list.
- If a stored envelope *does* carry it, equality is required — a signed value that disagrees
  with its row is a mismatch like any other. The result must still not describe `global_seq`
  as authenticated in general.
- Ordering must continue to be established by walking `prev_global_event_hash`, never by
  sorting on `global_seq` (already the rule per `spec.md` §17.11; the anchor path
  `_anchoring.py:152-250` and replay both walk links).
- **The result model must never let `global_seq` appear in `authenticated_fields`.** Emitting
  a "verified" result that implicitly covers `global_seq` would be a false claim about the
  017 backfill.

### 3.2 `scheme_id` — outside every envelope, yet it selects the verifier

`scheme_id` appears in none of `_V2_FIELDS`…`_V5_FIELDS` (`_signing.py:276-299`) and in none
of the five builders. It was added by `015_event_scheme_id.sql:2` as
`NOT NULL DEFAULT 'hmac-sha256'`, silently stamping every pre-015 row.

It is nonetheless read **from the row** on essentially every verification path:
`_signing.py:574` (`get_scheme(event.scheme_id)`), `_signing.py:823`, `_replay.py:1034`,
`_in_memory_replay.py:294`, `_archive_segments.py:80`, `_bundle.py:745`,
`_assurance.py:211-217`. Three consequences are worth naming because they are live
privilege-relevant behaviours, not hypotheticals:

1. `_replay.py:953` decides whether principal registration is *required* by testing the row's
   `scheme_id` against the asymmetric scheme set. **A row that claims `hmac-sha256` opts
   itself out of the binding requirement.**
2. `_signing.py:697` — `elif scheme_id == "hmac-sha256": pass` — a row claiming HMAC skips the
   "event `key_id` must match a non-revoked registered key" filter entirely.
3. `_assurance.py:211-217` derives the string `"verified"` vs `"asserted"` purely from the
   row's `scheme_id`, with no signature check anywhere in that path.

**Ruling.** `scheme_id` must be **derived from trusted key metadata, never read from the row**:
resolve the key from the envelope's `key_id` (v2+) via the principal-key registry / `KeySet`,
and take the scheme from that key entry (`KeyEntry.scheme`, as the write path already does at
`_events.py:231-232`). The row's `scheme_id` becomes an advisory column that may be *compared*
to the derived value and reported on mismatch, but must never select the algorithm, and must
always appear in the **unsigned** field list. For v1 envelopes there is no signed `key_id`, so
scheme derivation is itself unauthenticated for v1 — a fact the result must carry.

### 3.3 v4 `actor_kind` / `actor_metadata` — unsigned legacy provenance

v4 does not sign them (`_signing.py:116-130`); v5 does (`_signing.py:168-184`), which is what
WI-208 was for. The current reconciliation exists only for `stored_ver == 5`
(`_signing.py:474-486`) and returns a bare `False`, so a v4 event's actor provenance is
unauthenticated and *silently* so.

`spec.md` §17.9 still describes `actor_kind`/`actor_metadata` as "stored on the event row but
**not included** in the canonical signing envelope" — that text is **stale for v5** and should
be corrected as part of S1 (see §8).

**Ruling.** For v1–v4, `actor_kind` and `actor_metadata` go in the **unsigned** list and the
result's applicability is at best `legacy_partial`. Any consumer that makes a trust decision
from them — the review gate (`_review_validators.py:107`, `:155`, `:260`) and assurance
(`_assurance.py:201-219`) most of all — must be able to see, from the result, that those
fields were not authenticated. **Measured exposure: 18,695 v4 events across the estate
(5.3% of 351,371), of which 18,693 carry a non-NULL `actor_metadata`.**

### 3.4 Derived artifacts

`signature`, `payload_canonical_hash`, and `canonical_envelope` itself are outputs of signing,
not inputs to it. They must never appear as reconcilable envelope fields (there is no
`envelope["signature"]`), and must never appear in `authenticated_fields`. They are inputs to
the *signature* component of the result, not the *reconciliation* component.

---

## 4. Migration backfills that put unsigned values into rows

Exhaustive over `migrations/001` … `migrations/044`. There are exactly **two** `UPDATE events`
statements in the entire migration history, plus three `ADD COLUMN … NOT NULL DEFAULT`
materialisations.

| Migration | Column(s) | Value written | Ever signed for the affected rows? |
|---|---|---|---|
| `015_event_scheme_id.sql:2` | `scheme_id` | constant `'hmac-sha256'` via `ADD COLUMN NOT NULL DEFAULT` | **No — never signed in any version** |
| `017_events_global_seq.sql:8-14` | `global_seq` | `ROW_NUMBER() OVER (ORDER BY timestamp, event_id)` | **No** — affected rows carry v2 envelopes, and `_V2_FIELDS` has no `global_seq` |
| `031_entity_generalization.sql:12` | `entity_kind` | constant `'work_item'` via `ADD COLUMN NOT NULL DEFAULT` | **No** for pre-031 rows (their envelopes are v2/v3) |
| `031_entity_generalization.sql:16` | `entity_id` | `UPDATE events SET entity_id = work_item_id` (unconditional) | **No** for pre-031 rows; only implicitly covered insofar as a verifier cross-checks it against the signed `work_item_id` |
| `031_entity_generalization.sql:14` | `hash_alg` | constant `'sha-256'` via `ADD COLUMN NOT NULL DEFAULT` | **No** for pre-031 rows |
| `031_entity_generalization.sql:20-24` | same three on `events_archive` | same, with `WHERE entity_id IS NULL` on the archive | same |

Columns added **without** any backfill (existing rows left `NULL` forever):

| Migration | Column | Consequence |
|---|---|---|
| `002_add_canonical_envelope.sql:1` | `canonical_envelope` BYTEA, nullable, no DEFAULT, no UPDATE | Pre-002 rows have a `signature` and a `payload_canonical_hash` but **no envelope to verify against** — the `unverifiable` class, not the `invalid` class |
| `018_prev_event_hash.sql:2-3` | `prev_event_hash` | pre-018 rows are `NULL`, consistent with their chain-less envelopes |
| `030_global_event_chain.sql:13` (and `:16` for the archive) | `prev_global_event_hash` | same |

**No migration ever modifies `canonical_envelope`, `signature` or `payload_canonical_hash` of
an existing row.** Signed bytes are byte-stable across the whole migration history — which is
precisely why the 015/017/031 backfilled columns sit outside the signed scope for legacy rows,
and precisely why "verify the stored bytes and reconcile the row against them" is the correct
shape of the fix.

There are no generated columns, no views over `events`, and exactly one trigger
(`events_set_entity_id`, `031:34-47`).

---

## 5. Presence vs value: which fields must be reconciled by PRESENCE

The distinction is real because three different states exist and only two of them are the same:

- **absent from the envelope** — the key is not in the JSON object at all;
- **present with JSON `null`** — the key is there with a null value, and those bytes are signed;
- **row `NULL`** — the column has no value.

`absent` and `present-with-null` produce **different signed bytes** and therefore different
signatures. Getting the rule wrong in either direction is a defect: treating absent as
equivalent to null-valued lets an attacker delete a signed `null` and re-add it (no — the
signature would fail, but a *reconciler* that only compares values would report clean on an
envelope it never parsed strictly); treating a legitimately-absent optional field as a
mismatch fails every pre-018 event in the store.

**Reconcile by PRESENCE (and, when present, by value):**

| Field | Rule |
|---|---|
| `prev_event_hash` (v3–v5) | envelope-absent ⇔ row `NULL`; envelope-present ⇒ hex value must equal row bytes |
| `prev_global_event_hash` (v3–v5) | same |
| `global_seq` (v3–v5) | absent is the normal case and reconciles against **any** row value (§3.1); present ⇒ must equal |

**Reconcile by VALUE only (the key is unconditionally emitted, so its presence carries no
information):**

| Field | Why |
|---|---|
| `on_behalf_of` | emitted in every version at `_signing.py:24`, `:53`, `:85`, `:127`, `:181` — always present, value may be `null`. Envelope `null` ⇔ row `NULL`. |
| `transition` | always emitted, may be `null` |
| `payload` | always emitted, may be `null` |
| `actor_metadata` (v5) | always emitted at `_signing.py:174`, may be `null` |

**Presence of a required field is a schema question, not a reconciliation question.** If a v5
envelope is missing `actor_metadata`, it is not "a v5 event with an absent optional field" —
it is not a valid v5 envelope at all, and strict classification rejects it (see RESULT-MODEL
§3). This is the hole the current permissive classifier leaves open: `_signing.py:311-319`
uses `issuperset`, so any *subset* of a version's fields — including `{}` — falls through to
`return 1` and is treated as a v1 envelope.

---

## 6. Comparison rules (normative, per type)

| Type | Rule |
|---|---|
| UUID (`event_id`, `work_item_id`, `entity_id`) | normalise both sides to lowercase canonical UUID text; compare equal |
| Text (`actor_id`, `actor_kind`, `key_id`, `workflow_name`, `transition`, `entity_kind`, `hash_alg`) | exact byte-for-byte string equality; no case folding, no trimming |
| Integer (`event_seq`, `workflow_version`, `global_seq`) | exact integer equality; reject a JSON float that happens to be integral |
| Timestamp | parse envelope ISO-8601, require **instant** equality against the tz-aware row value; report textual-rendering differences as an informational note only; refuse to compare a naive against an aware datetime |
| `bytea` (`prev_event_hash`, `prev_global_event_hash`) | envelope holds `.hex()` (`_signing.py:90`); compare decoded bytes, or lowercase hex on both sides |
| JSON (`payload`, `actor_metadata`, `on_behalf_of`) | compare **canonical JCS bytes** (`regista._jcs.canonicalize`) of the two parsed values. Not raw text (jsonb normalises key order and whitespace). Not Python `==` (which conflates `1`/`1.0` and `True`/`1` where the signed bytes differ). |

The `jsonb` round-trip is safe for this purpose: Postgres stores JSON numbers as `numeric` and
psycopg re-parses to Python `int`/`float`, so re-canonicalising the row value reproduces the
signer's bytes for every value the signer could have produced. The residual risk is exotic
numeric literals; the tool surfaces any such case as a `payload` mismatch rather than silently
passing, which is the correct failure direction.

---

## 7. What the verifier must never do

1. **Never fall back to a rebuilt candidate once a stored envelope exists.** The current
   `verify_event` builds up to six candidate envelopes from row columns and returns `True` on
   the first that verifies (`_signing.py:366-489` and `:491-567`). Because the row-built
   candidates are constructed *from the very columns under attack*, this is the escape hatch
   S1 removes. See RESULT-MODEL §4.
2. **Never take the verification algorithm or the key from the row.** `scheme_id` (§3.2) and
   `hash_alg` (§2.3) both currently do, and `key_id` selects the key.
3. **Never report a v1–v4 event as fully authenticated.** The unsigned set is non-empty by
   construction for those versions.
4. **Never claim `global_seq` or `scheme_id` is authenticated.** In any version.

---

## 8. Entries I am least confident about

Listed explicitly rather than guessed, per the standard for this document.

1. **Whether `work_item_id == entity_id` should be enforced for *all* entity kinds or only
   `entity_kind='work_item'`.** Every writer in 0.5.6 sets them equal, including the segment
   seal, which writes `segment_id` into both columns (`_archive_segments.py:539-542`). So
   universal enforcement is safe *today*. But `031`'s stated intent is a deprecation window
   for `work_item_id`, and nothing in the schema forbids a future non-work-item entity from
   diverging. I have specified the check as universal in the preflight tool but scoped the
   *hard* requirement to `entity_kind='work_item'` in §2.1. **This needs an owner decision
   before implementation.**

2. **Whether a stored v3/v4/v5 envelope containing `global_seq` can exist anywhere outside the
   estate store.** I proved 0/351,371 in the live estate and traced all four sign sites, but I
   cannot rule out a store written by a regista version whose write path did pass `global_seq`.
   I have specified "if present, must reconcile" rather than "cannot be present" to be safe.

3. **Whether any v1 envelope has ever been persisted to `canonical_envelope`.** `v1` predates
   migration 002, which added the column with no backfill — so a v1 envelope in the column
   would have had to be written by an intermediate release. I found no writer that produces
   one (`sign_event` emits only v4/v5), and measured zero in the estate. The matrix specifies
   v1 fully anyway, because the strict classifier must still be able to *reject* something
   that claims to be v1, and because other deployments' history is not in evidence here.

4. **The exact `hash_alg` semantics for v2/v3 events.** `_signing.py:463` hardcodes
   `"sha-256"` for `ver < 4`, which makes the row's `hash_alg` column inert for those
   versions. I am confident that is the *current* behaviour; I am less confident it is the
   *intended* one, since `hash_alg` is NOT NULL on the row and a reader may reasonably assume
   it describes the event. I have specified it as "unsigned and inert for v1–v3".

5. **Whether `payload_canonical_hash` should be reconciled separately.** Both shipped schemes
   already verify it inside `verify` (`_signing_scheme.py:121-123`, `:188-190`), so a separate
   check is redundant *for those schemes* — but the `SigningScheme` protocol
   (`_signing_scheme.py:31-49`) does not *require* an implementation to check it. A
   third-party scheme could ignore `envelope_hash` entirely. I lean toward the verifier
   checking `hash_alg(stored_envelope) == payload_canonical_hash` itself rather than trusting
   the scheme to, but that is a defence-in-depth call for the implementer.

---

## 9. Measured shape of the live estate (evidence)

From `preflight_check.py` against the estate store, all 26 project schemas, read-only:

| Metric | Value |
|---|---|
| Events scanned | 351,371 |
| Envelope v5 | 332,676 (94.7%) |
| Envelope v4 | 18,695 (5.3%) |
| Envelope v1/v2/v3 | **0** |
| Envelope absent or unparseable | **0** |
| Envelopes whose strict class ≠ permissive class | **0** |
| Signature valid (HMAC-SHA256, real key material) | 351,371 / 351,371 |
| Row↔envelope field mismatches | **0** |
| Rows where `work_item_id ≠ entity_id` | **0** |
| Envelopes carrying `global_seq` | **0** |
| Events with `global_seq` in the unsigned set | 351,371 (all) |
| Events with `scheme_id` in the unsigned set | 351,371 (all) |
| Events with unsigned `actor_kind`/`actor_metadata` | 18,695 / 18,693 |

Interpretation for the matrix: every entry in the v4 and v5 columns above is corroborated by
351k real events; the v1/v2/v3 columns are derived from the code alone and have **no empirical
corroboration in this estate**. That is the honest confidence boundary of this document.
