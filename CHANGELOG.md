# Changelog

All notable changes to regista are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **The v6 verifier boundary (P1.7 phase 2), in `regista._verification` and the new
  `regista._v6_referents`.** `verify_event_strict` used to return
  `INVALID`/`envelope_schema_incomplete` for **every** v6 row — clean or tampered — so
  `applicability` carried no information about a v6 event at all. What replaces it is
  `TRUST-DOMAIN.md` §5.10's six-step enrolment-before-use procedure and §5.11's
  exhaustive verdict table, over **presented material**.

  - **Presented material is a new, required input.** §5.10 steps 1-4 are chain
    traversal, so the verifier needs to see other events; §8.4 says it may never fetch
    them. `ReferentResolver` is that input: two members (`resolve_referent`,
    `completeness`), no query surface, no connection. Referents are addressed by **v6
    event hash**, which covers the envelope bytes *and* the signature — so a tampered
    anchor does not resolve to something else, it does not resolve at all.
    Implementations: `StoreReferents` (an open store, claiming completeness),
    `BundleReferents` (deriving its completeness claim from the manifest's
    `since_seq`/`until_seq`), `MappingReferents`, and `NO_REFERENTS` for a caller that
    holds one row. `verify_event_strict(..., referents=...)` has **no default**: a call
    site that cannot say what it presents cannot get a v6 verdict.
  - **Ordering is by chain traversal only** — `chain.previous_project_event_hash`, never
    `occurred_at`, never `global_seq`. The writer's `global_seq` ordering is a
    documented write-time shortcut and is not borrowed here.
  - **§5.11's two absence rows are distinguished by the material's completeness claim.**
    An unresolvable anchor is `UNVERIFIABLE`/`KEY_BINDING_UNRESOLVED` from a
    `contiguous-range` export (absence of evidence, with the missing referent named as
    out of scope) and `INVALID`/`KEY_BINDING_MISSING_FROM_COMPLETE_SCOPE` from material
    that claims completeness (the claim is false — a fact about the artifact). This is
    `TRUST-DOMAIN.md` §9 criterion 15.
  - **`VerificationResult` gains `RESULT-MODEL.md` §10.1's eleven fields** —
    `epoch_position`, `attribution`, `checkpoint_binding`, `unbound_properties`,
    `trust_domain_id`, `trust_root`, `root_governance`, `key_binding`,
    `revocation_status`, `producer_consistency`, plus `key_binding_event_hash` — all
    reported on every result, all in `to_dict()`, with §10.2's invariants enforced in
    `__post_init__` as asserts. `EnvelopeVersion.V6` joins
    `full_authentication_versions`; without it no v6 event could ever be
    `FULLY_AUTHENTICATED` however completely §5.10 succeeded.
  - **`VerificationPolicy` gains the four caller pins** `pinned_project_instance_id`,
    `pinned_trust_domain_id`, `cutover_checkpoint_event_hash` and `producer_policy`, and
    `material_completeness`. All default to "not supplied", and an unsupplied pin
    produces an explicit `unbound_properties` entry rather than a skipped check (§10.2
    invariant 9). `material_completeness` is **tighten-only**: softening a store's
    completeness claim raises, because it would turn §5.11's `INVALID` row into its
    `UNVERIFIABLE` row on request.
  - **Fourteen new `FailureReason` members**, and `TrustedKeySource.TRUST_DOMAIN_LOG` /
    `EXTERNALLY_PINNED`.
  - **§5.9 rule 1 is enforced by raising.** Resolving a v6 event's key through
    `TrustedKeySource.PRINCIPAL_REGISTRY` is "a programming error [that] raises", not a
    degraded result — a degraded result is something a caller learns to tolerate.
  - **A bootstrap event without an external pin is `UNVERIFIABLE`**, per
    `RECONCILIATION.md` Resolution 1 ("bootstrap without an external pin is not a
    bootstrap; it is an unauthenticated first event"). With the trust log presented and
    a pinned domain and checkpoint it is `FULLY_AUTHENTICATED`. An ordinary
    post-genesis event reaches `FULLY_AUTHENTICATED` with `trust_root: bundled_only`,
    which is what unblocks replay over a v6 epoch.

  Consequence for callers: `verify_event_strict`, `verify_event_result`,
  `verify_event_result_with_public_key` and `verify_event` take a `referents` argument,
  and `_bundle._verify_event_signatures` returns a fourth element (the reasons each
  unverifiable signature was unverifiable).

- **`verify_audit_bundle_offline(path, policy=...)`, and bundle key evidence from v6
  acceptance payloads (WI-296).** A bundle now resolves key material from the
  `regista.key-acceptance` / `bootstrap_key_acceptance` objects it already carries —
  §5.8 repeats `public_key` inside them "on purpose … it makes a project bundle
  self-sufficient for key material without making it self-sufficient for trust". The
  rejected alternative was seeding a `principal_keys` row from the genesis payload,
  which §5.9 rule 1 forbids. An operator-registered registry entry still wins where
  both exist: it carries a validity window and a status the payload has no member for.
  `BundleVerificationReport` gains `unverifiable_details`, so a count never travels
  without its reason.

- **The post-genesis v6 ordinary-event writer (P1.7), `regista._v6_writer`.** Genesis
  opened the epoch and then every writer was refused on both sides of it; this is the
  sanctioned path after the boundary. `append_v6_event` constructs all sixteen v6
  members, resolves `signing.key_binding_event_hash` to a **preceding** project
  key-binding anchor (the genesis bootstrap acceptance or a standalone
  `principal_key_accepted`, `TRUST-DOMAIN.md` §5.8), links both the entity and project
  chains by v6 event hash, serializes on the same global-chain sentinel as genesis, and
  validates through `validate_v6_envelope` before any signing.

  It sits behind the two admission checks P1.7 owns, both failing closed with named
  codes and neither having a permissive default:

  - **`WORKFLOW_REGISTRATION_UNRESOLVED`** — an event naming a workflow must reference a
    signed `workflow_registered` event that precedes it and was not retired. A
    `workflow_registry` *row* is mutable operator state and is not a registration.
  - **`PRODUCER_NOT_AUTHORIZED`** — the `producer` block must fall inside the accepted
    key's scopes (entity kind and transition), declare `model`/`model_lineage` null
    together, and use a lineage family from the closed registry. A supplied producer
    policy that contradicts the event is a refusal; an *unsupplied* one is reported
    `policy_not_supplied` and never silently skipped.

  Also new: `KEY_BINDING_UNRESOLVED` (no anchor — the `principal_keys` projection is
  never consulted for a v6 event, §5.11), `V6_ENVELOPE_INVALID`, and
  `V6_CHAIN_LINK_MISSING`.

- **The two project-local acceptance contracts (`TRUST-DOMAIN.md` §5.8).**
  `_trust_log.DEFERRED_TRANSITIONS` assigned `principal_key_accepted` and
  `principal_key_acceptance_revoked` to P1.7 and neither had a parser anywhere: P2.2's
  §5.5 family covers *trust-log* enrolment, not *project-local* acceptance. Without the
  revocation contract, §5.10 step 4 ("no `principal_key_acceptance_revoked` for `A` lies
  between `A` and `E`") had no event shape to look for.

  `validate_key_acceptance_payload` enforces `regista.key-acceptance/v1` exactly,
  including the two cross-field facts that make it evidence: `fingerprint` must match
  the `public_key` bytes it ships beside (§5.8 calls a mismatch "**invalid**, not a
  preference"), and `accepted_by.key_binding_event_hash` may not be null — that field is
  precisely what the withdrawn self-referential first acceptance nulled.
  `validate_key_acceptance_revocation_payload` enforces
  `regista.key-acceptance-revocation/v1`, whose `reason` shares the closed §5.7
  vocabulary rather than growing a second one. New code
  `KEY_ACCEPTANCE_PAYLOAD_INVALID`.

  A revoked acceptance stops being a usable anchor, with §5.10 step 4's own reason code
  `KEY_ACCEPTANCE_REVOKED` — deliberately not `KEY_BINDING_UNRESOLVED`, since "revoked"
  and "never accepted" are different facts. It never falls back to an earlier, broader
  anchor: that would make revocation a privilege escalation.

  The writer additionally cross-checks what the payload validators structurally cannot:
  `accepted_by` / `revoked_by` must **be** the signer (`ACTOR_SIGNER_MISMATCH`), and the
  signing key's anchor must grant `may_accept_keys` (`PRODUCER_NOT_AUTHORIZED`).
  Acceptance authority therefore does not propagate — a standalone acceptance never
  grants it, which is what stops one compromised agent key from minting a population of
  trusted keys.

- **`register_workflow` now appends a signed `workflow_registered` event** once genesis
  has opened the epoch, in the same transaction as the `workflow_registry` INSERT, so
  the row and the signed registration cannot diverge and admission gate 1 has something
  to resolve. Before genesis the behaviour is unchanged. `definition` excludes
  `raw_yaml`, per `RECONCILIATION.md` Resolution 2.

- **A process-level producer identity**, `_v6_writer.resolve_producer`, resolved from
  `REGISTA_PRODUCER_HARNESS` / `_HARNESS_VERSION` / `_MODEL` / `_MODEL_LINEAGE`. The
  producer is a property of the running process, not a per-append argument — making it a
  parameter would invite the self-asserted-string pattern §1.8 exists to remove. Unset
  harness/version is `LOAD_BEARING_FIELD_MISSING` naming the variables; there is no
  default, because an invented harness name would be a signed falsehood.

- **`_datetime_utils.v6_occurred_at` / `parse_v6_occurred_at`** — the single §2.3 lexical
  form, centralised. `datetime.isoformat()` renders **three** fractional digits whenever
  the microseconds land on a whole millisecond and the strict parser rejects it, so the
  defect appears for roughly one instant in a thousand: absent from any hand-picked test
  value, present in production.

- **The shared Ed25519 actor-role test keyset and v6 genesis fixture**,
  `tests/_v6_fixtures.py`. The committed `tests/test_keys.json` is a single HMAC key with
  no `principal_id`, no `role` and no public key, so it cannot satisfy any v6 append;
  `make_v6_keyset` mints one actor-role Ed25519 key per principal, and
  `genesis_envelope` / `acceptance_payload` build the genesis and acceptance events in
  the order Bootstrap A → Bootstrap B → ordinary acceptance requires.

### Fixed

- **System-authored events could not be written in a clean v6 epoch at all.**
  Auto-escalation (`escalated`), hook dead-lettering (`hook_dead_lettered`) and
  recurrence firing were appended with a bare `actor_id="system"` /
  `"system:scheduler"`. Neither is a canonical `(human|agent|service):<subject>`
  principal (`TRUST-DOMAIN.md` §2.1) and neither can hold a key-binding anchor, so the
  v6 writer refused them with `ACTOR_SIGNER_MISMATCH` — three live features broken by
  the v6 route. A system event is now attributed to the project's own bootstrap
  principal, resolved by `_events.resolve_system_actor_id` (and its in-memory twin,
  which shares the same body). This is the attribution `_workflow_api` already used for
  `workflow_registered`, which is why that one call site worked. **Epoch-aware:** a
  legacy project keeps the literal unchanged.

- **Every Ed25519 witness receipt over a v6 event failed verification, silently.**
  `_witness` passed the row's `payload_canonical_hash` as `Ed25519Scheme.verify`'s
  `envelope_hash` while passing the bare envelope as `envelope`. Those coincide for
  v1-v5; under v6 the column hashes the *domain-tagged signature input*
  (`V6-ENVELOPE.md` §5.3), so `compare_digest` failed on every v6 event. The failure was
  invisible because `sig_verified` was unconditionally `False` — which also made the
  negative delivery tests pass vacuously. `verify_witness_countersignature` now
  establishes the two facts separately: that the row's hash column really is the hash of
  its own envelope column (under that envelope's version, via the new
  `_signing.compute_payload_canonical_hash`, which also fixes a second latent bug where
  the row's `hash_alg` was ignored), and that the witness's signature is valid over the
  bytes the delivery body actually carries. **No persisted format changed**; the
  alternative fix would have silently redefined what an external witness must sign, and
  would have given the witness the author's own hash domain tag.

- **The v6 referent resolver was missing from two of thirteen call sites**, both on the
  caller-supplied-public-key path: `_api_meta.verify_event_result` and
  `_in_mem_ops.verify_event_result` (which *built* the resolver and then did not pass
  it). Substituting the key resolver does not change what chain material a v6 verdict
  needs, so both returned `UNVERIFIABLE` for every v6 event — the public
  independent-verification API answering "nothing was checked" while looking like a
  verdict, and a wrong-key negative passing for the wrong reason.

- **The last two resolver-less call sites (P1.7 phase 4).**
  `_signing.verify_event_with_public_key` — the documented standalone verification
  utility (`spec.md` §17.12) — had **no** `referents` parameter, while the
  `VerificationResult` twin it delegates to has taken one since phase 2, so the bool
  shim returned `False` for every v6 event however complete the caller's material was.
  It now takes `referents` with the same `NO_REFERENTS` default as its twin: an offline
  verifier holding a bundle can present it, and a shim less capable than the function it
  wraps is a clamp with a smaller blast radius.

  `verify_event_with_principal_binding` inherited the omission through that shim, and
  its answer was worse than `False`: over a v6 event whose signature is valid and whose
  registry entry holds the very key that signed it, both binding twins reported
  `"signature-verification-failed: signature invalid under all registered public keys"`
  — measured, on two different mechanisms (the object twin read `UNVERIFIABLE` as a
  signature failure; the dict twin tripped §5.9 rule 1's raise and swallowed it). A
  `principal_keys` probe cannot decide a v6 binding at all, so it now says so:
  `V6_BINDING_NOT_DECIDED_BY_REGISTRY`, naming §5.10 and the material as the deciding
  procedure. `NO_REFERENTS` remains the contract for the binding path and deliberately
  **not** a parameter — offering callers material there would offer them a route around
  rule 1 — and the two twins now share one body, resolving through
  `TrustedKeySource.PRINCIPAL_REGISTRY` on both, which is where the key actually came
  from.

- **The v6 verifier boundary defeated WI-217's streaming space bound (P1.7 phase 4).**
  `_replay` builds one `StoreReferents` for the whole replay, and its index retained
  every indexed event's *whole parsed envelope* for the resolver's lifetime — so phase
  2's per-resolver cache was the log materialization `tests/test_wi217_replay_memory.py`
  exists to forbid, arriving through the verifier instead of through replay. Measured on
  an 8x log: peak growth **5.5x** against a 3.0x budget, 19.89 MiB against 5.00 MiB.
  Fixed without relaxing the budget and without making the resolver fetch: the index now
  holds a `ReferentSummary` (the six signed members every referent accessor reads,
  interned, ~0.5 KiB against ~5 KiB parsed) and re-reads an envelope only when a verdict
  reads its `payload` — which in a healthy replay is the trust-plane referents alone.
  `store_referents` also streams its scan through a **server-side** cursor rather than
  `fetchall()`; iterating a client-side cursor would have moved the same bytes into
  libpq's C heap, where tracemalloc cannot see them and RSS can. Re-measured: growth
  **1.61x**, peak **3.36 MiB**. The re-read is addressed by v6 event hash, so it can
  only return the bytes the referent already stood for; material that stops presenting a
  row mid-pass raises the new `MATERIAL_CHANGED_UNDER_VERIFICATION` rather than
  reporting an empty payload, and the materialization memo is bounded so it cannot grow
  back into the cache it replaced.

- **`InMemoryEventStore` never advanced the global chain head a v6 epoch wrote, so two
  of WI-266's fail-closed checks were dead on that backend (P1.7 phase 4).** Postgres
  has one `event_chain_head` row: the writer advances it, replay reads it back. In
  memory there were two — `InMemoryV6Rows.head_hash`, which the v6 writer advanced, and
  `InMemoryEventStore._global_chain_head`, which only the *legacy* `append` ever wrote
  and which is the one `_in_memory_replay` reads. So after `open_v6_epoch` plus real v6
  appends the head replay consulted was still `None`, and both "head set, log empty"
  (a wholesale-deleted log) and "head disagrees with the chain tail" (a tampered head or
  a deleted tail event) were **unreachable in memory** while Postgres detected them
  correctly. The two are now one piece of state, which is the parity discipline rather
  than a second advance: nothing is copied, so there is no window in which they disagree.
  This is the second parity hole measured after the chain-formula one above.

- **`_verification` and `_replay` disagreed about a nulled `canonical_envelope`, and now
  agree — fail-closed (P1.7 phase 4).** `verify_event_strict` reported
  `UNVERIFIABLE`/`ENVELOPE_ABSENT` ("nothing failed, there is nothing to check") while
  `_replay`, on the *same row*, halted with "the row contradicts its own cryptographic
  material" — reached through `AbsentEnvelopeProbe`, which rebuilds only the v1/v2 shapes
  `CUTOVER-POLICY` §4.1 enumerates and therefore never matches a v6 row at all. So a
  caller of `verify_event_result` got the weaker of the two, and the stronger one rested
  on a reconstruction never attempted for the version in question. Resolved on the
  **presented material** instead: a row whose chain predecessor is presented as a v6
  event stands inside the v6 epoch, where the stored bytes are the artifact
  (`V6-ENVELOPE.md` §9.2) and every append writes them, so the NULL is destruction and
  the verdict is `INVALID`. Nothing is reconstructed, no signature is re-derived, and
  with `NO_REFERENTS` the verdict is still `UNVERIFIABLE` — the conviction is a property
  of what was presented, never of the absence. `AbsentEnvelopeProbe` stays
  `_replay`-only for v1-v5 rows, which the material cannot speak about.

- **Both in-memory hash-chain walks used the v1-v5 head formula**, so no v6 event was
  reachable from genesis and a *healthy* in-memory v6 epoch reported one chain break per
  post-genesis event. The chain half of WI-287's parity claim was measurably false and
  nothing had asserted it. The formula now lives once, at
  `_signing.compute_chain_head_hash`, with `_replay` and all three in-memory sites
  delegating — the third recurrence of "a version-aware formula hand-copied per call
  site is version-aware at some of them" (mutation M20 was the second).

### Changed

- **`replay()` no longer reports a healthy clean-epoch chain as seven warnings.** The
  five spec-legal non-`work_item` entity kinds from the CLOSED §1.2 registry are counted
  in the new `ReplayReport.non_work_item_groups_verified` — a v6 chain necessarily
  carries `project`, `principal` and `workflow` groups, so their presence is the
  ordinary case and is neither a halt nor a warning. An entity kind **outside** the
  closed registry now **halts**, fail-closed: previously "not a work item" bought the
  tolerance, now five named values do. One entity id carrying several kinds also halts
  rather than being read as either. The closed registry itself was hand-copied in three
  modules and is now `_verification.V6_ENTITY_KINDS`, imported.

### Changed — BREAKING

- **Clean v6 project genesis:** fresh schemas now carry nullable workflow identity
  and a `project_identity` projection. `write_genesis()` requires an explicit
  passed conformance gate, complete load-bearing fields, an active Ed25519 actor
  key bound to the envelope principal, and bootstrap acceptance. The write is
  serialized behind the chain sentinel and is recoverable through the read-only
  `read_genesis()` API; legacy writers are refused before and after the v6 epoch.

- **Review findings no longer require reviewer independence (WI-284):** canonical
  workflow v3 marks `request_changes` as `finding_only`, so any actor may return
  an item to `in_progress` when it supplies a substantive review note. Positive
  `adversarial_pass` verdicts retain separation-of-duties and lineage checks.
  Persisted canonical v1/v2 items receive the same negative-finding semantics.
  Transitions whose declared validator is unavailable now fail closed with
  `VALIDATOR_NOT_REGISTERED` instead of executing without validation.

- **Signature verification authenticates the row, not just the envelope
  (WI-267):** `verify_event()` verified the stored `canonical_envelope` bytes
  and returned as soon as they verified. Only `actor_kind`/`actor_metadata`
  were reconciled against it, and only on v5 (WI-208). Every consumer then read
  the **unsigned row columns**, so an attacker with database write access could
  rewrite `transition`, `payload`, `timestamp`, `event_seq`, `prev_event_hash`,
  `prev_global_event_hash`, `on_behalf_of`, `key_id`, `entity_id`,
  `entity_kind` or `workflow_name`/`workflow_version` in the row and everything
  still reported "verified" — measured: 13 of 14 single-field row rewrites
  verified clean before this change.

  The rule is now: **the stored canonical envelope is the cryptographic
  artifact; the row is its indexed projection.** The exact stored bytes are
  verified, then every field that envelope version signs must agree with its
  row representation before any consumer uses the row.

  What lands with it:

  - **One verification primitive.** `regista._verification.verify_event_strict`
    returns a structured `VerificationResult` — envelope version and schema
    validity, signature validity, trusted-key source, row reconciliation and
    the *names* of any mismatched fields, authenticated vs unsigned field sets,
    and an applicability of `fully_authenticated` / `legacy_partial` /
    `invalid` / `unverifiable`. It replaces the incompatible result
    vocabularies that replay, the offline bundle, segments and the API each
    used. `_bundle.py` no longer carries a second, independent verifier.
  - **Strict envelope parsing.** The classifier used `issuperset`, so *any
    subset* of a version's fields — including `{}` and an attacker-authored
    object — fell through to "v1", the weakest possible claim. Unknown schemas
    are now rejected (`classify_envelope_version` returns `0`).
  - **No fallback.** Once a stored envelope exists it is the only envelope. A
    parse, signature or reconciliation failure is `invalid`; no candidate is
    rebuilt from the row columns under attack. `verify_event(stored_envelope=None)`
    is `unverifiable`, not "rebuild and try" — reconstructing a missing
    envelope is an explicit offline operator action.
  - **The signing scheme comes from trusted key metadata, never the row**
    (S2-interim). `scheme_id` is outside every envelope version. Three sites
    are closed: verification dispatch (a row claiming `hmac-sha256` against an
    ed25519 registry key is now an error), replay's principal-binding
    requirement (a row could opt itself out by relabelling), and the
    key-id-must-match filter in principal binding.
  - **`work_item_id == entity_id` is enforced** wherever both are present.
    `entity_id` is the signed identifier from v4 onward; `work_item_id` is the
    original column and carries no signature of its own.
  - **`global_seq` remains unsigned by design** (assigned post-signing, §17.11)
    and can never appear in `authenticated_fields`. A `global_seq` rewrite is
    not reported as a mismatch.
  - **The InMemory backend runs the same reconciliation**, so the two backends
    cannot disagree about what "verified" means. Its keyless mode reports
    `unverifiable` / `unsigned_event` rather than being pushed through the
    strict verifier as a malformed signed event — and a *Postgres* row showing
    the keyless byte pattern stays `invalid`, because the exemption is a
    property of the backend, not of the bytes.
  - **`BundleVerificationReport.verified` now requires
    `signatures_verified > 0`.** A bundle in which every signature was
    unverifiable reported `verified=True` provided `errors` was empty — that is
    "nothing was checked" reported as "everything checks out". **An HMAC-only
    bundle is therefore no longer `verified`:** verifying an HMAC needs the
    secret, which a bundle deliberately never carries, so such a bundle proves
    internal consistency and nothing cryptographic. `regista bundle export`
    against an HMAC store now exits `3` unless `--allow-unverified` is passed,
    and both `bundle export` and `bundle verify` say why. Splitting the verdict
    into internally-consistent / authenticated-to-an-external-root is separate
    work (S3/S5).

  Follow-ups from the cross-lineage review of the same work item:

  - **A NULL column no longer reads as the signed value.** `entity_id` was
    compared through a `work_item_id` fallback and the alias check exempted
    NULLs, so `UPDATE events SET entity_id = NULL` (the migration-031 trigger is
    BEFORE INSERT, so it does not re-fire) verified clean *and reported
    `entity_id` as authenticated*. `EventRow.from_mapping` did the same for
    `hash_alg` and `entity_kind` via `or <default>`. All four now mismatch.
  - **Keyless InMemory replay reports what it did not check.** A genuine
    keyless event is `accepted` under `accept_unsigned_keyless`, so the branch
    meant to report it never fired and the replay was silent.
  - **`ReplayReport.unverifiable`** is a new first-class counter, deliberately
    *not* folded into `warnings`: "there is nothing to verify" and "something
    that should have verified did not" call for different operator responses.
    `regista replay` prints it and names the log events to grep for
    (`replay.event_envelope_absent`, `replay.event_unverifiable`,
    `replay.keyless_no_signatures_verified`).
  - **Deleting an envelope is no longer a way out.** `UPDATE events SET
    canonical_envelope = NULL` followed by a row rewrite halted replay *before*
    this work (the rebuild-from-row candidate failed its signature check) and
    would have been fail-open after it. `probe_absent_envelope` asks whether
    the retained `signature`/`payload_canonical_hash` can be reconciled with the
    row by any shape a genuinely pre-002 row could have carried (v1, v1 without
    `on_behalf_of`, v2 — CUTOVER-POLICY §4.1). If none can, replay halts. The
    probe **convicts only**: `verify_event_strict` never calls it, its
    `CONSISTENT`/`UNKNOWN` outcomes change no verdict, and no path turns any of
    its outcomes into a pass — that asymmetry is what keeps it from being the
    rebuild-from-row escape hatch this work deleted.

  **Interaction with WI-266.** `chain_breaks` and `unverifiable` are three-way
  distinct from `warnings` and from each other: a chain break is a detected
  tamper (exit non-zero), `unverifiable` is "nothing was checked at all" (an
  evidentiary gap — reported loudly, does not by itself fail the exit status).
  Where both fire on the same event — a rewritten `prev_event_hash` is a broken
  chain link *and*, from envelope v3, a signed-field mismatch — both are
  reported: `_ReplayHaltError` now carries the counters accumulated before the
  halt so a per-work-item halt cannot silently erase the chain-walk finding on
  its way out.

  **Compatibility.** A read-only preflight over the live estate (351,371
  events, 26 project schemas) found **zero** row↔envelope mismatches, zero
  missing envelopes and zero unknown schemas: 94.7% v5, 5.3% v4, no v1/v2/v3.
  No migration and no re-signing is required there. v4 events verify as
  `legacy_partial` with `actor_kind`/`actor_metadata` listed as unsigned;
  events with no stored envelope are `unverifiable` and are reported by replay
  rather than halting it. **Envelope versions v1/v2/v3 are `invalid` under the
  shipped default policy** (`accept_legacy_versions={v4}`) — a deployment
  carrying such history must widen `VerificationPolicy.accept_legacy_versions`
  explicitly. Rewriting a *signed* row field now halts replay where it
  previously produced a warning or nothing at all.

  `spec.md` §17.9 and §17.9.2 are corrected: they still described
  `actor_kind`/`actor_metadata` as absent from the signing envelope, which v5
  falsified.

### Added

- **Witness public keys enrolled in the anchored key registry (WI-238):**
  An Ed25519 witness's public key is now enrolled into the `principal_keys`
  registry under the `witness:<witness_id>` principal at registration time
  (counterpart to cairn BC-016), so downstream verifiers can treat witness
  keys as a pinned trust root rather than the unverified
  `witness_registrations.public_key` column. The lifecycle mirrors principal
  keys: `rotate_witness_key` supersedes + activates atomically;
  `unregister_witness` revokes (the revoked key stays for history);
  `enrolled_witness_key(witness_id)` reads the active anchored entry; the key
  is also reachable via `principals.get_active("witness:<witness_id>")`.
  `regista doctor` adds a per-project `witness:key_enrollment:<project>`
  check that warns on an enrollment gap or pinned-key mismatch. The InMemory
  backend mirrors the same lifecycle.

## [0.5.5] — 2026-08-01

### Added

- **Vault AppRole login — an AppRole-only host is now possible (WI-228):**
  `VaultProvider` authenticated with `VAULT_TOKEN` and nothing else, so the
  posture agent-suite `docs/secrets-vault.md` §6 requires — a production host
  operating with **no `VAULT_TOKEN` in its environment** — was unreachable. The
  Linux platform qualification could not achieve it and wrote an undocumented
  wrapper script (`/usr/local/sbin/with-vault-approle`) that minted a 1h token
  per invocation, correctly labelling it a compensating control rather than
  evidence. Because that shim lived outside any generated systemd unit,
  systemd-launched services never got a token at all — which is why
  `cairn integrity` executed but exited 1, and dossier's `/healthz` returned 503,
  on that host.

  The resolver now authenticates by AppRole (`role_id` + `secret_id`) or by a
  static token, declared through the environment:

  | Variable | Meaning |
  |---|---|
  | `VAULT_ROLE_ID` / `VAULT_ROLE_ID_FILE` | AppRole RoleID, inline or from a file |
  | `VAULT_SECRET_ID_FILE` | File holding the SecretID — **preferred**, and where response-wrapped delivery lands it |
  | `VAULT_SECRET_ID` | SecretID inline (discouraged: readable from `/proc/<pid>/environ`) |
  | `VAULT_SECRET_ID_RESPONSE_WRAPPED` | `1` when the file holds a single-use response-**wrapping** token, which the host unwraps for itself (`docs/secrets-vault.md` §5) |
  | `VAULT_APPROLE_MOUNT_POINT` | AppRole mount, default `approle` |
  | `VAULT_ENV_FILE` | env-style plane file to read `VAULT_*` from; the process environment overrides it |
  | `VAULT_TOKEN` | static token, dev only — kept so `vault server -dev` walkthroughs still work |

  **One credential format across components.** acb provisions AppRoles and writes
  a mode-0600 env-style "plane file" carrying `VAULT_ADDR`, `VAULT_ROLE_ID` and
  `VAULT_SECRET_ID` (agent-capability-broker PR #20). Those are the same names
  this resolver reads, and `VAULT_ENV_FILE` points it at that file, so an operator
  who onboards a capability with acb and then runs a regista-backed component has
  one credential file rather than two incompatible ones. Precedence matches acb's
  `_authenticate` (AppRole before token) so the same file cannot authenticate as
  different identities depending on which component read it. Provenance is
  reported as `plane:VAULT_ROLE_ID` rather than `env:` for values that came from
  the file. Two deliberate divergences are documented in `docs/suite-config.md`:
  regista fails closed on partial AppRole material where acb falls through to
  `VAULT_TOKEN` (the strict reading is the one to converge on), and
  `VAULT_SECRET_ID_FILE` is retained because a plane file cannot express a
  single-use response-wrapping token.

  **No ambient credentials.** The client is constructed with `token=""`, not
  hvac's default `token=None` — which makes hvac call `get_token_from_env()` and
  silently pick up `$VAULT_TOKEN` *and* `~/.vault-token`. A stray `~/.vault-token`
  can no longer make an unconfigured host appear to work, and "this host carries
  no ambient token" is now structural rather than a property of statement
  ordering. (acb guards its privileged admin plane the same way; its runtime
  `cred_vault` path does not yet, which is reported upstream rather than worked
  around here.)

  Three properties the qualification found missing:

  - **The method is reported, so a host cannot silently sit on the weaker one.**
    New `regista.secrets.vault_auth_status()`, `regista secrets --auth-status`
    (`--json`, plus `--probe` to actually authenticate and exit 1 if it fails),
    a `vault_authenticated` structlog line at login, and a new doctor row
    `custody:vault_auth` — `ok` for AppRole, `warn` for a static token (the dev
    posture), `fail` for AppRole material that is present but unusable. The
    report names where each credential *came from*, never its value, so it is
    safe to print and log.

  - **A network failure is told apart from a credential refusal.** A
    `ConnectTimeout` used to be reported as "the SecretID expired or ran out of
    uses — issue a new one", sending an operator to rotate a credential nothing
    had been able to present. Found while validating on the qual-linux container,
    which has no outbound network.

  - **It fails closed.** Any AppRole variable being set means AppRole was asked
    for; `VAULT_TOKEN` is then never consulted. Half-configured material, a
    missing/empty/unreadable SecretID file, a spent wrapping token, and a
    rejected login each raise an actionable error naming the variable or path to
    fix and the command to re-deliver with. Falling back to the dev method would
    turn a broken production posture into a working dev one without saying so.

  - **A long-running process no longer wedges when the lease expires.** The
    client used to be cached for the process lifetime while the token behind it
    had a lease. It now re-authenticates before the lease runs out, and again if
    a 403 turns out to be a dead token rather than a policy denial — the two are
    distinguished by checking whether the token still validates, so a genuine
    denial is reported immediately instead of driving a login loop, and an
    expired lease is recovered from instead of being misreported as a
    permissions problem. A static token cannot be renewed from nothing, so its
    expiry is reported rather than papered over. Verified against the real Vault
    with a 60s `token_ttl`: one provider held across the boundary resolved
    correctly on both sides, re-authenticating once.

### Fixed

- **Bundle chain verification did not verify a v6 chain at all.**
  `_bundle._hash_event` computed `sha256(envelope || signature)` unconditionally, but a
  v6 chain links on the domain-tagged `compute_v6_event_hash` (`V6-ENVELOPE.md` §6.1),
  so for a v6 bundle **no link resolved**. The consequence was silence rather than a
  false alarm: `_verify_global_chain` treats an event whose predecessor is absent from
  the set as a legitimate *bridge point* (a windowed export starts mid-chain), so with
  every link unresolvable every event became an entry point, was immediately its own
  tail, and the function returned `ok=True` **vacuously** — the chain was not checked
  and the report said it was. `_hash_event` is now version-aware.

  Two notes for whoever picks up bundle v3 (P3.3). First, the vacuous-bridge-point
  behaviour is *still there* and is independent of this fix: a bundle whose links are
  all broken for any other reason still reports `global_chain_ok`. Second, the
  genesis-era fixtures could not have caught this — the epoch-opening ceremony writes
  one event per entity, so the per-entity chain check (which does fail loudly) had
  nothing to check. The regression test now builds an entity with two events on purpose,
  and asserts the hash formula at the primitive as well as through the report.

- **`hvac` failures now arrive as the error envelope, not a traceback
  (WI-229b, WI-226):** `regista secrets --ref` caught only `RegistaError`, so
  `hvac.exceptions.Forbidden` escaped as a raw traceback with **zero bytes on
  stdout** — a `--json` consumer had nothing to parse. Every Vault failure is now
  mapped: 403 to `SECRET_RESOLVE_FAILED` with the policy capabilities to grant,
  an absent path to `KEY_LOAD_ERROR` restating that the ref's field comes last,
  and anything else to a typed error. Only the exception's *type* is reported,
  never its text, so a backend message cannot carry secret material into the
  envelope (CLI contract §3). This path gets busier once AppRole is in use, not
  quieter: a 403 is exactly what a scoped policy produces when a ref reaches
  outside it.

  Also fixed in the same area: `secrets --delete` against Vault answered
  `except Exception: return ALREADY_ABSENT`, so a **permission denial was
  reported as a successful deletion** — telling an operator running an
  offboarding that the key was gone when the read had been refused and nothing
  was looked at. Only a genuinely absent path is now `already_absent`.

- **`--json` verbs exited 0 while their body reported failure (WI-229a):**
  `regista provision --json` exited 0 with `{"error": "permission denied to
  create role", "service_role_created": false}`, so every consumer that trusted
  the exit code read a failed provision as success — which is how
  `agent-suite bootstrap` reported `bootstrap: OK` over a provision that never
  created the service role. In each case the `sys.exit(1)` sat inside the
  `else:` of an `if args.json:`, making it unreachable in JSON mode. Auditing
  every `--json` path found the same shape on four verbs, all now fixed:
  `provision`, `provision-principal`, `bundle verify` and `archive
  verify-chain`. `archive verify` was worse — it exited 0 in **both** formats
  while printing `FAILED` and its errors — and now matches its sibling
  `bundle verify`.

  The machine-readable channel still carries the machine-readable answer: the
  body stays on stdout, where CLI contract §3 puts it and where
  `agent_suite.component_result.evaluate_component_result` reads it. A one-line
  human diagnostic is now *also* written to stderr on every error path, because
  under `--json` a downstream stderr-only parser previously saw nothing at all.
  Partial success picks a side: any failed project fails the verb.

  A regression test asserts the structural cause, not just the symptom — it
  parses each handler's AST and fails if a `sys.exit` is reachable only when
  `--json` is absent.

- **`REGISTA_KEY_PATH` was ignored by the CLI (WI-229c, WI-225):** `_resolve_config`
  read only the legacy alias `REGISTA_HMAC_KEY_PATH`, never the canonical
  `REGISTA_KEY_PATH` that `_config.CANONICAL_VARS`, every runbook and
  `suite.env` actually use. `principal enroll` therefore dropped the variable an
  operator had set, while `doctor` — which goes through `_config.resolve` —
  honoured it. Both names are now read, canonical first, matching
  `_config.resolve`'s precedence; an explicit `--hmac-key-path` still wins. The
  helper is shared, so `replay` and `principal list` (filed separately as
  WI-225) are covered by the same fix.

- **regista's own docs printed an unresolvable `vault:` ref:**
  `docs/suite-config.md` showed `vault:secret/data/regista/key`, which names a
  mount this estate does not have and mixes in the raw KV v2 API path. Replaced
  with a working shape, plus an explicit note on the three ref-shape traps: the
  `#field` form silently resolves a *different, neighbouring* secret rather than
  failing, there is no default mount, and `vault:` refs resolve only in a process
  where `hvac` is importable.

- **Principal binding was reported, not verified (WI-223):** a work item's
  entire chain could be signed by an Ed25519 key that its project never
  registered, and four surfaces reported green — `regista replay`
  (`principal_binding_failures=0`), `cairn integrity` (`[OK]`), `regista doctor`
  (`custody:consistency`), `agent-suite doctor` (exit 0). Only
  `regista bundle verify` caught it, rejecting every event with "No public key
  for key_id ... in bundle registry". Measured on the qual-linux platform
  qualification host: four `qual-agent` events in `qual_linux.events` signed
  with `pk_e6c7…`, which is active only in `agent_provenance.principal_keys`,
  while `qual_linux.principal_keys` names `pk_1a9a…`.

  Four separate defects, all in the direction of a false green:

  - **`principal_binding_failures=0` was printed by runs that never checked.**
    The binding check was opt-in via `--verify-principal-binding`, but the
    counter was printed unconditionally, so a plain `regista replay` published
    an affirmative "the binding was verified, nothing wrong" for a chain it had
    not examined. The check is now **on by default** in the CLI
    (`--verify-principal-binding` is a retained no-op,
    `--no-verify-principal-binding` opts out), and `ReplayReport` gained
    `principal_binding_verified: bool`. A zero count is only serialized when
    the check actually ran; when it did not, `principal_binding_failures` is
    omitted from the JSON entirely and the text output says
    `principal_binding=not-verified`. `InMemoryRegista`'s replay has no
    `principal_keys` registry and so always reports the binding as unverified,
    matching the no-op warning it already emitted.

  - **Replay collapsed "no keys for this actor" into "key belongs to another
    project".** `_replay_work_item` skipped the binding check whenever the actor
    had no rows in `principal_keys` — correct and documented for HMAC-only
    deployments, but it also silently skipped Ed25519 events whose signer this
    project never registered at all (reachable by provisioning a principal in
    project B and then writing to project A with the same key file). The two
    are now distinct: an event using a **symmetric** scheme whose actor has no
    registered keys is still skipped (HMAC-only backward compatibility is
    unchanged and tested); an event using an **asymmetric** scheme whose actor
    has no registered keys is an unregistered signer and fails.

  - **`provision-principal` silently created the collision.** `keys.json` is
    shared across projects while `principal_keys` is per-project, so
    provisioning the same principal in a second project minted a second keypair,
    appended it to the same file, and demoted the first to `deprecated` — after
    which the signer, which selects by `principal_id` with no project scoping,
    signed the *first* project's events with a key only the second project had
    registered. It now refuses, and `--reuse-existing-key` registers the
    existing public key in the additional project instead (no new keypair, no
    key-file mutation) as the supported way for one principal to act in several
    projects. The signer's selection rule is now a single pure function,
    `regista._keys.select_signing_key_id`, so callers that reason about which
    key will sign cannot drift from `KeySet`.

  - **`regista doctor` never checked registration at all.**
    `custody:consistency` only compares `secret_ref` custody prefixes against
    the configured backend; its old detail line ("N principal key(s) match
    backend file") read as a statement about the registry and is now explicit
    that it is not. The real claim lives in a new `custody:registration` check:
    for every principal a project has registered keys for, the key the signer
    would select from the key file must be active in that project's
    `principal_keys`. It fails on the qual-linux state, which also turns
    `agent-suite doctor` red, since that folds each component's top-level `ok`.

  `cairn integrity` is **not** fixed by this change: it calls `replay()` through
  the Python API (whose default stays opt-in for compatibility) and derives its
  verdict from `replayed_drift`/`halted` only, ignoring
  `principal_binding_failures`. Filed as agent-provenance WI-036. A related
  reporting inaccuracy in agent-suite's `verify_restore` (which now catches the
  condition via `warnings` but attributes it to "possible chain-link tampering")
  is filed as agent-suite WI-051.

- **Encryption key material now decodes per an explicit contract (WI-231):**
  a 256-bit key stored in a text backend (Vault KV field, env var, literal)
  necessarily arrives encoded, and nothing decoded it — the only working keys
  were strings whose UTF-8 bytes happened to number 32, and a
  correctly-provisioned 43-char base64url key was rejected at first use with a
  bare byte count. `decode_key_material()` applies the contract at load time:
  exactly 32 raw bytes are the key itself; otherwise ASCII text decoding to 32
  bytes as base64/base64url (padding optional, whitespace tolerated) or 64 hex
  chars; anything else raises `KEY_LOAD_ERROR` naming the accepted encodings
  and the ref it came from. The interpretations cannot collide (64 base64
  chars decode to 48 bytes, never 32). Applies to `encrypt_fields` and both
  `decrypt_fields` key sources, so the vault/azure `store()` paths — which
  already base64-encode on write — finally round-trip.

- **`claim_acquired` events now carry the claimer's declared lineage
  (WI-224):** the claim ops hard-coded `actor_metadata=None`, so an agent's
  claim set `agent_author_undeclared` permanently and the cross-lineage
  adversarial gate rejected every reviewer on any ever-claimed item.
  `acquire_claim`/`heartbeat_claim`/`release_claim` accept optional
  `actor_metadata` using the authoring ops' idiom, on both backends and the
  sidecar. Claim transitions still count the claimer as having worked the
  item (separation of duties is preserved), and chains recorded without the
  field verify exactly as before.

- **The documented 64 KB `actor_metadata` cap is now enforced (WI-234):**
  `validate_actor_metadata` existed with zero call sites, so the effective
  limit was the generic 1 MiB JSONB bound while spec.md promised 64 KB.
  `validate_mutation_params` now applies it at every metadata-accepting write
  path, including the claim ops. New writes only; recorded events are
  unaffected.

- **`ConnectionPool` is closed before interpreter finalization (WI-218):**
  nothing registered the pool's close for process teardown, and on Python
  3.14+ `ConnectionPool.__del__`'s thread join raises
  `PythonFinalizationError` once finalization has begun — every short-lived
  CLI invocation printed a traceback on exit. A `weakref.finalize` hook now
  closes the pool in the atexit phase and detaches on explicit `close()`.

- **The WI-228 doctor/CLI tests are hermetic against a configured host
  (WI-232):** the test fixtures cleared most Vault plane variables but missed
  `VAULT_ENV_FILE` and `VAULT_APPROLE_MOUNT_POINT`, so the suite failed on
  any host set up per `docs/secrets-instantiation.md` — the doctor under test
  read the host's real AppRole material instead of the fixture's intent.

- **Full replay no longer materializes the event log (WI-217):** `replay()`
  loaded every event row for the project in a single `fetchall()`, so its peak
  working set scaled with the log — ~2 GiB on the production estate, which the
  allocator then never returned to the OS (a dossier container measured 102 MiB
  → 2.09 GiB → 4.07 GiB across two rounds). The retention is not a leaked
  reference: tracemalloc shows ~0 net retention across successive replays and
  `malloc_trim(0)` hands the memory straight back, so the fix is to never reach
  the peak. Events are now streamed one entity at a time through a server-side
  cursor, and the global hash-chain walk consumes compact link records (event
  id, `global_seq`, previous link, precomputed head hash) rather than full event
  rows, so each event's envelope, signature and payload are released with its
  entity's group. Measured on a 10k-event log: per-replay peak 184.9 → 8.1 MiB,
  RSS growth over three successive replays 464 → 24 MiB.

  The streamed scan is ordered on `(entity_kind, entity_id, event_seq)` — the
  columns of `idx_events_entity` — and that is load bearing rather than
  cosmetic. `DECLARE CURSOR` over a plan containing a Sort makes Postgres
  materialize the whole sorted result before yielding row one and hold it in
  `pgsql_tmp` for the cursor's entire lifetime, which streaming extends from
  the duration of a `fetchall()` drain to the duration of the whole replay.
  Measured on a 6000-row / 8.3 MiB events table: ordering on `work_item_id`
  (for which migration 031 dropped the index) plans as `Sort → Seq Scan` and
  parks 6.1 MiB of `pgsql_tmp` after a single FETCH; the index ordering plans
  as `Index Scan` and uses none. Deployments with `temp_file_limit` set are
  therefore unaffected. Two costs remain and are bounded rather than removed:
  the fetch block is 100 **rows**, so its byte cost rises with payload width,
  and the compact chain index is ~55–105 MiB at 227k events depending on
  accounting (see `_EVENT_STREAM_SIZE`).

  `regista.testing.replay_fn` previously required the caller's connection to be
  inside a transaction, because a named cursor cannot be declared in autocommit
  mode; it now opens one itself when handed an autocommit connection.

  Scope: this covers the Postgres backend. `InMemoryRegista`'s replay has its
  own chain walk (`_verify_global_hash_chain_in_memory`) which is unchanged and
  is not equivalent — it has no orphan-reachability check, no multiple-genesis
  warning and no segment bridging — so the tamper-detection equivalence
  asserted here is a property of the Postgres path only.

## [0.5.4] — 2026-07-29

### Added

- **Durable principal lifecycle (Plan 031):** enrollment, rotation, and
  revocation operations survive process restarts and cross-instance handoff via
  Postgres rehydration. Schema 44 adds challenge-kind and approval-evidence
  fields; durable challenges are database-authoritative, single-use, and
  consumed atomically with the corresponding operation transition or receipt.
  `describe()` covers all lifecycle states exhaustively (`assert_never`).

- **Client signer (Plan 031 §5):** `client_signer.py` — out-of-process Ed25519
  signing helper. Generates keypairs, custodies private keys via the existing
  secret backends, and signs possession/effective-use challenges without
  exposing private material. CLI: `regista signer generate /
  sign-possession / sign-effective`.

- **Signed effective receipts:** the post-commit effective-use signature binds
  the full challenge, client type/version, status, and observed timestamp.
  `record_effective_receipt` verifies binding, chronology, expiry, single-use,
  and Ed25519 before accepting an EFFECTIVE receipt. Invalid or proof-less
  reports cannot burn a challenge.

- **Approval verification and separation of duties:** `ApprovalVerifier`
  protocol with `verify_approval(operation, approval)` hook; `record_approval`
  enforces that the approver is distinct from the requester (separation of
  duties) and optionally verifies evidence sufficiency.

- **Secrets delete (offboarding):** `secrets.delete(ref)` with tri-state return
  (`DELETED` / `INLINE_REF` / raises). File/Vault/Azure remove stored material;
  Windows/literal report inline (nothing stored to remove); env raises. Vault
  rewrites shared paths rather than destroying unrelated keys; Azure purges
  after soft-delete. CLI: `regista secrets delete`. Idempotent.

### Changed

- **Replay principal-binding enforcement (opt-in):**
  `replay --strict-principal-binding` exits non-zero when
  `principal_binding_failures > 0`. Default behavior unchanged (warnings, not
  halts) for backward compat with HMAC-only deployments. `ReplayReport` gains
  `principal_binding_failures` count.

- **Bundle signature honesty:** when the offline verifier enforces signature
  checks but verifies zero signatures (all HMAC/unverifiable),
  `signature_check` reports `enforced_none_verified` instead of `enforced`.

### Fixed

- **Durable lifecycle correctness:** operations persisted to Postgres but
  previously read only from in-memory dict — prepare-on-instance-A +
  commit-on-instance-B (or after restart) failed with `OPERATION_NOT_FOUND`.
  Fixed via DB rehydration with exact `compare_digest` match. Revocation gate
  unified to require `APPROVED` (previously rejected correctly-approved
  revocations). Cross-instance commit idempotency authoritative via DB
  `SELECT...FOR UPDATE`.

### Chore

- **Adopted ruff 0.16** (expanded default rule set).

## [0.5.3] — 2026-07-20

### Changed

- **Library logging defaults to stderr** unless the embedding application
  configures structlog (Plan 018 P0). This keeps stdout a clean single-document
  channel under `--json` for CLI consumers; an app that configures its own
  logging still wins. Root cause of a downstream consumer's stdout-pollution
  bug (agent-notes WI-019).

### Fixed

- **CLI errors now emit the contract v1 error envelope** on every error path
  (`{"ok": false, "error": {"code", "message", "detail", "retryable",
  "partial"}}` as the single `--json` stdout document; exit 1). No path prints
  an error and exits 0. (Plan 018 P0)
- **No uncaught tracebacks on documented error paths** (CLI contract §5): a
  top-level `RegistaError` boundary in `main()` reports any domain error that
  escapes a command handler (e.g. a failure while constructing `Regista()`)
  through the envelope, and `workflow validate` on a missing file reports an
  `INVALID_ARGUMENT` envelope instead of a `FileNotFoundError` traceback.

### Added

- **CLI contract v1 conformance kit adopted in CI** (`tests/test_cli_conformance.py`),
  consumed pinned from the agent-suite `agent_suite.conformance` package. CI
  test matrix moved to Python 3.13/3.14 (the kit requires ≥3.12).

## [0.5.2] — 2026-07-19

### Fixed

- **Version introspection survives the regista-hraedon rename:** `_installed_version()`
  in `_integrity.py` now tries both `regista-hraedon` and `regista` distribution
  names when resolving `REGISTA_VERSION` via `importlib.metadata`. Previously,
  `importlib.metadata.version("regista")` raised `PackageNotFoundError` on installs
  from the renamed PyPI distribution, breaking workflow compatibility checks.
  Consumers that pinned `regista-hraedon` from PyPI (e.g. dossier's container image)
  no longer need a build-time patch to fix the lookup.

## [0.5.1] — 2026-07-19

### Added

- **Public secret resolver contract:** added the stable
  `regista.secrets` facade (`API_VERSION = 1`) with typed errors, resolution,
  provider discovery, and strict non-resolving reference validation for
  provider-neutral consumers.

- **Plan 029 (Backend-aware principal key custody):** `secrets.store(ref, data)` write-side protocol on every `SecretProvider` (`file`/`windows`/`vault`/`azure` writable; `env`/`literal` raise `SECRET_WRITE_UNSUPPORTED`). New `_custody.py` shared helper extracts the keypair-generate → backend-write → ref-record sequence; `provision_principal`/`enroll_principal` no longer hardcode `file:`. Backend selected via `REGISTA_SECRET_BACKEND` (or `--secret-backend`); `private_key_dir` is meaningful only for `file`. Operator-writes seam (`operator` backend) raises `SECRET_WRITE_EXTERNAL` — enrollment fails loud, never silently falls back to disk. Key-file entries record `encoding: base64` for vault/azure (raw bytes base64-encoded on store; `_keys.py` decodes on resolve). `regista doctor` gains a `custody:consistency` check that warns when a principal's recorded `secret_ref` scheme doesn't match the configured backend. CLI `provision-principal`/`principal enroll` accept `--secret-backend`. 29 new tests.

- **Plan 028 (Event-log retention & segment sealing):** `event_segments` table (migration 039) records sealed contiguous ranges of the global event chain. `sub.archive.seal(before_timestamp)` verifies global and per-work-item hash chains, signs a `segment_sealed` event, and stores the segment seal. Replay bridges across sealed ranges via `first_event_prev_hash` / `head_hash`, so older events can be moved out of the hot store without orphan warnings. CLI: `regista archive seal/verify/list`. Added `docs/retention.md`.

### Fixed

- **BC-310:** Replay now runs at REPEATABLE READ isolation to prevent spurious drift/halt under concurrent writes. Spec §17.1 amended: mutating transactions remain READ COMMITTED; replay (read-only) is the sole exception. `ConnectionManager.transaction_repeatable_read()` uses `conn.isolation_level` for SSL-safe isolation setting.
- **Plan 027 follow-up:** Added `AssuranceOps` facade (`sub.assurance.compute_assurance()` / `sub.assurance.gate_rationale()`) so review-assurance computations live in the ops layer alongside other Plan 007 facades. Top-level `compute_assurance()`/`gate_rationale()` delegate to the facade.
- **BC-308:** `verify_event()` now filters backward-compat envelope candidates by the stored envelope's classified version — v4 events try only v4 candidates, v3 try v3/v4, v2 try v2/v3/v4. `classify_envelope_version()` v3 detection fixed to check any chain field (not just `prev_event_hash`). Dead code removed from non-chained branch.
- **BC-306:** `entity_kind` validated at sidecar (`Literal["work_item"]` → 422 on unknown), core API, and InMemory boundaries. Allowed set centralized in `_contract.py`. Public API docstring corrected.
- **BC-294:** Migration runner gains `repair_checksums()` (with advisory lock) and CLI `schema repair-checksums` command. `-- regista: autocommit` directive enables non-transactional migrations for `CREATE INDEX CONCURRENTLY`.

## [0.5.0] — 2026-06-26

### Added

- **Plan 020 (Validator context enrichment):** `ValidatorContext` (the object passed to sync transition validators) gains two additive fields: `actor_kind` (the acting actor's kind, identical to the `transition()` argument) and `prior_events` (the work-item's complete pre-transition event history as a tuple of `Event` objects, ascending `event_seq`). Both are populated only inside the registered-validator branch (zero-cost when no validator is registered), on the transition's own connection/store handle for transactional consistency. `to_dict()`/`from_dict()` round-trip both fields; `from_dict` tolerates their absence for forward-compatibility with pre-Plan-020 payloads (missing `actor_kind` decodes to `"agent"`, missing `prior_events` to `()`).
- **Plan 021 (Validator delegation chain on context):** `ValidatorContext` now also exposes the acting actor's `on_behalf_of` delegation chain (the same value passed to `transition()`). This enables separation-of-duties validators to detect self-review-via-delegation by comparing the transition's principal against prior-event authors. The field is zero-cost when no validator is registered and round-trips through `to_dict()`/`from_dict()`; `from_dict` tolerates its absence for forward-compatibility (missing `on_behalf_of` decodes to `None`).
- **Plan 022 (Entity generalization and crypto agility):** events carry `entity_kind`/`entity_id` (generalizing beyond `work_item_id`), a global event hash chain (`global_seq` + `prev_global_event_hash`), signing envelope v4, and per-event `hash_alg`. Spec updated to v9 (§17.11–17.14). Additive and backward-compatible via envelope-version retry in `verify_event`.
- **Witness Ed25519 co-signing (BC-297/303/305):** witnesses may register Ed25519 public keys; witness signatures verified against the public key at delivery time. Missing/invalid signatures treated as delivery failures.
- **WI-003 (Per-work-item scoped replay):** `replay()` now accepts an optional `work_item_id` keyword argument to replay and verify a single work item in isolation. Scoped replay runs per-item hash chain, signature, and projection checks, compares the derived state to the live projection row, and reports one warning that global-chain verification was skipped. Global chain, chain-head, and TSP timestamp coverage checks remain full-`replay()` concerns. A scoped id whose projection row is missing but whose events exist is reported as `halted` (corruption) rather than `WORK_ITEM_NOT_FOUND`.

### Fixed

- **BC-298/300:** `PostgresEventStore.append()` persists `prev_global_event_hash`; replay now verifies the global hash chain and detects tail-deletion via the `event_chain_head`.
- **BC-301:** `MAX_JSONB_BYTES` (1MB) enforced on all JSONB-bearing fields (payloads, `actor_metadata`, `custom_fields`) via the `Jsonb` wrapper.
- **BC-304:** `KeySet.verify_key_status` parses timestamps to `datetime` before comparison (was plain-string compare).
- **Adversarial review batch (Session 66–71):** numerous input-validation, parity, signature-verification, and replay-coverage fixes tracked under BC-276–BC-308.


## [0.4.0] — 2026-05-27

### Changed

- **Project renamed: `substrate` → `regista`.** The Python module, console script, PyPI name, and all env vars now use `regista`. Repo is at `hraedon/regista`; the old URL redirects. See Plan 018.
- **Schema:** `workflow_registry.substrate_version` column renamed to `regista_version`; `_substrate_migrations` table renamed to `_regista_migrations` (migration 028).
- **Env vars:** `SUBSTRATE_DSN`, `SUBSTRATE_HMAC_KEY_*`, `SUBSTRATE_BIND`, `SUBSTRATE_DISABLE_DOCS`, `SUBSTRATE_DISABLE_RATE_LIMIT`, `SUBSTRATE_POOL_MAX`, `SUBSTRATE_POOL_MIN`, `SUBSTRATE_PROJECT`, `SUBSTRATE_TOKENS_PATH`, `SUBSTRATE_VERSION` → all renamed `REGISTA_*`. No backwards-compat aliasing.
- **Console script:** `substrate` → `regista` in `[project.scripts]`.
- **Classes:** `Substrate` → `Regista`, `InMemorySubstrate` → `InMemoryRegista`, `SubstrateError` → `RegistaError`.

### Migration notes for consumers

Consumers pin to `v0.4.0-pre-rename` during their migration window. Migration steps:

1. Update `pyproject.toml` / requirements: `substrate` → `regista`.
2. Update imports: `from substrate import …` → `from regista import …`.
3. Update env var references in code, scripts, and deployment configs.
4. Re-run tests.

## [0.3.0] — 2026-05-26

### Added

- **Plan 010 (Delegation chain):** `on_behalf_of` field on every event for agent-to-principal binding. `validate_delegation_chain` with temporal validation (`expires_at`, `authenticated_at`). Integrity-protected by HMAC signature. Migration 019.
- **Plan 011 (Pluggable signing):** `SigningScheme` protocol with `HMACSHA256Scheme` (default) and `Ed25519Scheme` (optional, via `pip install regista[ed25519]`). `scheme_id` column on events (migration 015). Replay resolves scheme per event.
- **Plan 012 (RFC 3161 timestamping):** `_timestamping.py` with Merkle tree batching, TSA HTTP submission, token verification. `tsp_batches` table (migration 016). `TimestampOps` facade. `replay(verify_timestamps=True)` cross-references events against confirmed batches.
- **Plan 013 (Witness co-signing):** `_witness.py` with registration, event filtering, receipt creation, and HTTP delivery. `witness_registrations` and `witness_receipts` tables (migration 020). `WitnessOps` facade. Maintenance thread integration. Sidecar witness routes (7 endpoints).
- **Plan 014 (Global event sequence):** `global_seq BIGSERIAL` on events (migration 017). Rewrote timestamping batching and replay verification to use global sequence for coherent multi-work-item batching.
- **Plan 015 (Trust envelope v3):** Signing envelope v3 includes `prev_event_hash` and `global_seq`. `prev_event_hash BYTEA` column on events (migration 018). Hash chain verification in replay.
- **Plan 016 (Privileged transitions):** `privileged: true` flag on workflow transitions. Only `actor_kind='system'` can execute. New `PRIVILEGED_TRANSITION_REQUIRED` error code. Enforced in Postgres and InMemory backends.
- **Plan 017 (Webhook/witness unification):** Webhooks rewritten as thin wrapper over witness machinery. Migration 026 adds `mode` column to `witness_registrations`, unifies status to `paused` (dropped `failed`), drops `webhook_registrations` table. `X-Regista-Signature` header. Optional `sign_secret` on all endpoints.
- **Webhooks:** Push-model event delivery with `register_webhook`, auto-pause on failure. Now delegates to witness receipt+delivery model (async, not synchronous).
- **Event archival:** `archive_events(before_timestamp, dry_run)` with `ArchiveOps` facade. Only archives complete work-items to preserve hash chain integrity. Migration 024.
- **Batch operations:** `create_work_items_batch` for multi-create in a single transaction.
- **CLI additions:** `work-item create/transition`, `events archive`, `witness list/deliver/receipts`, `webhook register/list/remove`, `timestamp status/trigger/verify`, `workflow compose`.
- **`work_item_ref` multi-target:** Custom fields accept `target_work_item_types` (plural list) in addition to singular `target_work_item_type`.
- **CI:** All optional extras (`[sidecar,ed25519,timestamping]`) now installed in CI so full test suite runs.

### Fixed

- **Adversarial review (BC-238–BC-256):** 19 breadcrumbs covering witness receipt TOCTOU, sidecar error mapping gaps, InMemory parity issues, missing CHECK constraints, input validation across CLI/sidecar/core.
- **Adversarial review (BC-244–BC-256):** Input validation, error handling, and robustness improvements across 15 files.
- **BC-233:** Event hash chain — `prev_event_hash` computation in Postgres and InMemory backends.
- **BC-236:** `PostgresEventStore.append()` now includes `prev_event_hash` in INSERT.
- **BC-222:** Replay `_EVENT_FIELDS` now includes `scheme_id` for Ed25519 verification.

## [0.2.0] — 2026-05-22

### Added

- **Plan 007 (Facade decomposition):** Domain-scoped sub-objects (`sub.workflows`, `sub.work_items`, `sub.events`, `sub.claims`, `sub.links`, `sub.hooks`, `sub.recurrence`) via `_ops.py`. Legacy top-level methods remain as thin delegates.
- **Plan 008 (Trust model hardening):**
  - WS-1: `strict_roles=True` flag rejects unregistered actors and `prompt`-source roles at transition time
  - WS-2: Environment-variable key injection via `REGISTA_HMAC_KEY_<KEY_ID>` overrides file secrets
  - WS-3: Vendored `rfc8785` 0.1.4 into `_vendor/` with 73 cross-validation tests against system library
  - WS-5: Raise on unknown key status at startup; `expected_key_count` parameter; `keys_loaded` structured log
- **Plan 009 (Operational runtime):** `MaintenanceThread` in `_maintenance.py` with configurable sweep, recurrence, hook-poll, and partition intervals. `start_maintenance()` / `stop_maintenance()` on `Regista`. `maintenance_healthy` property. Subsumes hook consumer lifecycle.
- Shared datetime utilities (`_datetime_utils.py`): `ts_equal`, `to_utc`, `ts_equal_within` — eliminated 88 lines of duplication between replay modules.
- CI now installs `[vendor-check]` extra so rfc8785 cross-validation tests run in CI.

### Changed

- Constructor positional-signature contract test (BC-195) pins `Regista(dsn, project, hmac_key_path)` shape used by sf2.
- BC-196/197/198 (trust model design gaps) accepted and documented; implementation deferred.

### Deprecated

- WS-4 (sidecar rate limiting) explicitly deferred per reviewer consensus.

## [0.1.1] — 2026-05-21

### Changed

- **RFC-001:** Reverted events table partitioning. Events table is now flat with a global `UNIQUE(event_id)` index. `ensure_event_partitions()` is a no-op returning `[]`. Partition gauges (`events_default_rows`, `events_partition_horizon_days`) removed from Prometheus metrics. Migrations renumbered 010–013 (gaps 010/014 closed; no production data affected).
- **BC-194:** Heartbeat coalescing — `heartbeat_claim` suppresses `claim_heartbeat` events within `max(60s, ttl/2)` threshold. New optional `coalesce_threshold` parameter for custom override. Replay drift detection tolerates `claim_expires_at` deltas within the coalesce threshold.

### Deprecated

- `ensure_event_partitions()` — no-op, will be removed in a future version
- `auto_partition` parameter on `Regista.create_project()` — no-op, will be removed in a future version
- Prometheus gauges `regista_events_default_rows` and `regista_events_partition_horizon_days` — no longer emitted

### Fixed

- `_ts_equal_within` in replay modules incorrectly called `.astimezone(UTC)` on naive datetimes (assumed local time instead of UTC)
- `_ts_equal` mixed naive/aware comparison logic simplified to normalize both to UTC

## [0.1.0] — 2026-05-15

### Added

- Event-sourced coordination library for agent pipelines over Postgres (FR-01 through FR-29)
- Schema-per-project isolation with `SET LOCAL search_path` scoping
- Immutable append-only event log with gap-free `event_seq` per work-item
- Transactionally-consistent denormalized projection (`work_items_current`)
- HMAC-SHA256 signing with RFC 8785 canonicalization; library is sole signer (FR-15)
- Monthly partitioned events table (migration 010) — **removed in RFC-001**; events table is now flat with global `UNIQUE(event_id)`
- Durable claims with TTL, attempt tracking, and auto-steal on expiry
- Workflow registry with content-hash idempotency
- Sync transition validators with 5s timeout and I/O safety AST check (FR-13)
- Async hook queue with dead-letter, retry, and out-of-process claim/complete/fail lifecycle
- Actor role enforcement (FR-24) with `register_actor_role` / `check_actor_role_authorized`
- Custom field validation at workflow registration and transition time (FR-27)
- Typed directed links between work items
- Cursor-based pagination on `query_work_items`
- JSONB containment (`@>`) filtering on custom fields with GIN index (BC-139)
- Replay with drift detection and continue-on-revoked flag (FR-25)
- `update_not_before` API for rescheduling work items (FR-26)
- Recurring work items with interval and RRULE schedules, catch-up policies (FR-28)
- Workflow composition via `extends:` with keyed list merge and `__append`/`__remove` modifiers (FR-29)
- Admin CLI: `workflow validate`, `work-item show/list`, `events show/tail`, `replay`, `schema init/status`, `hooks dead-letter list/requeue`, `actor-roles list`, `recurrence list/due/fire/cancel/update`
- HTTP sidecar (Plan 005): thin 1:1 pass-through of the Python API over FastAPI with bearer-token auth, sole-signer enforcement, hook claim/complete/fail lifecycle, and OpenAPI docs
- Dockerfile and README for sidecar deployment (`deploy/sidecar/`)
- Prometheus metrics via `prometheus_client.CollectorRegistry`
- Structured logging via structlog
- CI configuration (`.github/workflows/ci.yml`)
- In-memory backend for testing (`InMemoryRegista`)
- Single-source-of-truth backend contract via `_contract.py` (RFC-062)
- Property-based conformance tests via hypothesis

### Fixed

- 188 breadcrumbs resolved across security, correctness, and conformance dimensions
- Key fixes: claim zombie revival prevention (BC-071), cross-partition event_id uniqueness (BC-148), projection-before-event ordering (BC-147), validator ThreadPoolExecutor lock leak (BC-146), structlog stderr routing in CLI
