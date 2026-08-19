# Regista 0.6.0 specification reconciliation

**Status:** normative integration overlay; implementation may begin when the conformance fixtures
named here exist. Where this document conflicts with `ARCHITECTURE-0.6.0.md`,
`V6-ENVELOPE.md`, `CUTOVER-CLASSIFICATION.md`, `TRUST-DOMAIN.md`, `BUNDLE-V3.md`, or
`REVIEW-VERDICTS.md`, **this document wins**. The frozen S1 documents remain authoritative for
v1-v5 except where `CUTOVER-CLASSIFICATION.md` explicitly supersedes them.

Evidence citations to `preflight-live.json:1` include a JSON pointer because that canonical JSON
file is one physical line. Code citations in the earlier documents are pre-S1 unless stated
otherwise; implementers must use `origin/main`. `V6-ENVELOPE.md:1134-1147` is the concordance.

# WHAT CHANGED IN MY ARCHITECTURE

I still recommend adoption, but the architecture is not implementable as written. The following
parts of my own design are wrong or superseded.

1. **Key binding is the release gate, not a parallel hardening track.** I put key provisioning,
   project acceptance, workflows, delegation and Vault work together in a parallel Stage 2
   (`ARCHITECTURE-0.6.0.md:755-771`). The live result is zero rehearsable projects and 26 blocked
   projects (`preflight-live.json:1`, `/proposed_estate_cutover_catalog/projects_rehearsable` and
   `/projects_blocked`). No project signs with a locally authorised Ed25519 key. Trust bootstrap,
   canonical principal assignment, exact signing-key selection and custody proof are hard gates
   before rehearsal and ceremony.
2. **WI-241 is not the dominant legacy key problem.** I centered the design on the 49,652
   cross-schema Ed25519 events and said their retrospective record could not establish chronology
   (`ARCHITECTURE-0.6.0.md:385-402`). The measured enrolment at 02:40:21Z precedes first use at
   18:15:30Z. Its record may truthfully report `chronology_observed: enrollment_preceded_use`; it
   still may not claim contemporaneous project-local acceptance. The larger finding is WI-275:
   `regista-prod-001` signs 304,333 events and has no `principal_keys` row in any project; it
   resolves only from the operator key file (`preflight-live.json:1`,
   `/estate/events_resolved_only_from_operator_key_file`).
3. **The S6 projection remedy cannot reconstruct the legacy epoch.** I said `principal_keys`
   could be rebuilt from signed lifecycle events (`ARCHITECTURE-0.6.0.md:365-383`). There are no
   such lifecycle events for the HMAC epoch, and the dominant key has no registry row. Projection
   rebuild is valid only for v6 lifecycle state. Legacy resolution remains a separately labelled
   compatibility input and never becomes lifecycle evidence.
4. **The first-event key-binding rule is circular.** I required every v6 event to reference an
   earlier project acceptance while also making the checkpoint the first v6 event
   (`ARCHITECTURE-0.6.0.md:76-80,442-475`). That cannot work. Resolution 1 defines the two narrow
   external-root bootstraps and removes B's self-authorising first-acceptance rule.
5. **The envelope has changed again.** The owner-mandated `producer` block is a sixteenth required
   top-level member. `model_lineage` moves out of `actor.metadata`; it is not duplicated. The
   15-key contract and test vector at `V6-ENVELOPE.md:80-109,964-1029` are obsolete and must be
   regenerated.
6. **`workflow: null` did not fit the schema or my semantics.** The columns have been `NOT NULL`
   since migration 001, and the current segment workaround signs `""`/`0` sentinels
   (`V6-ENVELOPE.md:1156-1170`; post-S1 `migrations/001_initial.sql:9-10`). A forward migration is
   mandatory. Also, `workflow == null` cannot imply `transition == null`: the checkpoint has a
   named lifecycle transition (`V6-ENVELOPE.md:182-185` versus
   `CUTOVER-CLASSIFICATION.md:261-265`). Resolution 3 replaces that rule.
7. **`global_seq` is not chain order.** The architecture correctly called it unsigned, but its
   runbook did not guard against consumers sorting by it. The live preflight manufactured 45
   phantom breaks when ordered that way. Security order is exclusively predecessor-link
   traversal (`CUTOVER-CLASSIFICATION.md:236-253`). Rehearsal comparisons also require quiesced
   writers; the store moved by roughly 500 events during measurement.
8. **Single-root default and publication exclusion are overturned.** Independent co-signing is
   the default under WI-272, solo is visible lab/dev posture, and the git publication channel is
   release scope. My exclusion of quorum roots (`ARCHITECTURE-0.6.0.md:847-860`) and statement
   that publication was not in 0.6.0 (`:541-550`) are wrong.
9. **Recovery at registrar authority is wrong.** My rule at
   `ARCHITECTURE-0.6.0.md:363` leaves the online registrar as the only residual takeover path
   that does not require host root (`OPERATOR-FORGERY.md:379-428`). Recovery rotation requires
   the current root threshold. Visible `recovery_rotated` classification remains, but is not a
   substitute for prevention.
10. **The historical classification changes after cutover.** A v5 event is
    `FULLY_AUTHENTICATED` only before that project cuts over. Afterward, v4/v5 are
    `LEGACY_PARTIAL`; only v6 is fully authenticated. This relabels roughly 334,000 events without
    changing a byte or cryptographic check (`CUTOVER-CLASSIFICATION.md:133-183`). It is a corrected
    claim boundary, not a regression.
11. **The HMAC disclosure changes the legacy claim.** WI-278 means successful verification under
    `regista-prod-001` now proves only that bytes match a disclosed symmetric value. Retaining the
    value for verification also retains its forging capability. Rotation cannot repair that.
    The checkpoint and the already published interim head are the mitigation: they make later
    substitution detectable; they do not restore origin authentication.
12. **The counts and uniform-ceremony assumptions are stale.** The measured estate is 353,985
    events: 304,333 HMAC and 49,652 Ed25519 (`preflight-live.json:1`, `/estate/total_events` and
    `/estate/by_scheme_id`), not the counts at `ARCHITECTURE-0.6.0.md:814-821`.
    `agent_provenance` alone has 349,066 events. Counts belong to a named snapshot and the locked
    transaction, never source code or a frozen payload.
13. **Host custody is not project authority.** The WI-223/WI-278-era qualification incident showed
    an Ed25519 key registered in one project signing another while four surfaces stayed green
    (post-S1 `origin/main:CHANGELOG.md`, “Principal binding was reported, not verified”). The
    preflight also finds no `actor_id -> principal_id` mapping and two unused `hermes-agent` keys,
    with the host-active key different from the registry-active key. The actual selected key,
    canonical principal, host and allowed producer harness must all reconcile.
14. **Five architecture code citations are stale, and one requested fix already shipped.** Do not
    reimplement the permissive classifier; S1 made it strict. Use the post-S1 concordance at
    `V6-ENVELOPE.md:1134-1147`.

# RESOLUTIONS

## 1. The two bootstrap circularities

There are two circularities and one trust-log genesis case. They compose as follows.

### Bootstrap A: the external trust domain

`signing.key_binding_event_hash` becomes `string | null`. `null` is valid only for these exact
transitions and positions:

| Event | Position | External authorisation |
|---|---|---|
| `trust_domain_established` | trust-log genesis, first v6 event | **A-prime (supersedes the prior "hash equals `initial_head_event_hash`" wording):** the genesis document must carry a null `trust_log.initial_head_event_hash` (`genesis_head_must_be_null`); the event is chain position 1 with `key_binding = null`; its payload's `genesis_document_digest` matches the published-document digest and its detached `root_signatures` meet the initial root threshold; the envelope signer is a genesis root (transport, not authority). The event hash is pinned by the checkpoint. |
| `project_cryptographic_epoch_started` | unique first v6 event in a legacy project | The payload's `bootstrap_key_acceptance` resolves through the pinned genesis and a verified trust-log checkpoint; the event signer is exactly that accepted key. |
| `project_initialized` | genesis of a project created directly in v6 | Same as the cutover checkpoint, with an empty previous epoch. |

No other null is accepted. A null on any other event is
`INVALID/KEY_BINDING_BOOTSTRAP_NOT_PERMITTED`.

The trust-log genesis event is the binding anchor for subsequent root-authorised trust-log events.
Root-threshold operations additionally carry their detached threshold signatures as specified by
`TRUST-DOMAIN.md:795-818`; a single event signature never substitutes for the threshold.

### Bootstrap B: the first project-local authority

The cutover/initialisation payload embeds this exact object:

```json
"bootstrap_key_acceptance": {
  "principal_id": "service:...",
  "key_id": "pk_...",
  "scheme_id": "ed25519",
  "public_key": "base64-raw-32",
  "fingerprint": "ed25519:sha256:<64-lowercase-hex>",
  "trust_event_hash": "sha256:...",
  "trust_log_checkpoint": {
    "checkpoint_seq": 12,
    "head_event_hash": "sha256:...",
    "document_digest": "sha256:..."
  },
  "scopes": {
    "entity_kinds": ["project", "principal", "workflow", "work_item"],
    "transitions": null,
    "may_accept_keys": true,
    "may_sign_checkpoints": true,
    "may_sign_bundles": false
  }
}
```

The checkpoint/initialisation event hash is itself the first project-local key-binding anchor.
The next event, including the first standalone `principal_key_accepted`, references that hash.
Every later event references either the checkpoint anchor or a preceding standalone acceptance for
the same principal/key/scope.

This deliberately replaces B's rule that the first acceptance signs itself
(`TRUST-DOMAIN.md:986-993`). There is no self-referential event. Bootstrap A establishes external
authority; Bootstrap B imports that authority and creates project-chain order; ordinary acceptance
then operates without exceptions. `V6-ENVELOPE.md:135` is widened from “must resolve to a
`principal_key_accepted`” to “must resolve to a preceding project key-binding anchor”, whose closed
types are checkpoint bootstrap, project initialisation bootstrap, and `principal_key_accepted`.

The checkpoint's `entity.id` is exactly `project_instance_id`. Empty project `x` uses
`project_initialized`, not a fiction that it had a legacy epoch: previous count maps are empty and
all previous hashes and `previous_project_event_hash` are null
(`CUTOVER-CLASSIFICATION.md:314-316,703-706`).

## 2. The three ownerless artifacts

This reconciliation assigns all three. They are release-blocking contracts, not implementation
details.

### `VerificationResultV6`: owned here, implemented in `_verification.py`

Extend the S1 `VerificationResult` (`RESULT-MODEL.md:117-166`) with these non-optional fields:

```python
epoch_position: "pre_cutover | is_cutover | post_cutover | no_cutover | unknown"
attribution: "individual | shared_secret | none"
checkpoint_binding: "externally_pinned | checkpoint_bound | unbound | not_applicable"
unbound_properties: frozenset[str]
trust_domain_id: str | None
trust_root: "externally_pinned | trust_log_only | bundled_only | absent"
root_governance: "co_signed | solo | solo_effective | unknown"
key_binding: "accepted_in_project | bootstrap_external | trust_log_only | retrospective | legacy_registry | legacy_unbound | unresolved | mismatched | after_use | recovery_rotated"
revocation_status: "not_revoked | revoked_before_use | indeterminate_window | suspect_declared | unknown"
identity_consistency: "consistent | principal_kind_conflict | actor_id_ungrammatical | mapping_absent"
producer_consistency: "matches_published_policy | contradicts_published_policy | policy_not_supplied | not_applicable"
```

Add `EnvelopeVersion.V6` and failure reasons
`ENVELOPE_UNCANONICAL`, `PROJECT_BINDING_MISMATCH`, `TRUST_DOMAIN_MISMATCH`,
`KEY_BINDING_UNRESOLVED`, `KEY_BINDING_NOT_BEFORE_USE`,
`KEY_BINDING_BOOTSTRAP_NOT_PERMITTED`, `WORKFLOW_DEFINITION_MISMATCH`,
`WORKFLOW_REGISTRATION_UNRESOLVED`, `DELEGATION_CHAIN_INVALID`, `EPOCH_VIOLATION`, and
`PRODUCER_POLICY_MISMATCH`. Add policy inputs `pinned_project_instance_id`,
`pinned_trust_domain_id`, `cutover_checkpoint_event_hash`, and `producer_policy`.

Class invariants:

- Any signed-field, project, trust-domain, workflow, delegation, epoch or producer-policy
  contradiction is `INVALID`; no policy can waive it.
- Post-cutover v4/v5 or HMAC is `INVALID/EPOCH_VIOLATION`.
- Pre-cutover v4/v5 is never `FULLY_AUTHENTICATED` after a checkpoint exists.
- A normal v6 event is fully authenticated only with `key_binding=accepted_in_project`.
- A valid checkpoint/initialisation may instead use `bootstrap_external`, but only with
  `trust_root=externally_pinned` and `checkpoint_binding=externally_pinned`.
- `trust_log_only` is distinct from both an external pin and bundled-only material.
- A valid HMAC event has `attribution=shared_secret`, `key_binding=legacy_unbound`, and
  `LEGACY_PARTIAL`; for `regista-prod-001`, reports also include reason
  `disclosed_shared_secret` and may not imply origin authentication.
- `unsigned_fields` remains row-column vocabulary; `unbound_properties` is semantic vocabulary
  (`CUTOVER-CLASSIFICATION.md:524-534`).
- Missing pins produce explicit unbound/not-checked states; they never silently skip a check.

The only boolean bridge remains `.ok == (applicability is FULLY_AUTHENTICATED)`. Review code uses
`acceptable_under(named_policy)`, not the undefined `result.accepted` at
`REVIEW-VERDICTS.md:304-307`.

### Workflow lifecycle: owned here, implemented with the envelope contract

Add `workflow` to the shared `entity.kind` registry. A workflow entity id is
`UUIDv5(NAMESPACE_OID, "regista.workflow:" + project_instance_id + ":" + name + ":" + version)`.
`workflow_registered` is workflow-free (`workflow: null`) and carries:

```json
{
  "type": "regista.workflow-registration",
  "version": 1,
  "name": "canonical-name",
  "workflow_version": 3,
  "definition": {},
  "definition_hash": "sha256:...",
  "supersedes_registration_event_hash": null
}
```

`definition` is the complete semantic definition and must not contain `raw_yaml`.

```text
b = JCS(definition)
definition_hash = SHA256(
  b"regista.workflow-definition.v1\x00" || uint64be(len(b)) || b
)
```

Exactly one registration may introduce `(name, workflow_version)` in a project. A duplicate,
even byte-identical, is invalid rather than an alternate reference. A replacement uses a new
version and may name `supersedes_registration_event_hash`.

`workflow_retired` carries
`{type:"regista.workflow-retirement", version:1, name, workflow_version,
registration_event_hash, reason}`. It shares the workflow entity chain. No workflow event after
the retirement's project-chain position may reference that registration. Registration must
strictly precede every referring event by project-chain traversal. A complete-store bundle missing
the registration is invalid; a bounded range reports `not_checkable` only when the registration is
outside the declared range and supplied as separately authenticated dependency evidence.

### Action-delegation credential: owned by `TRUST-DOMAIN`

Registrar delegation and action delegation remain distinct. `registrar_delegated` authorises
lifecycle administration only. The action document is `regista.action-delegation/v1`:

```json
{
  "type": "regista.action-delegation",
  "version": 1,
  "credential_id": "uuid",
  "trust_domain_id": "uuid",
  "issuer_principal_id": "human:...",
  "subject_principal_id": "agent:...",
  "issuer_key_id": "pk_...",
  "issuer_key_binding_event_hash": "sha256:...",
  "parent_credential_hash": null,
  "scope": {
    "project_instance_ids": ["uuid"],
    "entity_kinds": ["work_item"],
    "workflow_names": ["..."],
    "transitions": ["..."]
  },
  "not_before": "...",
  "not_after": "...",
  "max_uses": null,
  "delegation_allowed": false,
  "signature": {"scheme_id":"ed25519", "value":"base64"}
}
```

The signature covers the exact object without `signature`, framed by
`regista.action-delegation.v1\0` plus length. Its hash uses a separate
`regista.action-delegation.hash.v1\0` domain. Non-root links require a parent hash and
`delegation_allowed=true`; maximum depth is eight; cycles, scope widening, expired credentials and
revoked credentials are invalid. `action_delegation_revoked` is a signed project event, and
ordering is project-chain ordering.

An action credential never manufactures human identity. `principal_kind` comes from a
root/registrar-authorised `principal_registered` event. Therefore
`accepted_by_credentialed_human` means “accepting principal has authenticated human registration”,
not “a delegation document said human”. This corrects the dependency at
`REVIEW-VERDICTS.md:277-288`.

## 3. `workflow: null`, transition semantics, and the migration

The v6 rule is:

- `workflow` is non-null exactly when this event is evaluated by a registered workflow.
- `workflow` is null for project, trust, principal and workflow lifecycle events.
- `transition` is a required non-empty string for every v6 event. For a workflow event it is a
  transition in the referenced definition; for a lifecycle event it is one of the closed event
  catalogue names. There are no transitionless v6 events in 0.6.0.

Before any v6 append, a forward migration runs:

```sql
ALTER TABLE events ALTER COLUMN workflow_name DROP NOT NULL;
ALTER TABLE events ALTER COLUMN workflow_version DROP NOT NULL;
```

Apply the same change to `events_archive` only if archive consolidation has not already removed
that table. v6 `workflow:null` projects to SQL null/null. `""`/`0` is rejected; it is never
generated. Existing legacy sentinel events retain their signed bytes and legacy classification.
This resolves `V6-ENVELOPE.md:1156-1170` and the direct checkpoint contradiction at
`CUTOVER-CLASSIFICATION.md:360-378`.

## 4. A/B/C collisions and the integrated contract

The complete checkpoint payload is the union of A's measured fields and B's trust material, with
one vocabulary:

```json
{
  "type": "regista.project-cutover",
  "version": 1,
  "previous_epoch": {
    "allowed_envelope_versions": [4, 5],
    "event_count": 12345,
    "genesis_event_hash": "sha256:...",
    "head_event_hash": "sha256:...",
    "head_hash_construction": "sha256(canonical_envelope||signature)",
    "max_global_seq": 12997,
    "scheme_counts": {"ed25519": 345, "hmac-sha256": 12000},
    "envelope_version_counts": {"4": 700, "5": 11645}
  },
  "new_epoch": {
    "envelope_version": 6,
    "production_signing_scheme": "ed25519",
    "project_instance_id": "uuid",
    "trust_domain_id": "uuid",
    "trust_domain_core_digest": "sha256:...",
    "genesis_document_digest": "sha256:...",
    "trust_log_checkpoint": {
      "checkpoint_seq": 12,
      "head_event_hash": "sha256:...",
      "document_digest": "sha256:..."
    },
    "root_governance": {
      "mode": "co_signed",
      "threshold": 2,
      "signer_count": 2
    },
    "bootstrap_key_acceptance": {}
  }
}
```

`bootstrap_key_acceptance` is Resolution 1's exact object. Count maps are sorted by key and each
sums to `event_count`. The values are measured under the cutover transaction, not copied from
preflight. `max_global_seq` remains informational. Use wire values `co_signed`, `solo`, and
`solo_effective` everywhere. The hyphenated B spellings and C's `single_signer_lab` are retired.

The shared entity kinds are exactly `work_item`, `project`, `principal`, `trust_domain`,
`project_instance`, and `workflow`. `project_system` is prose, never a wire value. This resolves
the closed set at `V6-ENVELOPE.md:111-119` against B's required kinds at
`TRUST-DOMAIN.md:751-793`.

Cryptographic primitive choices:

- Event hash is version-aware: v1-v5 use `SHA256(canonical_envelope || signature)`; v6 uses the
  domain-separated length-framed construction at `V6-ENVELOPE.md:511-543`. Every event reference
  uses the referenced event's version-derived hash. C's legacy-only definition at
  `BUNDLE-V3.md:155-168` is wrong.
- Fingerprint remains `ed25519:sha256:<SHA256(raw_public_key)>`, matching deployed values and
  `TRUST-DOMAIN.md:329-333`. Remove the conflicting domain-separated “fingerprint” from
  `V6-ENVELOPE.md:954-961`; if retained for another purpose, call it `key_material_digest`.
- Bundle leaf is
  `SHA256("regista.bundle.member.v1\0" || uint64be(scope_ordinal) || event_hash)` with no extra
  `0x00`; interior nodes use
  `SHA256("regista.bundle.node.v1\0" || left || right)` and RFC-6962 split-at-largest-power-of-two.
  `scope_ordinal` is local to the signed scope. Freeze byte vectors.
- Review digest domains in `REVIEW-VERDICTS.md:165-186` win:
  `regista.review-subject.state.v1` and `regista.review-subject.v1`. Remove the conflicting
  `regista.review-verdict.v1` entry from A's registry unless a distinct whole-verdict digest is
  later specified.

Bundle v3 consumes B's `regista.trust-policy/v1`; it does not define a competing schema. Rename
`accept_hmac_prefix` to `accept_legacy_shared_secret_events`, because the legacy region is mixed.
Key bytes may come from bundle evidence, but trust comes only from an auditor pin. A recomputed
fingerprint matching an auditor pin is externally pinned even when the convenient bytes travelled
inside the bundle; arbitrary bundled bytes remain `bundled_only`.

C's WI-269 split survives and widens. The axes at `BUNDLE-V3.md:337-350` remain, with these
corrections:

- `event_trust_root` adds `trust_log_only`.
- Add `event_attribution_counts = {individual, shared_secret, none}` and
  `key_binding_counts`, including `recovery_rotated` and `legacy_unbound`.
- `legacy_checkpoint_bound` requires an externally pinned checkpoint. A bundled-only checkpoint
  is `checkpoint_present_unauthenticated` and cannot exceed `bundle_rooted`.
- Mixed complete-store scope qualifies as `legacy_checkpoint_bound` only if every legacy event is
  covered by the pinned checkpoint, every v6 event is fully authenticated, and no epoch violation
  exists. Reports display legacy HMAC, legacy Ed25519 and v6 counts separately.
- Remove `declared-selection` from 0.6.0. Its proposed clamp can mislabel an all-v6 selection as
  legacy (`BUNDLE-V3.md:364-369`), and no concrete release requirement justifies an attested
  completeness mode. Keep `complete-store` and `contiguous-range`.
- Section schemas are closed. `events` contains canonical envelope/signature records.
  `key_lifecycle`, `project_key_acceptance`, `workflows`, `review_verdicts`, and `checkpoints`
  contain sorted event-hash references into `events`, not extracted payload duplicates.
  `bundled_key_evidence` contains exact public-key material records; `external_evidence` is
  convenience-only and never raises an axis. Unknown section names or nested keys reject.
- Export computes dependency closure for signing authority, lifecycle, acceptance, workflow,
  delegation, checkpoints and verdict supersession. Missing closure in `complete-store` is
  invalid; a bounded range reports the named dependency as outside scope, never silently valid.

Review's two-dimensional result survives: `review_assurance` is `none`,
`lineage_undetermined`, `same_lineage_asserted`, `cross_lineage_asserted`, or
`legacy_unverdicted`; acceptance is `none`, `accepted_by_declared_human`,
`accepted_by_credentialed_human`, or `accepted_by_agent`
(`REVIEW-VERDICTS.md:312-350`). “Independent” is not a cryptographic label. The producer block is
the source for reviewer harness/model/lineage; `reviewer_claims` restates it and must reconcile,
or may omit the duplicates entirely. Simplify `subject_profile` out of 0.6.0: hash the complete
deterministic reduced signed prefix under reducer version 1, and stale a verdict after any
state-changing event. This avoids shipping the untested cross-version reducer/profile mechanism
flagged at `REVIEW-VERDICTS.md:478-484`. Sort artifacts by `(media_type, locator, digest)` and
exclusions by `(media_type, locator, reason)`. Freeze the pass/request-changes/reject/accept
supersession state machine before coding its reducer; competing successors are invalid.

## 5. Recovery rotation authority

Recovery rotation requires signatures from the **current root threshold**. The online registrar
may prepare and submit the request but cannot authorise it. Normal rotation requires old-key
signature plus registrar. Root-key and registrar-key recovery also require the current root
threshold. Every recovery remains signed as `mode: recovery`, reports
`key_binding=recovery_rotated`, and carries a reason. This overrides
`ARCHITECTURE-0.6.0.md:363` and `TRUST-DOMAIN.md:885-903,1551-1560` for WI-278's threat model.

## 6. The legacy epoch after WI-275 and WI-278

The key story is coherent only if it is stated narrowly.

A verifier may conclude for a pre-cutover HMAC event:

1. The stored canonical bytes reconcile with the row under the v1-v5 rules.
2. The MAC mathematically matches the supplied value for `regista-prod-001`.
3. If the whole chain reaches a checkpoint whose Ed25519 authority is externally pinned, the
   presented bytes are exactly the legacy bytes that checkpoint signer committed to.
4. If that legacy head also matches the independently retained interim head from WI-278, no
   substitution occurred between that observation and cutover, subject to matching count/genesis
   evidence carried with the observation.

A verifier may **not** conclude who created the event, that the key was authorised by a registry,
that the event predates disclosure, or that any holder of the disclosed secret could not have
created it. The operator key file is compatibility verification material, not a trust root or a
binding record. No retrospective event may convert the absent HMAC lifecycle into enrolment.

Add these entries to `WHAT 0.6.0 STILL CANNOT CLAIM` after
`ARCHITECTURE-0.6.0.md:866-881` and `OPERATOR-FORGERY.md:452-482`:

13. A valid legacy HMAC proves knowledge of a shared value that is now disclosed; it does not
    prove origin, creation time, or pre-disclosure existence.
14. The 304,333 `regista-prod-001` events have no store-side principal/key binding. A verifier
    cannot infer one from the operator key file or create one retrospectively.
15. The cutover checkpoint contains the disclosure. It does not remediate it: an externally
    observed head can detect later substitution, but neither that head nor the checkpoint proves
    that earlier HMAC history was honestly produced.
16. Distinct root signatures prove distinct keys, not distinct people or custody; publication
    under a distinct account is address separation, not independent control.
17. The producer block is a principal-signed assertion. Matching a published host/harness policy
    makes inconsistency detectable; it is not remote attestation of the process or model.

## 7. Corrected sequencing

The authoritative sequence is in `THE CORRECTED SEQUENCE` below. In short: schemas and vectors
freeze first; implementation tracks may then run in parallel; trust bootstrap and writer identity
must exist before keys are generated; per-host key provisioning and trust-log enrolment are a hard
gate; project cutover is never a way to discover or create keys.

## 8. Scope discipline

The authoritative in/out list is in `FINAL SCOPE`. Two changes ride this breaking window because
the evidence makes them directly security-relevant:

- `keys.json` may no longer contain an inline `secret` in production or verification posture.
  Post-S1 `_keys.py` still accepts it and only logs `keys.plaintext_at_rest`; WI-278 shows warning
  is insufficient. A migration command moves every retained secret to `secret_ref`, verifies the
  effective fingerprint before/after, and then removes the inline value. Legacy HMAC verification
  uses a `secret_ref`; HMAC signing remains prohibited after checkpoint. Inline secrets remain
  available only in an explicit in-memory/test constructor, not the file schema.
- Producer policy is signed and published. Key enrolment binds a key to its host principal; the
  policy maps that canonical principal to a host label and allowed harnesses. Required initial
  entries are mvmcc03 -> `[claude-code]`, mvmcc02 ->
  `[claude-code, opencode, codex]`, and mvmhermes01 -> `[hermes]`. This is many-to-many by design,
  not a 1:1 host/harness assumption.

# COLLISIONS FOUND

The following are not editorial differences; each changes accepted bytes or a verdict.

1. **Checkpoint bootstrap:** every v6 event requires a prior acceptance, but the checkpoint is the
   first v6 event (`V6-ENVELOPE.md:129-136`; `CUTOVER-CLASSIFICATION.md:360-378,692-701`). Resolved
   by the externally authorised checkpoint anchor.
2. **First acceptance bootstrap:** B nulls only `accepted_by.key_binding_event_hash`, leaving the
   envelope field impossible (`TRUST-DOMAIN.md:948-993,1591-1594`). Resolved by making the
   checkpoint/initialisation the prior anchor; no self-authorisation remains.
3. **Trust-log genesis:** B requires a v6 genesis but universal project acceptance has no
   predecessor (`TRUST-DOMAIN.md:751-761`). Resolved by the genesis-only root-threshold rule.
4. **Top-level envelope:** A freezes 15 fields and lineage under actor metadata
   (`V6-ENVELOPE.md:80-109,121-127`); WI-277 requires 16 and a producer block. A's vector is stale.
5. **Entity registry:** A allows only work item/project; B requires principal/trust-domain/project
   instance and inconsistently says project-system (`V6-ENVELOPE.md:111-119`;
   `TRUST-DOMAIN.md:759-793`). Resolved by the six-value shared registry (amended to seven by
   `WI-305 B` — `spec` added).
6. **Null workflow:** A requires transition null while the checkpoint requires a named transition
   (`V6-ENVELOPE.md:182-189`; `CUTOVER-CLASSIFICATION.md:261-265`). Resolved by separating
   workflow evaluation from lifecycle transition naming.
7. **Checkpoint payload:** A adds counts/hash construction/governance; B adds core digest and root
   governance, with different names and enum spellings
   (`CUTOVER-CLASSIFICATION.md:270-312`; `TRUST-DOMAIN.md:465-480`). Resolved by the union schema.
8. **Fingerprint:** A's test vector domain-separates; B preserves deployed raw-key SHA-256
   (`V6-ENVELOPE.md:954-961`; `TRUST-DOMAIN.md:329-333`). B wins for compatibility.
9. **Event hash in bundles:** C hardcodes the legacy formula while v6 defines another
   (`BUNDLE-V3.md:155-168`; `V6-ENVELOPE.md:511-543`). Resolved by version-aware event hash.
10. **Bundle leaf:** architecture/A omit C's leading `0x00`; C claims it only filled interior-node
    detail (`ARCHITECTURE-0.6.0.md:238-246`; `BUNDLE-V3.md:155-175,545`). The named leaf/node
    domains above are authoritative.
11. **Trust policy:** B and C use different field names/shapes; C's fingerprints alone cannot
    supply verification keys (`TRUST-DOMAIN.md:665-704`; `BUNDLE-V3.md:268-303`). B owns the one
    policy; key-material source and trust source are separate.
12. **Trust-root propagation:** B requires a four-field signed `trust_root` block in every bundle;
    C supplies a smaller `governance` block (`TRUST-DOMAIN.md:465-480`;
    `BUNDLE-V3.md:119-141`). B's block replaces C's.
13. **Verdict states:** C omits B's `trust_log_only` and A's individual/shared-secret attribution,
    and overgeneralises all legacy events as unattributable (`BUNDLE-V3.md:337-350,517`;
    `CUTOVER-CLASSIFICATION.md:185-234`; `TRUST-DOMAIN.md:1381-1418`). The widened axes above win.
14. **Checkpoint-bound summary:** A permits bundled-only checkpoint material to reach
    `legacy_checkpoint_bound`; C requires an external root
    (`CUTOVER-CLASSIFICATION.md:351-358`; `BUNDLE-V3.md:356-368`). C's stricter prerequisite wins.
15. **Review digest registry:** A and C assign different domains to the same concept
    (`V6-ENVELOPE.md:594-608`; `REVIEW-VERDICTS.md:165-186`). The review-specific domains win.
16. **Human evidence:** C makes an action credential assert human kind; B never defines that and
    the architecture credential has no such field (`REVIEW-VERDICTS.md:277-288`;
    `ARCHITECTURE-0.6.0.md:104-140`). Identity registration, not delegation, supplies kind.
17. **Publication command:** B's `publish` touches no private key but has no signed-document input
    (`TRUST-DOMAIN.md:604-632`). The implementable command is
    `regista trust publish --kind <kind> --input <signed.json> --repo <clone> [--push]`; it parses,
    canonicalises, verifies, writes, indexes, commits and optionally pushes in one invocation.
18. **Publication rewrite claim:** a coherent malicious rewrite is not detectable from a fresh
    clone despite `TRUST-DOMAIN.md:505-509`; detection requires a prior clone, commit or digest
    (`OPERATOR-FORGERY.md:160-193`). `prev_commit` detects gaps in presented history, not a fully
    rewritten history.
19. **Publication mutability:** `index.json` cannot list its own digest. It lists every immutable
    artifact except itself. Later custodian countersignatures and anchors are new immutable
    `attestations/<subject-digest>/<ordinal>.json` records; they reference the original core digest
    and do not mutate genesis, change `trust_domain_id`, or require a new epoch.
20. **Producer identity:** no A/B/C schema owns the owner-mandated producer map. Add published
    `producer-policy.json`, root-threshold or explicitly scoped-authority signed, with exact
    entries `{host, principal_id, key_fingerprints, allowed_harnesses}` plus
    `countersignatures:[]` and `anchors:[]`. A v6 event's producer block is exactly
    `{harness,harness_version,model,model_lineage}`; each value is non-empty string except `model`
    and `model_lineage`, which may be null for non-model producers. `actor.metadata` must not
    contain any of those four keys. An externally pinned contradiction is
    `INVALID/PRODUCER_POLICY_MISMATCH`; absent policy is explicitly `policy_not_supplied`.
21. **Catalog signer and bundle signer:** B leaves catalog signer `{}` and C omits principal id
    (`TRUST-DOMAIN.md:575-599`; `BUNDLE-V3.md:132-141`). Every signed publication uses
    `{principal_id,key_id,scheme_id,fingerprint,authority_kind,authority_event_hash}`. Direct root
    threshold uses `root_signatures[]`, not a fake principal id.
22. **Current head publication:** C claims B publishes the current project head, but B defines
    only trust checkpoints and a cutover catalog (`BUNDLE-V3.md:209-215,475-479`;
    `TRUST-DOMAIN.md:519-600`). Add `catalog_kind: project_heads` using the same signed catalog
    envelope. It is optional after the mandatory cutover catalog; without it, reports retain
    `tail_truncation_undetectable`.
23. **Cross-reference paths:** documents referred to nonexistent `s1-design` and `v6-design`
    directory prefixes although this spec set is flat (preambles of `V6-ENVELOPE.md` and
    `CUTOVER-CLASSIFICATION.md`). Resolve all links to sibling filenames before
    freeze. **Applied:** every such path now names a sibling file; the S1-era preflight is
    `preflight-s1.json` / `preflight-s1.txt` and the post-S1 measurement is `preflight-live.json`
    — two named snapshots, never one moving number. `check-crossrefs.py` enforces flatness.
    Also fix C's nonexistent `§9.5/§9.6` references (`BUNDLE-V3.md:559-561`), C's wrong workflow
    ownership (`REVIEW-VERDICTS.md:193`), the undefined `result.accepted` reference
    (`REVIEW-VERDICTS.md:304-307`), and A's external test-vector generator path
    (`V6-ENVELOPE.md:948-952`). The generator and resulting vectors belong in the repository.
24. **Read-only preflight versus backfill:** A says preflight backfills `envelope_version`, while
    frozen preflight is read-only (`V6-ENVELOPE.md:910-914`; `CUTOVER-POLICY.md:282-295`).
    Preflight emits expected values; a forward migration/rebuild command writes the cache and then
    reconciles it.

# THE CORRECTED SEQUENCE

## Gate 0: freeze and conformance fixtures

1. Apply this overlay to the sibling documents or mark their conflicting clauses superseded.
2. Freeze the 16-field envelope, producer policy, shared entity registry, complete checkpoint,
   workflow lifecycle, action delegation, consolidated result model, trust policy and bundle
   closure schemas.
3. Check every internal link. Commit byte-level vectors for envelope, all bootstrap cases,
   fingerprint, version-aware event hashes, bundle tree, workflow definition, review subject,
   delegation, genesis, checkpoint, producer policy and catalog.
4. Prove reducer v1 deterministic under JCS. If that test fails, signed review verdicts do not
   implement in this window; transition-name inference is removed but assurance remains
   `legacy_unverdicted/none` rather than shipping an unverifiable digest.

Nothing else starts before Gate 0 because incompatible hash fixtures create unrecoverable signed
artifacts.

## Parallel implementation tracks after Gate 0

These are genuinely parallel:

- **Core:** v6 parser/signer, stored-byte fixed point, version-aware hashes, total row
  reconciliation, `VerificationResultV6`, producer checks, nullable workflow migration, project
  identity projection and one-way append gate.
- **Trust:** genesis/root threshold, trust log, lifecycle, root-threshold recovery, project
  bootstrap acceptance, action delegation, projection rebuild, producer policy, publication and
  catalog.
- **Workflow/review:** workflow lifecycle/replay binding and the simplified verdict reducer.
- **Bundle:** exact v3 sections, dependency closure, mixed-epoch axes and atomic self-verified
  export.
- **Operations:** archive consolidation/deletion, dead anchor/timestamp surfaces, key-file secret
  migration, doctor checks, quiesce support, preflight chain walk and ceremony tooling.

No track may invent a local primitive or enum. All consume Gate 0 fixtures.

## Gate 1: trust and identity bootstrap

1. Generate independent default root keys; create and threshold-sign genesis. Solo lab/dev genesis
   is a different, visibly `solo` artifact.
2. Create the v6 trust log via its genesis exception; register every project instance.
3. Assign canonical host/writer principals and sign the scoped legacy actor mappings. The missing
   `actor_id -> principal_id` answer must be supplied deliberately; it is not inferred from string
   similarity.
4. Sign and publish the producer policy and genesis through the distinct-account git repository.
   Verify from a fresh direct-exchange pin and retain the commit.

## Gate 2: key provisioning, a hard ceremony prerequisite

1. Resolve the two mvmhermes01 keys explicitly: select one host key, reconcile the host-active and
   registry-active disagreement, and deprecate the other through signed lifecycle. Do not choose
   by “active” label alone.
2. Provision one Ed25519 signing key per host principal, not per harness. mvmcc02's one host
   principal may assert any of its three allowed harnesses. Private material uses `secret_ref`.
3. Enrol each selected public key in the trust log with proof of possession and host/principal
   binding. Verify the signer-selection function chooses that exact key.
4. Prepare every project's bootstrap acceptance and checkpoint authority scope. Run doctor until
   every project is `ready_for_bootstrap_checkpoint`; a key existing in some other schema is not
   ready.

Projects may provision in parallel, but **all 26 must pass Gate 2 before estate rehearsal**. The
cutover event imports prior trust authority; it does not provision a missing key.

## Gate 3: quiesced full-estate rehearsal

1. Restore production backups of all projects. Apply forward migrations, including nullable
   workflow columns and removal of inline key secrets.
2. Consolidate `events_archive`; reject divergent duplicates; then remove archive/segment/anchor
   security paths as scoped below.
3. Register every workflow definition needed by enabled v6 writers.
4. Quiesce all rehearsal writers before taking the baseline. Do not byte-compare snapshots from a
   moving store.
5. Run strict pre-verification by predecessor links, never `global_seq`. For the large project,
   perform a fresh read-only pass before lock and the mandatory recheck inside the locked
   transaction (`CUTOVER-CLASSIFICATION.md:708-714`).
6. Exercise trust genesis, project bootstrap, empty-project initialisation, all result states,
   v5/HMAC rejection after checkpoint, rollback before commit, root-threshold recovery, producer
   mismatch, publication and bundle verification.
7. Record expectations by artifact hash and named snapshot, not frozen estate totals.

## Gate 4: production containment ceremony

1. Back up and test restore. Put every writer read-only **before** final preflight and keep all
   writers read-only until the final catalog is published and verified.
2. Recheck the publication repository against the retained commit. A rewrite is a stop.
3. Run final strict preflight and compare with the quiesced rehearsal baseline. Drift is a stop,
   not an invitation to update expectations.
4. Apply forward migrations. Verify no production key entry contains inline `secret` and every
   selected writer key equals its signed enrolment and producer-policy mapping.
5. Per project, in a locked transaction: walk by hash links; measure genesis/head/count/version
   and scheme maps; compare to preflight; build payload from the transaction; append the
   checkpoint/initialisation; set the v6-only projection; commit; reread; strict-verify; require a
   v5/HMAC test append to fail (`CUTOVER-CLASSIFICATION.md:638-660`).
6. If any project fails after another has committed, keep the estate read-only and repair forward.
   Never remove a committed checkpoint or resume HMAC.
7. Produce, threshold-authorise as required, sign and publish the complete estate cutover catalog.
   Its entries include all project checkpoint hashes and the WI-278 interim-head comparison
   result. A partial catalog says `catalog_status: partial` and is ceremony failure, not success.
8. Reclone/recheck the publication, verify catalog and every checkpoint against the direct pin,
   then export and independently verify one bundle v3 per project.
9. Enable only 0.6.0 writers after all prior steps pass. Retain preflight, migration report,
   producer policy, trust policy, catalog, publication commit and bundle reports.

Checkpoint commit is the cryptographic point of no return. Publication makes the containment
externally observable. After either publication or any post-checkpoint write, repair forward only
(`ARCHITECTURE-0.6.0.md:840-845`).

# FINAL SCOPE

## In 0.6.0

- Strict v6 envelope with the required producer block, project/trust/scheme/workflow/delegation
  binding, bootstrap rules and all conformance vectors.
- Consolidated machine-readable result model and post-cutover v5 reclassification.
- Co-signed root by default; visibly solo lab/dev mode; root-threshold recovery.
- Trust log, canonical principal/host mapping, signed lifecycle, project bootstrap acceptance,
  projection-only registries and exact selected-key doctor checks.
- Per-host Ed25519 provisioning and producer policy for mvmcc03, mvmcc02 and mvmhermes01.
- Forward nullable-workflow migration and signed workflow registration/retirement.
- Action delegation v1. Human-kind evidence comes from principal registration.
- Signed review verdicts only if reducer determinism passes Gate 0; simplified full-prefix subject
  binding, two-dimensional assurance and honest lineage names.
- Bundle v3 with signed membership, version-aware hashes, exact sections, dependency closure,
  external trust policy, mixed-epoch verdicts, complete-store and contiguous-range scopes.
- Canonical one-command git publication with signed input, immutable index/catalog/checkpoint
  artifacts, direct-exchange pinning, future countersignature/anchor records without epoch change.
- WI-278 containment: compare and retain the interim head, cut over under quiescence, publish the
  resulting catalog, permanently reject post-checkpoint HMAC/v5 writes.
- Remove inline secrets from production `keys.json`; retain legacy HMAC only through `secret_ref`
  for verification.
- Restore/consolidate archive rows and delete the empty `event_segments`, `anchor_receipts`,
  `tsp_batches` and their false security claims. The live zero-row evidence supports deletion
  (`preflight-live.json:1`, `/estate/non_zero_dead_subsystem_rows`).
- Operational blockers WI-216, WI-235, WI-247, WI-251, WI-252 and WI-260 to the extent needed to
  make provisioning, migration, doctor, replay and ceremony fail honestly.

## Cut from 0.6.0

- `declared-selection` bundles. No completeness proof and no demonstrated release need.
- Positive witness-independence work. There are zero registrations/receipts. Preserve webhook
  delivery only as non-evidentiary transport if consumers require it; remove or hide security
  claims. A signed witness lifecycle and external witness belong in a later release with an actual
  witness.
- Review `subject_profile` extensibility and cross-version reducer compatibility. Use one complete
  reducer v1 or defer signed assurance if its determinism cannot be proved.
- Automatic periodic project-head publication. The format and command support
  `catalog_kind: project_heads`, but only genesis, producer policy, trust checkpoint and the
  cutover catalog are release gates. Reports remain honest about tail truncation until a later
  head is published.
- Retrospective HMAC lifecycle or synthetic HMAC principal binding. It would manufacture evidence
  that never existed. WI-241's measured Ed25519 retrospective attestation may ship, but is not a
  cutover gate once its events verify and the checkpoint binds them.
- Repairing the old segment, anchor, timestamp or witness-verification implementations. Empty
  security surfaces are deleted or demoted, not redesigned during the epoch cutover.

## Still out of scope

The following original exclusions remain correct (`ARCHITECTURE-0.6.0.md:847-862`):

- a new RFC 3161 or OpenTimestamps provider;
- CT-style transparency or witness federation;
- post-quantum algorithms;
- per-event signed `global_seq`;
- historical re-signing;
- a new retention/object-storage subsystem;
- hardware-token/HSM integration;
- unrelated encryption/provider work beyond required Ed25519 custody and removal of inline key
  secrets;
- external IdP integration.

Quorum roots and external git publication are removed from that exclusion list because WI-272
makes them mandatory. No claim of trusted time, transparency, independent witness, independent
co-signer identity, or protection from a host operator holding every key enters 0.6.0.

# REMAINING OPEN QUESTIONS FOR THE OWNER

None. The remaining unknowns are operational inputs, not design value judgments: the canonical
principal assigned to each host, the actual second root custodian/key, the publication repository,
and the project-to-host writer inventory must be supplied during Gates 1-2. Their required artifact
shapes and failure behavior are fixed above.
