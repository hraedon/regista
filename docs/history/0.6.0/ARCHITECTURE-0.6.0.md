# VERDICT: adopt this architecture for 0.6.0

> ## SUPERSEDED IN 14 PLACES — read `RECONCILIATION.md` and `ARCHITECTURE-FINAL.md` first
>
> **Rank 5 of the precedence order (`ARCHITECTURE-FINAL.md` §1). Retained for reasoning and for
> rejected alternatives; it is NOT the document to implement from.** Its code citations are
> pre-S1 and five are wrong — use the concordance in `V6-ENVELOPE.md` §12 (D-1). Its counts are
> the architecture-era measurement and are stale — use `preflight-live.json`.
>
> The fourteen superseded parts, in `RECONCILIATION.md`'s numbering (§ WHAT CHANGED IN MY
> ARCHITECTURE), with where the corrected rule now lives:
>
> | # | What is wrong here | Corrected in |
> |---|---|---|
> | 1 | Key provisioning treated as a parallel hardening track | `IMPLEMENTATION-PLAN.md` Gate 2 — a **hard** prerequisite; 0 of 26 projects can cut over today |
> | 2 | WI-241 framed as the dominant legacy key problem | WI-275: `regista-prod-001` signs 304,333 events with **no** `principal_keys` row anywhere |
> | 3 | Projection rebuild reconstructs the legacy epoch | `TRUST-DOMAIN.md` §5.9 — rebuild is valid for the **v6 epoch only** |
> | 4 | First-event key binding (circular) | `V6-ENVELOPE.md` §1.4, `TRUST-DOMAIN.md` §5.8 — Bootstraps A and B |
> | 5 | 15-key envelope, lineage under `actor.metadata` | `V6-ENVELOPE.md` §1.1, §1.8 — 16 keys, `producer` block |
> | 6 | `workflow: null` semantics and the `NOT NULL` columns | `V6-ENVELOPE.md` §1.6, §9.3 M1; `CUTOVER-CLASSIFICATION.md` §4.4 |
> | 7 | No guard against consumers ordering by `global_seq` | `CUTOVER-CLASSIFICATION.md` §2.2, §3.4 — predecessor-link traversal only |
> | 8 | Single-root default; publication out of scope | `TRUST-DOMAIN.md` §3.4, §4 — co-signing default, git publication in scope (WI-272) |
> | 9 | Recovery at registrar authority (`:363`) | `TRUST-DOMAIN.md` §5.6 — **current root threshold** |
> | 10 | v5 stays `FULLY_AUTHENTICATED` after cutover | `RESULT-MODEL.md` §10.2 invariant 3 — ~334k events relabel to `LEGACY_PARTIAL` |
> | 11 | The legacy claim before the WI-278 disclosure | `RECONCILIATION.md` §6 — a valid HMAC proves knowledge of a **disclosed** value |
> | 12 | Counts at `:814-821` and a uniform ceremony | `preflight-live.json`; counts belong to a **named snapshot** |
> | 13 | Host custody read as project authority | `TRUST-DOMAIN.md` §2.1 — selected key, principal, host and harness must all reconcile |
> | 14 | Five stale code citations; one requested fix already shipped | `V6-ENVELOPE.md` §12 D-1 — **do not** reimplement the permissive classifier; S1 made it strict |
>
> Everything not listed above still stands as reasoning. Nothing in this document overrides
> `RECONCILIATION.md`, and where this document and a sibling specification disagree, the sibling
> wins (rank 3 or 4 beats rank 5).

> **LOCAL SAFETY MARKER — WI-283.** The historical design below is retained for rejected
> alternatives and architecture reasoning. It is not an implementation contract. Before using a
> declaration from this file, resolve it against the owning sibling named in the banner; a local
> `SUPERSEDED`, `AMENDED` or `CUT` marker immediately before a declaration is authoritative for
> that declaration.

## EXECUTIVE SUMMARY

Regista 0.6.0 should establish a new cryptographic epoch: strict v6 envelopes, Ed25519-only production signing, signed identity and workflow state, content-bound review verdicts, and externally rooted bundle v3 artifacts. Existing v4/v5 and HMAC events remain immutable and verifiable under their original, explicitly limited semantics; a signed per-project cutover checkpoint binds each legacy history to the new public-key epoch without pretending to re-authenticate it. Public keys move from project-local mutable tables into an estate-wide signed trust-domain log rooted in operator-supplied fingerprints, while project-local tables become rebuildable projections only. The unused segment and anchoring implementations should be deleted rather than repaired during this release: they currently provide no deployed evidence and keeping them preserves false security surfaces. After 0.6.0, regista can defend against database-only tampering when signing keys are kept outside PostgreSQL, but it still cannot defeat a host operator who controls every signing key and every publication channel.

---

## 1. The v6 signed envelope

### Decision

> **SUPERSEDED — `V6-ENVELOPE.md` §1.1–§1.9 and `RECONCILIATION.md` Resolution 1.** The envelope
> object shown in this historical section predates the required `producer` block and the bootstrap
> exceptions. Implement the 16-key v6 contract, canonical order, signed producer semantics and
> `string | null` key-binding rules from `V6-ENVELOPE.md`; do not copy this section's 15-key
> example.

Introduce exactly one writable event format:

- v6 is mandatory for every event after a project's cutover.
- Production v6 events must use Ed25519.
- v4/v5 parsing and verification remain forever for history.
- No new v4/v5 or HMAC event may follow a signed v6 cutover checkpoint.
- Unknown envelope versions and unknown fields fail closed.

The current envelope omits `scheme_id`, project identity, workflow content identity, and a cryptographically meaningful authorization chain. It also exposes format inference through permissive field-set classification (`_signing.py:276-319`) and defaults signing to HMAC (`_signing.py:194-220`). Both patterns should disappear for v6.

### Exact v6 structure

The canonical JSON object should have this shape:

```json
{
  "type": "regista.event",
  "version": 6,
  "project_instance_id": "uuid",
  "trust_domain_id": "uuid",
  "event_id": "uuid",
  "entity": {
    "kind": "work_item",
    "id": "uuid"
  },
  "entity_seq": 17,
  "actor": {
    "principal_id": "agent:opaque-subject",
    "kind": "agent",
    "metadata": {}
  },
  "signing": {
    "scheme_id": "ed25519",
    "key_id": "pk_...",
    "key_binding_event_hash": "sha256:..."
  },
  "authorization": {
    "mode": "direct",
    "credentials": []
  },
  "workflow": {
    "name": "canonical-name",
    "version": 3,
    "definition_hash": "sha256:...",
    "registration_event_hash": "sha256:..."
  },
  "occurred_at": "2026-08-08T12:34:56.123456Z",
  "transition": "transition-name",
  "payload": {},
  "chain": {
    "hash_algorithm": "sha-256",
    "previous_entity_event_hash": "sha256:...",
    "previous_project_event_hash": "sha256:..."
  }
}
```

Rules:

- Every listed key is required. Optional semantic values use JSON `null`; absent and null must not collapse.
- `type` and `version` are literal values, not hints.
- UUIDs use lowercase canonical text.
- Timestamps use one UTC RFC 3339 representation. They are signed actor claims, not trusted time.
- `scheme_id` is signed and must equal the scheme from the referenced trusted key binding. This structurally closes S2.
- `project_instance_id`, not project name, is the security boundary. Names are mutable labels and belong in projections and manifests.
- `trust_domain_id` prevents importing a key credential from another estate with coincidentally identical principal/key identifiers.
- `workflow.definition_hash` binds replay to the exact registered definition rather than mutable `workflow_registry.definition`, currently read directly by replay at `_replay.py:1165-1183`.
- `key_binding_event_hash` makes the event causally dependent on a signed project-local acceptance of the signer key.
- For non-workflow entities, `workflow` is explicitly `null`.
- Actor metadata remains signed because lineage and actor-kind policy consume it, but the verifier must describe model lineage as a signed assertion unless an external harness attestation exists.

### Canonicalization and hashes

Use RFC 8785 exactly, but add domain separation:

```text
canonical_envelope = JCS(v6_object)
signature_input =
    b"regista.event.v6\x00" || canonical_envelope

event_hash =
    SHA256(
      b"regista.event.hash.v1\x00" ||
      uint64be(len(canonical_envelope)) ||
      canonical_envelope ||
      signature
    )
```

The exact stored canonical bytes remain authoritative. Online loading verifies those bytes and then totally reconciles every duplicated row column, following WI-267. Bundle v3 should avoid most duplication entirely and carry canonical envelope plus signature as the event artifact.

### Delegation: WI-008

Do not treat an `on_behalf_of` object signed only by the acting agent as authorization. That merely authenticates the agent's assertion that somebody authorized it.

For `authorization.mode == "delegated"`, `credentials` must be an ordered chain of independently signed delegation credentials:

```json
{
  "type": "regista.delegation",
  "version": 1,
  "credential_id": "uuid",
  "trust_domain_id": "uuid",
  "issuer_principal_id": "human:...",
  "subject_principal_id": "agent:...",
  "scope": {
    "project_instance_id": "uuid",
    "entity_kinds": ["work_item"],
    "workflow_names": ["agent-notes"],
    "transitions": ["..."]
  },
  "parent_credential_hash": null,
  "issued_at": "...",
  "expires_at": "...",
  "issuer_key_id": "pk_..."
}
```

Each credential has its own Ed25519 signature and key-binding proof. The chain must:

1. Begin at a directly trusted or authorized principal.
2. End at `actor.principal_id`.
3. Have no cycles.
4. Authorize the current project, entity, workflow and transition.
5. Be unrevoked at the event's position in the project chain.
6. Match the signed credential hashes embedded in the event.

For historical `on_behalf_of`, retain the exact signed assertion but report `legacy_delegation_assertion`, not verified delegation.

### `work_item_id` versus `entity_id`

Drop `work_item_id` from v6. `entity.kind + entity.id` is sufficient and removes the current double representation. The database may retain `work_item_id` as a work-item projection/FK convenience, but v6 verification requires it to equal `entity.id` whenever `entity.kind == "work_item"`.

For v4/v5 history, preserve and enforce the WI-267 rule that work-item `entity_id == work_item_id`.

### `global_seq`

Do not put `global_seq` into v6 and do not add two-phase signing.

It is assigned after signing today (`_events.py:230-294`) and is only a database locator. Cryptographic order is already established by `previous_project_event_hash`, while per-entity order is established by `entity_seq` and `previous_entity_event_hash`.

A per-event post-hoc sequence attestation would introduce:

- a second signature artifact per event,
- crash states between the two signatures,
- new reconciliation rules,
- no additional protection over the predecessor hash.

Signed checkpoints and bundle membership statements should attest `event_count`, chain head and an informational maximum `global_seq`. The sequence value must never be the sole proof of order or completeness.

---

## 2. Signed bundle v3

### Decision

> **SUPERSEDED — `BUNDLE-V3.md` §§3–5 and `RECONCILIATION.md` Resolution 4.** This historical
> bundle sketch predates the final scope and trust-policy amendments. `declared-selection` is cut;
> the bundle verifier must use the owning v3 contract, externally supplied trust material and the
> corrected signer, index and attestation rules.

Delete bundle formats v1 and v2 from the public verifier. Old bundles are regenerable artifacts, unlike event history. Bundle v3 becomes the only accepted format.

This removes the v1 signature downgrade at `_bundle.py:646-658` rather than preserving another legacy mode.

### Bundle contents

A v3 bundle contains:

1. `membership_statement`
2. `membership_signature`
3. `events`
4. Required key-lifecycle proofs
5. Required project key-acceptance events
6. Required workflow-registration events
7. Review verdicts and referenced subject metadata
8. Cutover/checkpoint evidence
9. Optional externally obtained evidence, explicitly classified

Each event record should contain only:

```json
{
  "canonical_envelope": "base64...",
  "signature": "base64..."
}
```

An optional index may contain derived fields for display, but verification must recompute it from the envelope.

### Signed membership statement

> **CUT — `BUNDLE-V3.md` §3.5.** The historical scope example below includes
> `declared-selection` for rejected-alternative reasoning. 0.6.0 accepts only
> `complete-store` and `contiguous-range`; do not implement the third value or its `selection`
> member.

The statement should be:

```json
{
  "type": "regista.audit-bundle",
  "version": 3,
  "bundle_id": "uuid",
  "project_instance_id": "uuid",
  "trust_domain_id": "uuid",
  "created_at": "...",
  "scope": {
    "kind": "complete-store | contiguous-range | declared-selection",
    "selection": {},
    "event_count": 352509,
    "first_event_hash": "sha256:...",
    "last_event_hash": "sha256:...",
    "preceding_event_hash": null
  },
  "event_membership_root": "sha256:...",
  "section_digests": {
    "events": "sha256:...",
    "key_lifecycle": "sha256:...",
    "workflows": "sha256:...",
    "checkpoints": "sha256:..."
  },
  "signer": {
    "scheme_id": "ed25519",
    "key_id": "pk_..."
  }
}
```

Its signature input is:

```text
b"regista.audit-bundle.v3\x00" || JCS(membership_statement)
```

The event membership tree must be ordered by project-chain traversal, not event UUID or mutable `global_seq`. Its leaves are:

```text
SHA256(
  b"regista.bundle.member.v1\x00" ||
  uint64be(chain_ordinal) ||
  event_hash
)
```

This closes S4 against an offline attacker: deleting, adding, replacing or reordering any event or supporting section invalidates the signed statement. The existing unkeyed bundle hash (`_bundle.py:570-577`) can be removed.

`complete-store` is allowed only when the statement identifies the exact chain head and count
observed by the signer. `contiguous-range` must include the predecessor hash. The rejected
`declared-selection` alternative is retained only to explain why it was cut; it is not a 0.6.0
scope kind.

### Trust root and WI-209

The bundle's included public keys are evidence and convenience copies, never roots of trust. Current verification builds its root directly from bundled key rows (`_bundle.py:690-736`), which is circular.

The verifier requires one of:

- `--trust-policy <file>`
- `--trusted-fingerprint <fingerprint>` repeated
- a programmatic equivalent

The trust policy pins:

- `trust_domain_id`
- root public-key fingerprints
- accepted project instance IDs
- minimum known trust-log checkpoint
- optionally a known project checkpoint/head
- permitted bundle-signing authority and algorithm
- policy for the legacy cutover epoch

WI-209's registry⇄chain consistency and enrollment-before-use requirements remain correct, but “anchored chain” must become “externally pinned signed trust-log checkpoint” in 0.6.0 because real anchoring is removed from this release.

### Verdict model: WI-269 remains necessary

A signed bundle does not collapse the verdict dimensions. Report at least:

- `structurally_valid`
- `membership_signature_valid`
- `membership_complete_for_claimed_scope`
- `event_authentication`: `full | legacy_partial | invalid | unverifiable`
- `trust_root`: `externally_pinned | bundled_only | absent`
- `cutover_checkpoint_valid`
- `external_time_evidence`: `absent | valid | invalid | unverifiable`
- `identity_conflicts`
- final applicability:
  - `externally_authenticated`
  - `internally_consistent`
  - `legacy_checkpoint_bound`
  - `invalid`
  - `unverifiable`

Keep WI-269's three-way distinction. A manifest may be correctly signed against a bundled key yet remain circular. A bundle may be externally rooted while containing checkpoint-bound HMAC history. A bundle may be authentic but intentionally partial.

Do not reintroduce a generic `verified: bool` except as `true` only when every requirement of a caller-supplied policy is met.

### Auditor workflow

1. Obtain the bundle from the operator.
2. Obtain the trust policy or fingerprints through an independent channel.
3. Verify the membership signature against an externally pinned root/delegated bundle signer.
4. Recompute all section digests, counts and ordered membership roots.
5. Strictly parse every envelope and verify project binding, signature, key lifecycle, authorization and chain links.
6. Reconstruct workflow definitions from signed registration events.
7. Verify review verdicts against their subject digests and predecessor state.
8. Verify the cutover checkpoint and classify every pre-cutover event separately.
9. Compare against any externally known project/trust-log checkpoint.
10. Emit the multidimensional verdict, including unanchored-tail and legacy limitations.

Bundle export must also address:

- WI-259 by reading the complete logical event stream;
- WI-261 by refusing an existing destination unless `--overwrite` is explicit;
- atomic temporary-file replacement only after successful self-verification.

---

## 3. Identity, keys and trust root

### Canonical principal identity: WI-055

Adopt the ratified agent-suite WI-055 grammar:

```text
human:<stable-opaque-subject>
agent:<stable-opaque-subject>
service:<stable-opaque-subject>
```

Rules:

- Enforce it on new enrollment, append and delegation creation after project cutover.
- Never enforce it when verifying historical events.
- Never treat `key:*` as a principal.
- Derive and validate write-time actor-kind compatibility, but preserve the existing distinction between acting principal and execution kind.
- Historical prefix/kind disagreements are explicit `principal_kind_conflict`, not silently resolved.
- A legacy-to-canonical mapping is itself a signed identity event and never changes historical signature binding.

The approximately 231k `human:*`/`actor_kind=agent` events remain `legacy_conflated`: signed actor claim `human:*`, execution classification `agent`, not human judgment.

### Estate-wide trust-domain log

Create one estate-wide identity/trust project, with a stable `trust_domain_id`. It owns signed events for:

- principal creation,
- key enrollment and proof of possession,
- rotation,
- revocation,
- registrar delegation,
- legacy identity mapping,
- ~~witness key enrollment~~ **CUT FROM 0.6.0** — future witness lifecycle only,
- bundle-signing authority,
- project instance registration.

The genesis root is necessarily out-of-band. It should be an offline Ed25519 root key, not an online application key. The externally distributed genesis trust document contains:

- trust-domain ID,
- root public key and fingerprint,
- trust-log project instance,
- initial trust-log head,
- document format and signature.

Routine non-recovery lifecycle operations use a scoped, expiring registrar credential signed by the
offline root. New principal enrollment also requires proof of possession by the principal key.
Normal rotation is dual-authorized by the old key and registrar; recovery rotation requires the
current root threshold and remains visibly classified as recovery. The registrar may prepare and
submit recovery but cannot authorise it.

### Project-local key acceptance

A global binding alone does not establish when a key became authorized in a particular project. Before a principal key signs its first event in a project, append a signed project event:

```text
principal_key_accepted
```

It references:

- global trust-log lifecycle event hash,
- principal ID and fingerprint,
- project instance ID,
- allowed scopes,
- acceptance event hash.

Every later event references this project-local acceptance hash. Revocation or rotation produces a corresponding project event. This gives enrollment-before-use and post-revocation ordering on the same project chain rather than trying to compare unrelated schemas' `global_seq` values.

`principal_keys` can remain as a cache, but it must be rebuilt from these signed events and never be a verifier's authority. The current direct mutation path at `_principal_keys.py:102-153` must be replaced by event append plus projection update.

### WI-241 historical cross-schema keys

Do not copy the current `agent_notes` row into `agent_provenance` and call it contemporaneous enrollment. Instead create a signed retrospective event:

```text
legacy_key_binding_attested
```

It records:

- exact historical principal and key identifiers,
- public key fingerprint,
- source schema and source registration evidence,
- affected event hashes or bounded range,
- who performed the retrospective attestation,
- that enrollment-before-use was not proven.

The historical Ed25519 signatures in the named preflight snapshot can then be cryptographically
verified, while their registry chronology is honestly classified as retrospective. Counts are
measured inputs, not architecture constants. Future cross-project use goes through the trust-domain
log and project-local acceptance.

### Workflow and other side tables: S6

- `workflow_registry` becomes a projection of signed `workflow_registered` and `workflow_retired` events carrying the complete canonical definition and digest.
- `principal_keys` becomes a projection.
- `event_chain_head` remains only a concurrency lock/cache; `_events.py:65-99` may continue using it operationally, but no verifier may trust it as tail evidence.
- Signed checkpoints, not `event_chain_head`, establish externally known heads.
- `event_segments` is deleted, discussed below.
- `anchor_receipts` is deleted with the current anchoring implementation.

### Witness enrollment: WI-264

> **CUT FROM 0.6.0 — `RECONCILIATION.md` FINAL SCOPE.** The witness lifecycle and positive
> witness-independence work are retained below only as a future design. No witness row, callback or
> receipt is a 0.6.0 trust mechanism.

For a later release, witness registration, key rotation, pause and revocation would become signed
project/trust events. The current plain insert followed by principal-key insertion
(`_witness.py:133-163`) and mutable rotation (`_witness.py:227-262`) must not establish trust in
0.6.0.

A witness receipt is evidence only when:

- the witness key chains to an externally pinned root or fingerprint,
- its enrollment preceded the receipt's subject,
- the receipt signs a content/checkpoint hash,
- the auditor obtained either the receipt or a checkpoint independently of the database.

A registered callback in the same database is not an external witness.

---

## 4. Ed25519 cutover and the history seam

> **SUPERSEDED — `CUTOVER-CLASSIFICATION.md` §§1–5 and `RECONCILIATION.md` Resolution 1.**
> The checkpoint sketch in this historical section is not the complete Bootstrap A/B contract.
> Implement the owning cutover schema, including explicit checkpoint/initialisation bootstrap,
> measured snapshot counts, chain-position classification and the post-cutover legacy boundary.

### Classification of the existing corpus

Do not describe the legacy region simply as an “HMAC prefix.” `agent_provenance` is already mixed. The correct classification is:

- **Pre-cutover legacy epoch:** v4/v5 events, individually classified as:
  - Ed25519 signature independently verifiable;
  - HMAC valid only to a holder of the shared secret and never proof of an individual signer;
  - malformed/unknown/invalid.
- **Post-cutover v6 epoch:** Ed25519-only, project-bound and lifecycle-bound.

Existing Ed25519 v5 events remain independently signature-verifiable but lack intrinsic project binding. The cutover checkpoint binds their exact bytes into the project history as observed at cutover.

### Signed cutover checkpoint

The first post-migration event in each project is a v6 Ed25519 event on a project-system entity:

```text
project_cryptographic_epoch_started
```

Its payload includes:

```json
{
  "previous_epoch": {
    "allowed_envelope_versions": [4, 5],
    "event_count": 12345,
    "genesis_event_hash": "sha256:...",
    "head_event_hash": "sha256:...",
    "max_global_seq": 12997,
    "scheme_counts": {
      "hmac-sha256": 12000,
      "ed25519": 345
    }
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

The checkpoint's own `previous_project_event_hash` must equal the legacy head. Its signature key must resolve through the externally pinned trust domain.

`max_global_seq` is informational. The binding is the chain head plus count and genesis hash.

### What the checkpoint proves

For HMAC history, an external auditor can:

1. Recompute every envelope/signature event hash.
2. Walk the whole predecessor chain.
3. Reach the exact legacy head named by the Ed25519 checkpoint.
4. Verify that checkpoint against a pinned public key.

This proves that the presented legacy bytes are the bytes committed at cutover and have not subsequently changed. It does **not** prove:

- which individual possessed the shared HMAC secret,
- that an operator did not fabricate history before cutover,
- that timestamps reflect real time,
- that each HMAC actor attribution is independently authentic.

The wording in WI-270 should therefore be tightened from “the history that existed at cutover” to “the exact history the cutover signer committed to.” Without an independent observer at cutover, those are not identical claims.

### Production enforcement

After the checkpoint:

- append rejects HMAC;
- append rejects envelopes below v6;
- verifier treats either condition as structural invalidity, regardless of mutable policy rows;
- doctor fails production posture if any active writer lacks Ed25519 custody;
- HMAC signing remains only under an explicit test/development posture;
- HMAC verification remains permanently available.

WI-268 is absorbed into the common verifier: `continue_on_revoked` may continue traversal for diagnostics, but an unresolved or invalid signature is never applied to replay state. The current skip path at `_replay.py:1004-1038` must be removed.

---

## 5. Operator forgery: WI-007

### What 0.6.0 closes

Against an attacker with database write access but no private-key access:

- event modification fails signature or reconciliation;
- event insertion requires an authorized Ed25519 key;
- event deletion before a pinned checkpoint breaks the committed head/count;
- key-registry mutation is irrelevant because verification rebuilds from signed lifecycle events;
- workflow mutation is irrelevant because events bind the workflow digest;
- project replay fails across project instance IDs;
- bundle rewriting fails the signed membership statement;
- review transition forgery cannot create a valid content-bound verdict.

Key custody must enforce separate Vault policies per principal or principal class. A database service credential must not be able to read every private key.

### What remains irreducible

A host/root operator who can:

- read all online private keys,
- alter the code before signing,
- impersonate every principal,
- control the offline root,
- and control every publication/witness channel

can fabricate an internally valid history. Ed25519 does not solve that.

The practical mitigations are:

- offline trust root,
- scoped online registrar,
- per-principal Vault policy separation,
- external publication of checkpoint heads,
- ~~independent witnesses~~ **CUT FROM 0.6.0** — future release only,
- eventual multi-party root or transparency log.

The 0.6.0 posture includes the offline root, scoped registrar, per-principal custody and the
publication channel. Governance is a **monotone signed log** inside the stable trust domain, and
the publication limit is explicit: a **fresh clone cannot establish that the first publication was
honest**; detection requires a prior observation. Independent witnesses and eventual multi-party
transparency remain outside the release. WI-007 stays open as a narrowed decision item rather than
being marked resolved.

---

## 6. Review assurance as signed verdicts

### Verdict event

> **SUPERSEDED — `REVIEW-VERDICTS.md` §§2–5 and `RECONCILIATION.md` Resolution 2/4.** This
> historical payload predates the complete seven-member subject and reducer-v1 staleness contract.
> Do not implement `subject_profile`, credential-established human kind or the old digest formula
> from this section; use the owning review-verdict document.

Replace transition-name inference with a versioned signed payload:

```json
{
  "type": "regista.review-verdict",
  "version": 1,
  "verdict_id": "uuid",
  "decision": "pass | request_changes | reject | accept",
  "review_subject": {
    "project_instance_id": "uuid",
    "entity_id": "uuid",
    "subject_digest": "sha256:...",
    "reviewed_through_event_hash": "sha256:...",
    "artifacts": [
      {
        "media_type": "application/vnd.git.commit",
        "locator": "repo-name",
        "digest": "sha256:..."
      }
    ]
  },
  "author_snapshot": {
    "principals": [],
    "lineages": [],
    "has_undeclared_agent": false,
    "digest": "sha256:..."
  },
  "reviewer_claims": {
    "model_lineage": "openai/gpt-5.6",
    "harness": "opencode",
    "harness_version": "...",
    "same_lineage_acknowledged": false
  },
  "computed_relation": "distinct | same | unknown",
  "policy": {
    "gate_profile": "...",
    "validator_version": 1
  },
  "review_note": "..."
}
```

The verifier recomputes the author snapshot, lineage relation and subject digest. Payload values are evidence to reconcile, not trusted answers.

An `accept` verdict must reference:

- the exact pass verdict ID,
- the same subject digest,
- the same reviewed-through hash or an allowed non-content extension,
- a different effective reviewer principal where policy requires it.

### Subject binding

The subject digest should cover:

- canonical work-item body/frontmatter,
- relevant code artifact digests or git commit/tree,
- workflow version/digest,
- any other declared review artifact.

Regista cannot infer a repository commit by itself. The gate client must supply artifact digests, and the signed verdict must say exactly what was and was not reviewed.

A later content mutation changes the subject digest and makes prior passes stale. Non-content diagnostic events may remain after a pass only when the reducer proves they do not change the subject digest; do not trust a caller-provided `affects_review=false`.

### Assurance computation

`compute_assurance_level` reads only cryptographically valid `review-verdict/v1` payloads, never bare transition strings. The current inference at `_assurance.py:235-277` and duplicate pass scanning in `_review_validators.py:244-324` should be replaced by one verdict reducer and one `LineageRelation` implementation.

This closes S8 and WI-250. WI-211's finding dispositions should use signed `review_finding` and `finding_disposition` events referencing the verdict ID and subject digest.

Delete `lineage_verification`. Its current value merely checks whether a scheme class is asymmetric (`_assurance.py:201-219`). Replace it with fields sourced from the common `VerificationResult`, such as:

- `event_signature_status`
- `principal_binding_status`
- `lineage_claim_status`
- `review_subject_binding_status`

Model lineage still remains a signed claim unless the key enrollment contains an independently trusted harness/model attestation.

---

## 7. Anchoring

### Decision: delete it from 0.6.0

Delete both current anchoring implementations and remove their public APIs, CLI commands, sidecar routes, maintenance jobs and positive documentation claims.

Specifically remove:

- legacy timestamp batches in `_timestamping.py`;
- RFC 3161 positive verification without a trust anchor, currently returned at `_timestamping.py:487-495`;
- UUID-only Merkle trees at `_timestamping.py:84-129`;
- the non-functional OpenTimestamps provider at `_anchoring.py:355-437`;
- mutable `anchor_receipts` as evidence;
- “anchored” or “externally witnessed” claims from README/spec/docs.

This is preferable to repairing the subsystem now because:

- there are zero receipts and zero timestamp/segment evidence rows to preserve;
- both provider semantics and committed content are wrong;
- correct RFC 3161 path validation and OTS integration require dedicated interoperability testing;
- that cost is not reduced by riding the v6 cutover.

Retain only generic, provider-neutral checkpoint export and verification. An operator may publish a checkpoint through Git, an auditor exchange or another medium, but regista 0.6.0 must call it an externally supplied pin, not an anchor or trusted timestamp.

A future release may add one anchoring provider after real-network tests prove:

- the commitment is over project chain heads/content hashes;
- certificate/path/time semantics are fully validated;
- receipts survive retention independently;
- positive status is impossible without configured trust material.

S7 is therefore closed in 0.6.0 by removing the false implementation and narrowing the claim, not by delivering external temporal anchoring.

---

## 8. Cutover mechanics

### Remove segment/archive complexity

> **AMENDED — `CUTOVER-CLASSIFICATION.md` and `CUTOVER-POLICY.md` are the owning cutover
> contracts.** The operational direction below is retained as architecture reasoning only; the
> signed checkpoint payload, snapshot counts and read-only/rehearsal boundaries in those siblings
> win whenever this section is less specific.

Because the estate has zero `event_segments`, delete segment sealing, replay bridging and destructive event archival.

Before cutover:

- consolidate any `events_archive` rows back into the single logical `events` stream without changing envelope, signature, event hash or chain values;
- detect divergent duplicates and halt;
- export must read the complete stream during the transition;
- drop `event_segments` after confirming it is empty;
- stop deleting events.

At the measured estate size, retention is not currently worth an unauthenticated chain-hole
mechanism. Future storage optimization should use transparent PostgreSQL partitioning or immutable
external objects with independently pinned manifests, not verifier-trusted side rows.

This structurally closes S10 and removes the `event_segments` part of S6. The current live verifier's dependence on mutable segment rows (`_archive_segments.py:597-706`) and replay bridge trust (`_replay.py:782-817`) disappears rather than being patched.

### One cutover event per project

There cannot be one atomic event across 26 schemas. The operational unit is one signed cutover event per project, followed by one externally published estate catalog containing all 26 resulting checkpoint hashes.

For each project:

1. Acquire the global append lock and a project cutover advisory lock.
2. Re-run strict verification inside the transaction.
3. Confirm the head/count equal the approved preflight result.
4. Append `project_cryptographic_epoch_started` as the first v6 Ed25519 event.
5. Set the runtime projection to v6/Ed25519-only.
6. Commit.
7. Re-read and verify the checkpoint from storage.

The signed event, not the mutable posture row, tells future verifiers where strict v6 rules begin.

---

# SEQUENCING

## Stage 0 — contracts and preflight, before implementation

Freeze these documents first:

1. Exact v4/v5 authenticated-field matrix.
2. Exact v6 JSON schema, canonicalization and hash domains.
3. `VerificationResult` states and policy evaluation.
4. Bundle v3 statement schema.
5. Trust-domain genesis and lifecycle schemas.
6. Review-verdict subject schema.
7. Legacy/cutover classification policy.

Extend the WI-267 preflight to report per project:

- envelope/signature/reconciliation status;
- scheme and version counts;
- missing/unknown key bindings across all schemas;
- live/archive placement and duplicates;
- identity conflicts;
- workflow-definition digest availability;
- chain genesis/head/count;
- current writer principal and Ed25519 readiness;
- any segment/anchor rows;
- exact proposed cutover payload.

Preflight output itself should be canonical JSON so it can be retained alongside the cutover ceremony.

## Stage 1 — common authenticated semantics

Implement together:

- WI-267 common verifier completion;
- v6 strict parser and signer;
- S2 scheme binding;
- project/trust-domain binding;
- no fallback reconstruction;
- WI-268 removal of unverified replay application;
- chain breaks and invalid events as structural failures;
- replay path parity and missing-work-item checks;
- WI-252 replay report cleanup and exception-preserving temp-table teardown.

Every consumer must accept only `VerificationResult`, not a boolean.

## Stage 2 — trust and identity

In parallel after schemas stabilize:

- estate trust-domain log;
- canonical principal grammar from agent-suite WI-055;
- signed lifecycle events and projections;
- project-local key acceptance/revocation;
- retrospective WI-241 binding records;
- signed workflow registration;
- ~~signed witness enrollment~~ **CUT FROM 0.6.0** — future design only in `TRUST-DOMAIN.md` §7;
- delegation credentials for WI-008;
- Ed25519 Vault provisioning.

Include WI-216: `PARTIALLY_EFFECTIVE → EFFECTIVE` must be possible after a transient custody outage, because the cutover depends on recoverable key provisioning.

Complete WI-235's ratified consumer-owned codec contract and provider capability split before generating estate keys. Ambiguous private-key octets are unacceptable during a one-way ceremony.

## Stage 3 — review verdicts and bundle v3

These can proceed in parallel once the common verifier and trust schemas are fixed:

- signed review verdict/review-subject reducer;
- one lineage relation path, closing WI-250;
- WI-211 finding dispositions;
- removal of `lineage_verification` per WI-263;
- bundle v3 signed membership;
- external trust-policy input;
- WI-269 multidimensional verdict;
- archive-aware/consolidated export for WI-259;
- explicit overwrite contract for WI-261.

Bundle export must strict-verify its source before signing and then verify the produced file before atomic publication.

## Stage 4 — delete unneeded security surfaces

Before cutover:

- restore any archived rows;
- remove segment/archive APIs and verifier bridges;
- remove RFC 3161/OTS/timestamping APIs and claims;
- add migrations dropping empty segment/anchor tables;
- remove maintenance scheduling for them.

Do not rewrite old migration files; add forward migrations so existing stores upgrade safely.

## Stage 5 — operational hardening

Resolve release-adjacent debt that can invalidate the ceremony:

- WI-260: migration must work with `pool_max=1` or reject it immediately;
- WI-247: bounded doctor behavior and fail-honest test leak guard;
- WI-252: replay output must not expose dangling table names;
- production doctor must fail on HMAC writers, missing Ed25519 custody, stale trust imports or unsigned lifecycle projections.

WI-251 is not product architecture, but fix the worktree editable-install hazard before trusting non-pytest cutover tooling.

## Stage 6 — rehearsal

> **AMENDED — `RECONCILIATION.md` Resolution 6 and `preflight-live.json`.** The numeric values in
> the historical rehearsal checklist are not frozen inputs. The ceremony must use a named,
> quiesced preflight snapshot and carry its measured counts into the signed checkpoint payload.

Run the complete upgrade against restored copies of all 26 schemas:

- no rewritten envelope/signature/hash bytes;
- all events in the approved named snapshot retain exact artifact hashes;
- every project produces the expected legacy checkpoint payload;
- all historical Ed25519 signatures in the approved snapshot resolve;
- all HMAC events in the approved snapshot receive explicit legacy classification;
- replay and bundle results match;
- old binaries fail safely after schema capability change;
- v6 append and rollback-before-commit are exercised.

## Stage 7 — production ceremony

1. Back up and test restore.
2. Publish the trust-domain root through the chosen independent channel.
3. Provision and prove possession of Ed25519 keys.
4. Put writers into read-only mode.
5. Run final preflight and compare it byte-for-byte with rehearsal expectations.
6. Apply schema migrations.
7. Cut over each project, producing one signed checkpoint.
8. Produce and sign the estate cutover catalog.
9. Publish that catalog through the independent channel.
10. Enable only 0.6.0 writers.
11. Export and independently verify a bundle v3 for every project.
12. Retain the final preflight, catalog, trust policy and verification reports.

### Rollback

- Before any checkpoint commits: roll back schema/code and restore service.
- After a checkpoint commits but before external publication and before subsequent writes: restore the complete backup only if the checkpoint is explicitly abandoned and never published.
- After publication or any post-cutover event: no rollback to 0.5.x. Keep the service read-only and repair forward with another signed event/release.
- Never delete the checkpoint, rewrite history, or resume HMAC signing.

## Work that should not enter 0.6.0

Despite the expansive mandate, exclude:

- a new RFC 3161 or OpenTimestamps provider;
- CT-style key transparency or witness federation;
- ~~quorum/multi-signature roots~~ **WITHDRAWN — WI-272 makes independent co-signing the default;
  solo is visible lab/dev posture.**
- post-quantum algorithms;
- per-event signed `global_seq` attestations;
- historical re-signing;
- a new retention/object-storage subsystem;
- hardware-token integration;
- unrelated encryption or secret-provider features beyond what Ed25519 custody requires;
- external IdP integration beyond preserving stable opaque principal subjects.

Those costs are not materially reduced by this cutover.

---

# WHAT 0.6.0 STILL CANNOT CLAIM

Release notes must state all of the following plainly:

1. Historical HMAC events are not independently attributable to individual principals.
2. The cutover checkpoint binds the exact legacy bytes the checkpoint signer committed to; it does not prove that pre-cutover history was honest when created.
3. Historical v4/v5 Ed25519 events are individually signature-verifiable but gain project placement only through the later checkpoint.
4. Retrospective WI-241 key attestations do not prove contemporaneous enrollment-before-use.
5. A signed bundle proves what its signer attested and is externally authenticated only against auditor-supplied trust material.
6. Without a fresh externally published checkpoint, tail truncation after the last known checkpoint may remain undetectable.
7. 0.6.0 provides no trusted timestamp or public anchoring guarantee.
8. Signed actor/model-lineage metadata proves what the signer asserted, not which model or human actually generated the action.
9. Delegation credentials prove authorization under the configured trust root, not subjective human intent.
10. A host operator controlling all roots, private keys and publication channels can fabricate a valid-looking history.
11. A local witness configured and stored by the same operator is not an independent external witness.
12. `global_seq` remains an unsigned database index and is not cryptographic ordering evidence.
13. A valid legacy HMAC proves knowledge of a shared value that is now disclosed; it does not prove
    origin, creation time or pre-disclosure existence.
14. The `regista-prod-001` legacy population has no store-side principal/key binding; a verifier
    cannot infer one from an operator key file or create one retrospectively.
15. The cutover checkpoint contains the disclosure but does not remediate it: an observed head can
    detect later substitution, not prove earlier HMAC history was honestly produced.
16. Distinct root signatures prove distinct keys, not distinct people or custody; a distinct
    publication account proves address separation, not independent control.
17. The v6 `producer` block is a principal-signed assertion. Policy matching detects
    inconsistency; it is not remote attestation of the process or model.

The defensible headline is:

> **Regista 0.6.0 makes event semantics, identity lifecycle, review verdicts and exported membership cryptographically checkable against externally pinned Ed25519 trust material, while preserving older history under explicitly limited legacy semantics. It does not yet provide external timestamping, transparency-log publication, or protection against an operator who controls every private key and observation channel.**

---

# OPEN QUESTIONS FOR THE OWNER

> **RESOLVED — WI-272, recorded immediately below.** These questions are retained as decision
> history only. Implement the owner decisions, not the interrogative text.

1. **Root governance:** Is an offline root controlled solely by the owner acceptable for 0.6.0, or must the genesis trust document require a second independent co-signer? This changes the operator-forgery boundary, not merely implementation detail.
2. **Publication channel:** What channel will auditors actually treat as independent for root fingerprints and the estate cutover catalog—direct exchange, a separately controlled repository/account, or another custodian?
3. **Lineage assurance:** Should 0.6.0 claim only “principal-signed model-lineage assertion,” or is harness-issued lineage attestation required before `independently_reviewed` may be presented as more than policy evidence?
[agent-wake-opencode] INFO notify-on-idle: published ocidle-mslbul2k-68fa82951b86d306 for session ses_01b288219ffeYG1xKWMdTyvY1q (status 202, delivery next_session)

---

# OWNER DECISIONS ON THE THREE OPEN QUESTIONS (2026-08-08) — WI-272

**1. Root governance — independent co-signer BY DEFAULT.** Owner: *"Provided that there is a mode
we can opt into or instructions in order to make the home lab implementation continue to work, I am
fine defaulting to an independent cosigner."*

A single-signer lab/dev mode exists. **Binding constraint:** it must be *visible in the artifact*,
not merely in configuration. The genesis trust document carries its own signer set and threshold;
verification reports which it actually saw; an estate rooted by a solo signer says so in every
bundle it produces. Implementing the opt-in as a config flag that leaves the artifact identical is
forbidden — if lab mode is invisible, anyone can claim `co_signed` governance and no verifier can
check, which makes the default theater.

**2. Publication channel — a dedicated public git repository under an account distinct from the
estate's operational identity, bootstrapped by direct exchange.**

The channel *cannot prevent* an operator publishing a false fingerprint; nothing short of a real
transparency log can. Its job is to make **substitution detectable to an auditor holding a prior
observation** — an auditor told fingerprint F at time T can check the channel still says F at T+1,
and that its history shows no rewrite. The
properties that matter are therefore **retention, history and third-party hosting, not authority**.
Git on a separate account supplies all three at near-zero ongoing cost, and the estate already
holds two distinct GitHub identities, so the separation is free.

**Design constraint: publication must be one command emitting canonical JSON.** A ceremony that
takes an hour will not happen at cutover time under pressure, and an unpublished checkpoint is
worth nothing. Leave format room for a custodian countersignature or a public anchor later
*without* requiring a new epoch.

**3. Lineage assurance — strict.** 0.6.0 claims only **principal-signed model-lineage assertion**.
`independently_reviewed` is documented as **policy evidence, not cryptographic proof of
independence**: a principal can sign a truthful claim to be `claude-opus` or an untruthful one, and
0.6.0 cannot tell them apart. A signature proves *who asserted*, never *what generated the action*.
The strong claim waits for harness-issued lineage attestation.

This is the same defect class as WI-263 (`lineage_verification` reporting `"verified"` for what is
only a scheme property). Both resolve under one rule, which should be applied to assurance-level
names as well as field names: **the name must not promise more than the check performs.**
