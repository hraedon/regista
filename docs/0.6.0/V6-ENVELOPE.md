# regista 0.6.0 — the v6 signed envelope (FROZEN CONTRACT)

**Status:** Stage 0 contract. Frozen before implementation, per `ARCHITECTURE-0.6.0.md`
§ SEQUENCING / "Stage 0 — contracts and preflight, before implementation", item 2
("Exact v6 JSON schema, canonicalization and hash domains").
**Not a code change.** No production source was modified to produce this document.

**Companions.**
`FIELD-MATRIX.md` — the frozen v1–v5 authenticated-field matrix. This document
interlocks with it: everything it says about v1–v5 remains true and unamended.
`RESULT-MODEL.md` — the `VerificationResult` shape this extends (§9.4).
`CUTOVER-CLASSIFICATION.md` — the legacy/cutover epoch policy (companion deliverable).

**Code baseline — every `file:line` in this document is against `origin/main` @ `334b995`**
("fix(signing): authenticate the row, not just the envelope (WI-267) (#37)"), the post-S1
keystone. Sources were read with `git show origin/main:<path>` and cited from that output; the
shared `rc-build` regista checkout is on `release/0.5.6`, which **predates the
Phase 1 merges**, so its working-tree files are pre-S1 and must not be used to check these
citations. Verify every code citation the same way — `git show 334b995:<path>` — never against a
working tree. (`src/regista/_verification.py` does not exist on that branch at all.) Where
`ARCHITECTURE-0.6.0.md` cites pre-S1 line numbers, this document gives the post-S1 location and
says so — see DIVERGENCES D-1, which enumerates the four stale citations found.

**Owned elsewhere.** Three sibling Stage 0 documents own artifacts this schema *references*.
Where a v6 field points at one of them, this document specifies the **field** — its type,
meaning, and the constraint a verifier enforces — and marks the **referent** as owned
elsewhere:

| Referent | Owner |
|---|---|
| trust-domain genesis document, `trust_domain_id` allocation, key enrollment / rotation / revocation events, `principal_key_accepted`, the delegation-credential document | sibling B (trust-domain genesis and key/identity lifecycle schemas) |
| bundle v3 membership statement, review-verdict payload and review-subject digest | sibling C (bundle v3 statement schema and review-verdict subject schema) |
| the preflight inventory tool and its canonical-JSON output | sibling D |

---

## OVERLAY APPLIED — 2026-08-09 (P0.1)

`RECONCILIATION.md` governs this document. The overlay has been applied in place: every clause
it supersedes now carries a **SUPERSEDED** marker stating the replacement rule where the clause
sits, so an implementer reading a section never has to know the overlay exists to implement the
right thing. Where a marker and the surrounding prose disagree, the marker wins; where the
marker and `RECONCILIATION.md` disagree, `RECONCILIATION.md` wins and the marker is a defect —
report it rather than choosing.

| Clause | Superseded by | Where the replacement now lives |
|---|---|---|
| §1.1 — 15 required top-level keys | WI-277 producer block (overlay change 5, collision 4) | §1.1, row 16 and §1.8 |
| §1.1/§4.3 — `model_lineage` under `actor.metadata` | overlay change 5, collision 20 | §1.8 — `producer.model_lineage`, never duplicated |
| §1.2 — `entity.kind ∈ {work_item, project}` | collision 5 | §1.2 — the six-value shared registry |
| §1.4 — `key_binding_event_hash` is a required string resolving to `principal_key_accepted` | overlay change 4, Resolution 1, collisions 1–3 | §1.4 and §3.5 — `string \| null`, three bootstrap positions, three anchor types |
| §1.6 — `workflow == null` ⇒ `transition == null` | overlay change 6, Resolution 3, collision 6 | §1.6 — `transition` is required non-empty on every v6 event |
| §1.6/§9.3 M1 — `NOT NULL` workflow columns | Resolution 3 | §9.3 M1 is now a **hard prerequisite of the first v6 append**, not an accompanying change |
| §6.1 — `regista.review-verdict.v1` domain | collision 15 | §6.1 — the review-specific domains in `REVIEW-VERDICTS.md` §2.3 win |
| §6.1/§10.1 — domain-separated key fingerprint | collision 8 | §6.1 — deployed raw-key SHA-256 (`TRUST-DOMAIN.md` §3.2) wins; the domained value, if kept, is `key_material_digest` |
| §8.3 `ACCEPT_V6` | all of the above | §8.3 — S6/S7/S9 updated for 16 keys, `producer`, nullable key binding, always-present transition |
| §9.4 — result-model additions "no Stage 0 document owns" | Resolution 2 | `RESULT-MODEL.md` §10 owns `VerificationResultV6` |
| §10.2–§10.4 — the worked test vector | overlay change 5 | **Obsolete. Do not use.** Regenerated under P0.3 (§10.0) |
| D-6 — `workflow_registered` payload unowned | Resolution 2 | §1.9 — workflow lifecycle, owned by this document |
| D-7 — delegation-credential document ownership ambiguous | Resolution 2 | `TRUST-DOMAIN.md` §5.12 — `regista.action-delegation/v1` |

Two further standing corrections apply to every section below:

1. **Line citations into sibling specifications are pre-overlay** unless the citing sentence
   says otherwise. Cite by section, not by line, in anything written from here on;
   `check-crossrefs.py` enforces that the target exists.
2. **`global_seq` is not chain order** (overlay change 7). Wherever this document says
   "position", it means predecessor-link traversal. There is no ordering claim in 0.6.0 that
   `global_seq` may satisfy.

---

## 0. Sources of truth

| Thing | Where |
|---|---|
| Target v6 shape (normative input) | `ARCHITECTURE-0.6.0.md` §1 "Exact v6 structure" |
| Owner decisions binding on this document | `ARCHITECTURE-0.6.0.md` § "OWNER DECISIONS ON THE THREE OPEN QUESTIONS (2026-08-08) — WI-272" |
| Canonicalizer | `src/regista/_jcs.py:8-9` → `src/regista/_vendor/rfc8785.py:120` (`dumps`) |
| JCS key ordering | `_vendor/rfc8785.py:164` — `sorted(..., key=lambda kv: kv[0].encode("utf-16be"))` |
| JCS integer domain | `_vendor/rfc8785.py:17,137` — `±(2**53 - 1)`, `IntegerDomainError` outside |
| JCS fail-closed rejections | `_vendor/rfc8785.py:56` (non-UTF-8), `:61-62` (NaN/Infinity), `:166` (non-string key) |
| Strict envelope parse | `src/regista/_verification.py:260-274` |
| Legacy strict classifier | `src/regista/_verification.py:277-296` |
| Legacy required/optional field sets | `src/regista/_verification.py:157-206` |
| Row↔envelope reconciliation | `src/regista/_verification.py:956-1062` |
| Comparators (per type) | `src/regista/_verification.py:820-916` |
| `VerificationResult` invariants | `src/regista/_verification.py:418-443` |
| Signing schemes | `src/regista/_signing_scheme.py:98-123` (HMAC), `:126-191` (Ed25519) |
| Hash-algorithm registry | `src/regista/_signing_scheme.py:8-15` |
| Legacy event/chain hash construction | `src/regista/_events.py:227-228` and `:318-322` — `sha256(canonical_envelope ‖ signature)` |
| `global_seq` assigned post-signing | `src/regista/_events.py:257-294` (`INSERT … RETURNING global_seq`); `spec.md:677-679` |
| `events` row shape | `migrations/001_initial.sql:1-17` plus 002, 014, 015, 017, 018, 030, 031 |
| Entity generalization + the alias trigger | `migrations/031_entity_generalization.sql:12-16`, `:34-47` |
| Projects catalog (no instance UUID today) | `migrations/037_projects_catalog.sql:18-24` |
| Existing size limits | `src/regista/_contract.py:14` (`MAX_JSONB_BYTES = 1_048_576`, enforced `:550-554`), `:13` (`MAX_ACTOR_METADATA_BYTES = 65536`, enforced `:620`), `:11` (`MAX_ACTOR_ID_LENGTH = 255`) |
| Workflow definition digest today | `src/regista/_workflow.py:535-540` — `sha256(JCS(definition − raw_yaml))`, undomained |
| Replay's mutable workflow oracle (S6) | `src/regista/_replay.py:1331-1344` (post-S1 location; the architecture cites the pre-S1 `_replay.py:1165-1183`) |

Two facts about the baseline that shape everything below:

1. **The canonicalizer is trustworthy and is not being replaced.** The audit attacked it and
   could not break it: RFC 8785's own mixed-script UTF-16BE ordering vectors matched, all 12
   ES6 number-serialization boundary vectors matched, and nine hostile inputs all failed
   closed (`AUDIT-REPORT.md` §4). v6 therefore changes *what* is canonicalized and *what wraps
   the result*, never the canonicalization algorithm.
2. **The signing schemes are byte-signers with no notion of envelope version.**
   `Ed25519Scheme.sign` signs exactly the byte string handed to it (`_signing_scheme.py:143-144`)
   and returns `hash_fn(envelope)` alongside (`:145-147`). This is why v6's domain separation
   can be introduced *above* the scheme layer without touching either scheme (§5.3).

---

## 1. The object

### 1.1 Top level — the complete field set

Every key is REQUIRED and must be present. There are no presence-significant fields in v6:
an optional *value* is JSON `null`, and absent-vs-null must not collapse
(`ARCHITECTURE-0.6.0.md` §1, "Rules"). This is a deliberate reversal of the v3–v5 convention,
where `prev_event_hash` / `global_seq` / `prev_global_event_hash` were emitted only when
non-`None` (`_verification.py:190`, `_signing.py:188-193`) and therefore had to be reconciled
by presence (FIELD-MATRIX §5). v6 has no such field, which removes an entire class of
reconciliation bug.

| # | Field | JSON type | Required | Meaning | Validation rule |
|---|---|---|---|---|---|
| 1 | `type` | string | yes | Artifact discriminator | MUST equal `"regista.event"` exactly. Not a hint; a literal. |
| 2 | `version` | integer | yes | Envelope version | MUST equal `6`. JSON integer, not `6.0`, not `"6"`. A JSON float that happens to be integral is rejected (mirrors `_cmp_int`, `_verification.py:837-844`). |
| 3 | `project_instance_id` | string | yes | The project's stable identity — the security boundary | Lowercase canonical UUID text, RFC 4122 form, 36 chars. MUST equal the project instance the verifier is verifying *for* (§3.2). |
| 4 | `trust_domain_id` | string | yes | The estate whose trust root governs this key material | Lowercase canonical UUID text. MUST equal the trust domain the verifier pinned. Referent owned by sibling B. |
| 5 | `event_id` | string | yes | Event identity | Lowercase canonical UUID text. Unique within the project (already the `events` PK, `001_initial.sql:2`). |
| 6 | `entity` | object | yes | The chain this event belongs to | Exactly the keys in §1.2. |
| 7 | `entity_seq` | integer | yes | 1-based position on the entity chain | Integer ≥ 1. Renamed from v4/v5 `event_seq`; the row column keeps its old name (§9.2). |
| 8 | `actor` | object | yes | Who asserted this event | Exactly the keys in §1.3. |
| 9 | `signing` | object | yes | Which key, under which scheme, authorized by which binding | Exactly the keys in §1.4. |
| 10 | `authorization` | object | yes | Direct action, or a delegation chain | Exactly the keys in §1.5. |
| 11 | `workflow` | object \| null | yes | The exact workflow definition this event's transition is evaluated against | `null` for non-workflow entities; otherwise exactly the keys in §1.6. |
| 12 | `occurred_at` | string | yes | The signer's asserted time | The single lexical form in §2.3. A **signed actor claim, not trusted time.** |
| 13 | `transition` | string | yes | Workflow or lifecycle transition name | Non-empty on every v6 event, ≤ 255 chars. |
| 14 | `payload` | object \| null | yes | Event content | JSON object or `null`. Never an array or scalar. Constrained by §2.5. |
| 15 | `chain` | object | yes | Predecessor commitments | Exactly the keys in §1.7. |
| 16 | `producer` | object | yes | The harness and model that produced this event | Exactly the keys in §1.8. **Added by WI-277**; `model_lineage` lives here and **nowhere else**. |

> **SUPERSEDED — `RECONCILIATION.md` overlay change 5 / collision 4 / collision 20.**
> The frozen 15-key contract is **16 keys**. `producer` is a required top-level member and
> `model_lineage` **moves** out of `actor.metadata` into `producer`; it is never carried in both
> (two homes for one concept produced WI-257 and WI-250). `actor.metadata` MUST NOT contain any
> of `harness`, `harness_version`, `model`, `model_lineage` — see §1.8 and §8.4 rule 7.

`len(keys(top)) == 16`, exactly. Any additional key is a rejection, not a forward-compatibility
tolerance (§8).

### 1.2 `entity`

| Field | Type | Required | Meaning | Rule |
|---|---|---|---|---|
| `kind` | string | yes | Entity class | One of the closed six-value registry below. Adding a kind is a schema change (§8.4). |
| `id` | string | yes | Entity identity | Lowercase canonical UUID text. |

> **SUPERSEDED — `RECONCILIATION.md` Resolution 4 / collision 5.** The closed set is not
> `{work_item, project}`. The shared entity-kind registry is exactly:
>
> ```
> work_item | project | principal | trust_domain | project_instance | workflow
> ```
>
> `project_system` is prose and is **never** a wire value. This registry is shared with
> `TRUST-DOMAIN.md` §5.2–§5.3 (which requires `principal`, `trust_domain` and
> `project_instance`) and with §1.9 of this document (`workflow`). One registry, six values, no
> per-document additions.
>
> The cutover checkpoint's `entity.kind` is `project` and its `entity.id` is **exactly
> `project_instance_id`** (`CUTOVER-CLASSIFICATION.md` §4.2).

`entity.kind` + `entity.id` together identify the chain. There is **no** `work_item_id` in v6
(§7).

### 1.3 `actor`

| Field | Type | Required | Meaning | Rule |
|---|---|---|---|---|
| `principal_id` | string | yes | The acting principal | Must match the WI-055 canonical grammar `(human\|agent\|service):<stable-opaque-subject>` (`ARCHITECTURE-0.6.0.md` §3). Enforced at **append** for post-cutover events; **never** enforced when verifying pre-cutover history. ≤ 255 chars (`_contract.py:11`). `key:*` is never a principal. |
| `kind` | string | yes | Execution classification | One of `{"agent","human","system"}` — the existing row CHECK (`001_initial.sql:6`). This is the *execution* kind and is deliberately allowed to differ from the `principal_id` prefix; disagreement is reported as `principal_kind_conflict`, never silently resolved (`ARCHITECTURE-0.6.0.md` §3). |
| `metadata` | object \| null | yes | Supplementary actor claims | JSON object or `null`. ≤ 65 536 bytes canonical (`_contract.py:13`). MUST NOT contain `harness`, `harness_version`, `model` or `model_lineage`; those live only in `producer` (§1.8). **Signed, but a signed assertion only** — see §4.3. |

### 1.4 `signing`

| Field | Type | Required | Meaning | Rule |
|---|---|---|---|---|
| `scheme_id` | string | yes | The signature scheme | Must be a registered scheme id (`_signing_scheme.py:74-83`). For production v6, MUST be `"ed25519"`. MUST equal the scheme of the trusted key resolved from `key_id`, **and** the row's advisory `scheme_id` column. Any disagreement is `INVALID` (§3.1). |
| `key_id` | string | yes | The signing key | Non-empty string, ≤ 255 chars. The verification key is resolved from **this** value, never from the row (`_verification.py:1321-1331` establishes the rule for legacy; v6 keeps it). |
| `key_binding_event_hash` | string \| null | yes | The project-local key-binding anchor that authorized this key in this project | `sha256:<64 lowercase hex>` (§2.4), or `null` in exactly the three bootstrap positions below. When non-null, MUST resolve to a **preceding project key-binding anchor** in **this** project's chain whose subject is `signing.key_id` bound to `actor.principal_id`. |

> **SUPERSEDED — `RECONCILIATION.md` Resolution 1 (Bootstraps A and B), overlay change 4,
> collisions 1–3.** The frozen rule ("required string, must resolve to a
> `principal_key_accepted`") is circular: the cutover checkpoint is the first v6 event in every
> legacy project, so no acceptance can precede it. Two corrections:
>
> **(a) The type is `string | null`.** `null` is valid only at these exact positions:
>
> | Event | Position | What authorises it externally |
> |---|---|---|
> | `trust_domain_established` | trust-log genesis, first v6 event | Its hash equals `trust_genesis.trust_log.initial_head_event_hash`; the genesis document verifies at root threshold; the signing key is a genesis root key. |
> | `project_cryptographic_epoch_started` | unique first v6 event of a legacy project | The payload's `bootstrap_key_acceptance` resolves through the pinned genesis and a verified trust-log checkpoint; the event signer is exactly that accepted key. |
> | `project_initialized` | genesis of a project created directly in v6 | Same, with an empty previous epoch. |
>
> A `null` anywhere else is `INVALID` / `KEY_BINDING_BOOTSTRAP_NOT_PERMITTED`. Root-threshold
> operations additionally carry their detached threshold signatures (`TRUST-DOMAIN.md` §5.4); a
> single event signature never substitutes for the threshold.
>
> **(b) The referent is widened.** "Must resolve to a `principal_key_accepted`" becomes "must
> resolve to a **preceding project key-binding anchor**", a closed set of three:
>
> 1. the cutover checkpoint's bootstrap acceptance,
> 2. the project-initialisation bootstrap acceptance,
> 3. a standalone `principal_key_accepted` event.
>
> The checkpoint/initialisation event hash is itself the project's first key-binding anchor, so
> the next event — including the first standalone `principal_key_accepted` — references *it*.
> **There is no self-referential event**: `TRUST-DOMAIN.md` §5.8's rule that the first acceptance
> signs itself is withdrawn. Bootstrap A establishes external authority, Bootstrap B imports it
> and creates project-chain order, and ordinary acceptance then runs with no exceptions.

### 1.5 `authorization`

| Field | Type | Required | Meaning | Rule |
|---|---|---|---|---|
| `mode` | string | yes | How the actor is authorized | Exactly one of `{"direct","delegated"}`. |
| `credentials` | array | yes | The delegation chain, in order from the trust root to `actor.principal_id` | MUST be `[]` when `mode == "direct"`. MUST be non-empty when `mode == "delegated"`. Elements are objects with exactly `{"credential_id","credential_hash"}` (§1.5.1). Max length 8 (§2.6). |

#### 1.5.1 Credential reference element

| Field | Type | Rule |
|---|---|---|
| `credential_id` | string | Lowercase canonical UUID text; equals the referenced credential's `credential_id`. |
| `credential_hash` | string | `sha256:<64 hex>` over the credential document, in the credential hash domain (§6). |

The event embeds the **hash**, not the credential body. The architecture's requirement that the
chain "match the signed credential hashes embedded in the event"
(`ARCHITECTURE-0.6.0.md` §1, "Delegation: WI-008", rule 6) is discharged by this field: an
auditor obtains each credential document (from a bundle v3 section, sibling C, or out of band),
recomputes its hash in the credential domain, and requires equality with the value the event
signed. Substituting a different credential therefore breaks the event signature, not merely a
side table.

The credential **document** is `regista.action-delegation/v1`, frozen at `TRUST-DOMAIN.md`
§5.12 (`RECONCILIATION.md` Resolution 2 assigned it there; DIVERGENCES D-7 is discharged). The
version at `ARCHITECTURE-0.6.0.md` §1 "Delegation: WI-008" is superseded by it. Note the two are
**not** interchangeable: an action credential never asserts `principal_kind`, so it cannot
manufacture human identity — that comes from a root/registrar-authorised `principal_registered`
event (`RECONCILIATION.md` collision 16).

Chain validity conditions (inherited verbatim from `ARCHITECTURE-0.6.0.md` §1, restated here so
the envelope contract is self-contained; the *evaluation* belongs to the verifier, not to
parsing): begin at a directly trusted or authorized principal; end at `actor.principal_id`;
no cycles; authorize this `project_instance_id`, `entity.kind`, `workflow.name` and
`transition`; unrevoked at this event's position in the project chain; hashes match.

**Historical `on_behalf_of` is not authorization.** v6 has no `on_behalf_of` field at all. For
v1–v5 events the exact signed assertion is preserved and reported as
`legacy_delegation_assertion` — never as verified delegation.

### 1.6 `workflow` (object, or `null`)

| Field | Type | Required | Meaning | Rule |
|---|---|---|---|---|
| `name` | string | yes | Canonical workflow name | Non-empty, ≤ 255 chars. |
| `version` | integer | yes | Workflow version | Integer ≥ 1. |
| `definition_hash` | string | yes | Digest of the exact workflow definition this transition is evaluated against | `sha256:<64 hex>` in the workflow-definition domain (§6). |
| `registration_event_hash` | string | yes | The signed `workflow_registered` event that introduced that definition | `sha256:<64 hex>` — an **event hash** (§6), resolving to an event in this project's chain strictly preceding this event. |

`workflow == null` iff the event is not evaluated against a workflow definition. When `workflow`
is `null`, the row's `workflow_name` / `workflow_version` columns MUST be SQL `NULL` — which
requires the migration in §9.3, because both columns are `NOT NULL` today
(`001_initial.sql:9-10`).

> **SUPERSEDED — `RECONCILIATION.md` Resolution 3 / overlay change 6 / collision 6.**
> The rule "`workflow` null ⇒ `transition` null" is withdrawn. It contradicted the checkpoint,
> which has a named lifecycle transition (`project_cryptographic_epoch_started`) and no
> workflow. The v6 rule is:
>
> - `workflow` is non-null **exactly when** the event is evaluated by a registered workflow;
> - `workflow` is `null` for project, trust, principal and workflow lifecycle events;
> - **`transition` is a required non-empty string on every v6 event.** For a workflow event it
>   is a transition of the referenced definition; for a lifecycle event it is a name from the
>   closed event catalogue. **There are no transitionless v6 events in 0.6.0.**
>
> §1.1 row 13 reads `string | null` for `transition`; for v6 the null case does not occur.
> The cross-field equality in §8.3 S9 is replaced accordingly.
>
> **`""` / `0` sentinels are rejected and never generated.** The segment seal writes them today
> (`_archive_segments.py:527-528`); in v6 the envelope would *sign* the falsehood. The forward
> migration in §9.3 M1 is therefore a **prerequisite of the first v6 append**, not an
> accompanying change. Existing legacy sentinel events keep their signed bytes and their legacy
> classification.

The `workflow_registered` event **payload** schema is owned by this document — see §1.9.
(DIVERGENCES D-6 recorded it as unowned; `RECONCILIATION.md` Resolution 2 assigned it here.)

### 1.7 `chain`

| Field | Type | Required | Meaning | Rule |
|---|---|---|---|---|
| `hash_algorithm` | string | yes | The algorithm used for this event's `event_hash` and for the two link values below | MUST be `"sha-256"` in 0.6.0 (§6.5). Must be a key of `_HASH_ALGORITHMS` (`_signing_scheme.py:8-15`). |
| `previous_entity_event_hash` | string \| null | yes | `event_hash` of the predecessor on **this entity's** chain | `sha256:<64 hex>`, or `null` iff `entity_seq == 1`. |
| `previous_project_event_hash` | string \| null | yes | `event_hash` of the predecessor on **the project's** chain | `sha256:<64 hex>`, or `null` iff this is the project's genesis event. In a store with legacy history it is never `null` — see the seam rule in §6.6. |

A `null` link and a present link are different signed bytes, so "genesis" is a signed claim, not
an inference. This closes local defect 3 from `AUDIT-REPORT.md` §3 (`_replay.py` treating a NULL
`prev_event_hash` as a passing link) by construction rather than by patch: for v6 the genesis
test comes from the signed envelope.

### 1.8 `producer` (added by the overlay — WI-277, collision 20)

| Field | Type | Required | Meaning | Rule |
|---|---|---|---|---|
| `harness` | string | yes | The agent harness that produced the event | Non-empty, ≤ 255 chars. MUST appear in the published producer policy's `allowed_harnesses` for `actor.principal_id` when a policy is pinned. |
| `harness_version` | string | yes | Its version | Non-empty, ≤ 255 chars. |
| `model` | string \| null | yes | The model, when there is one | Non-empty string, or `null` for a non-model producer. |
| `model_lineage` | string \| null | yes | Its lineage family | Non-empty string, or `null` for a non-model producer. **This is the only home for lineage in v6.** |

Exactly four keys. `producer` itself is never `null`: an event with no model producer carries
`model: null, model_lineage: null` and still names its harness. That distinction — "no model"
versus "undeclared" — is the one WI-239 had to reintroduce one layer down, and it is not
re-collapsed here.

**Why this is in the envelope and not in `actor.metadata`.** A principal is a host or a service
and holds a private key; a model holds nothing and can sign nothing. Treating a model as a
principal is the category error that left the review gate comparing self-asserted strings
(`ARCHITECTURE-FINAL.md` §3 decision 5). With per-host keys and a published
host-principal → allowed-harness policy, the producer block becomes **cross-checkable**: a
contradiction against a pinned policy is `INVALID` / `PRODUCER_POLICY_MISMATCH`; an unsupplied
policy is explicitly `policy_not_supplied`, never a silent skip.

**What it is not.** A principal-signed assertion. Matching a published policy makes
inconsistency detectable; it is not remote attestation of the process or the model
(`RECONCILIATION.md` cannot-claim item 17).

The published `producer-policy.json` — entries `{host, principal_id, key_fingerprints,
allowed_harnesses}`, root-threshold or explicitly scoped-authority signed, plus
`countersignatures: []` and `anchors: []` — is owned by `TRUST-DOMAIN.md` §4.3. Required initial
entries: `mvmcc03 → [claude-code]`, `mvmcc02 → [claude-code, opencode, codex]`,
`mvmhermes01 → [hermes]`. Many-to-many by design; one signing key per **host principal**, not
per harness.

### 1.9 Workflow lifecycle (owned here — `RECONCILIATION.md` Resolution 2)

`workflow` joins the shared `entity.kind` registry (§1.2). A workflow entity id is:

```text
UUIDv5(NAMESPACE_OID, "regista.workflow:" + project_instance_id + ":" + name + ":" + version)
```

`workflow_registered` is itself workflow-free (`workflow: null`, `transition:
"workflow_registered"`) and carries:

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

`definition` is the complete semantic definition and MUST NOT contain `raw_yaml`. The digest is
domain-separated and length-framed:

```text
b = JCS(definition)
definition_hash = SHA256(b"regista.workflow-definition.v1\x00" || uint64be(len(b)) || b)
```

Rules:

- Exactly one registration may introduce `(name, workflow_version)` in a project. A duplicate —
  **even byte-identical** — is invalid, not an alternate reference to the same definition.
- A replacement uses a new version and may name `supersedes_registration_event_hash`.
- `workflow_retired` carries `{type: "regista.workflow-retirement", version: 1, name,
  workflow_version, registration_event_hash, reason}` and shares the workflow entity chain. No
  workflow event after the retirement's **project-chain position** may reference that
  registration.
- Registration MUST strictly precede every referring event by project-chain traversal.
- A `complete-store` bundle missing the registration is **invalid**. A bounded range reports
  `not_checkable` only when the registration lies outside the declared range and is supplied as
  separately authenticated dependency evidence (`BUNDLE-V3.md` §3.2).

This is what makes `workflow.definition_hash` (§3.4) an authenticated referent rather than a
digest of a mutable `workflow_registry` row, and it is the input reducer v1 needs to be a pure
function of signed material (`REVIEW-VERDICTS.md` §2.3).

---

## 2. Type and format rules (normative)

### 2.1 UUID text

Lowercase canonical RFC 4122 text: 8-4-4-4-12 lowercase hex with hyphens, exactly 36
characters. Uppercase hex, braces, URN form (`urn:uuid:…`) and unhyphenated forms are
**rejected at parse**, not normalized. Rationale: the v1–v5 comparator normalizes both sides
before comparing (`_verification.py:820-826`) because the envelope held `str(uuid)` while the
row held a `uuid` type and the representation was a legacy artifact. v6 has no such history, so
it fixes one representation and rejects the others; normalization at the boundary is a place
where two implementations can disagree about which bytes were signed.

### 2.2 Digest strings

Every digest-valued field is the string `"sha256:"` followed by **exactly 64 lowercase hex
characters** (71 chars total). Not raw hex, not base64, not uppercase. The algorithm prefix is
part of the signed bytes so an algorithm change is visible in the signature, not inferred from
length.

### 2.3 `occurred_at`

Exactly one lexical form:

```
YYYY-MM-DDThh:mm:ss.ffffffZ
```

— RFC 3339, UTC, literal `Z`, **exactly six** fractional-second digits, no offset form, no
omitted fraction. Example: `2026-08-08T12:34:56.123456Z`.

This is a change from the v2–v5 behaviour, which signed `timestamp.isoformat()`
(`_signing.py:55`, `:87`, `:128`, `:182`), producing `+00:00` rather than `Z` and a
variable-length fraction (Python omits the fraction entirely when microseconds are 0). Fixing
the form removes the "same instant, two spellings" ambiguity that FIELD-MATRIX §2.3 had to
handle with an instant-comparison rule. For v6 the reconciliation rule is *both*: the lexical
form must match the pattern above **and** the parsed instant must equal the row's `timestamp`.

`occurred_at` is a **signed actor claim about time**. It is not trusted time, and 0.6.0 provides
no trusted timestamp (`ARCHITECTURE-0.6.0.md` § "WHAT 0.6.0 STILL CANNOT CLAIM", item 7).

### 2.4 Hash-reference resolution

`signing.key_binding_event_hash`, `workflow.registration_event_hash`,
`chain.previous_entity_event_hash` and `chain.previous_project_event_hash` are all **event
hashes** (§6.2) and MUST resolve to events in the same `project_instance_id`. A reference that
resolves to an event in another project, or to no event the verifier holds, is:

- `INVALID` when the verifier holds a complete store or a `complete-store`-scoped bundle;
- `UNVERIFIABLE` (reason: reference not resolvable in scope) when the verifier holds a declared
  partial selection. The distinction matters and must not be collapsed — it is the same
  `INVALID` / `UNVERIFIABLE` split RESULT-MODEL §5 exists to preserve.

### 2.5 `payload` and `actor.metadata` value constraints

Inherited from the canonicalizer and the existing contract module, restated because a strict
parser must enforce them on the *read* side too, not only at append:

- Numbers: **no number, integer or float, may have `|v| >= 2**53`** — see the amendment below;
  no NaN, no Infinity (`_vendor/rfc8785.py:61-62`); a JSON float is permitted but is a
  **different signed value** from the integer of equal magnitude and must never be silently
  coerced (`_cmp_int`, `_verification.py:837-844`).

> **AMENDED 2026-08-09 by P0.2 — a signable envelope with no computable digest.**
> The frozen rule bounded *integers* at `±(2**53 - 1)` and left floats to the canonicalizer.
> That is not sufficient, and the gap is reachable with an ordinary payload value.
>
> JCS serialises numbers in ES6 form, which prints any float below `1e21` **without an
> exponent**. So the float `1e16` canonicalises to the integer literal `10000000000000000`.
> A verifier parsing those canonical bytes back gets an integer of 10^16 — outside JCS's safe
> integer domain — and **cannot canonicalise it again**. The event is signable, its bytes are
> canonical, and its review-subject digest cannot be computed by anyone, ever.
>
> Measured band: floats with `2**53 <= |v| < 1e21`. At or above `1e21` ES6 switches to
> exponential form and the value round-trips; below `2**53` the integer is inside the safe
> domain.
>
> **The rule is therefore magnitude-based and applies to both types: `|v| < 2**53`.** Rejecting
> the whole large-magnitude region rather than carving out the exact band is deliberate — the
> precise rule needs a case analysis over the exponential-form threshold, and a rule two
> independent implementations must reproduce identically should be one comparison. Values that
> large are identifiers, and identifiers belong in strings.
>
> Enforced at **ingress and at parse**, on both `payload` and `actor.metadata`, with the
> conformance vectors in `tests/reducer_v1_vectors.py` (`float-1e16-as-canonical-integer`,
> `float-2-to-53-as-canonical-integer`, `int-above-safe-domain`, `float-1e21-exponential-form`).
> §8.3 S8 inherits it via "every field satisfies its type/format rule".
- Object keys must be strings (`_vendor/rfc8785.py:166`) and UTF-8 encodable (`:56`).
- `payload` canonical size ≤ 1 048 576 bytes (`_contract.py:14`).
- `actor.metadata` canonical size ≤ 65 536 bytes (`_contract.py:13`).

### 2.6 Whole-envelope bounds

| Bound | Value | Why |
|---|---|---|
| Canonical envelope size | ≤ 1 048 576 bytes | Matches the existing JSONB bound (`_contract.py:14`); a hard bound is required so a verifier can reject before allocating. |
| Nesting depth | ≤ 32 | **New.** There is no depth limit anywhere in the tree today; without one, two implementations will disagree about whether a deeply-nested payload is a valid event, and a recursive canonicalizer is a stack-exhaustion target. |
| `authorization.credentials` length | ≤ 8 | **New.** Bounds delegation-chain evaluation cost; 8 is far above any plausible real chain. |

Both new bounds are decisions this document had to make; see §11 (DD-6).

---

## 3. Why each newly-signed field is in scope

Each subsection names the attack that is open today and the property that closes it.

### 3.1 `signing.scheme_id` closes S2

**Today.** `scheme_id` appears in no envelope version (FIELD-MATRIX §3.2) and was stamped
`NOT NULL DEFAULT 'hmac-sha256'` onto every pre-015 row (`015_event_scheme_id.sql:2`). It is
read from the row on essentially every verification path. The audit's live finding
(`AUDIT-REPORT.md` §2, S2) is that relabelling an Ed25519 event as `hmac-sha256` exempted it
from asymmetric verification in the **offline bundle** path, while the bundle's own key
registry still named the key as Ed25519.

**Post-S1 state (verified, not assumed).** `verify_event_strict` derives the scheme from
trusted key metadata and returns `INVALID` with `SCHEME_MISMATCH` when the row disagrees
(`_verification.py:1349-1375`). That is the architecture's "interim" fix and it is *shipped*.
It has one residual weakness: when the resolver supplies bare key material with no scheme
metadata (`StaticKeyResolver(scheme_id=None)`, `_verification.py:683-709`), the code falls back
to the row's claim (`_verification.py:1353-1355`). The row still decides in that configuration.

**What v6 closes.** With `signing.scheme_id` inside the signed bytes, the scheme is fixed by the
signature itself. The v6 rule is a **three-way agreement**:

```
envelope.signing.scheme_id == trusted_key.scheme_id == row.scheme_id
```

Any disagreement is `INVALID`. The bare-material fallback disappears for v6, because even a
resolver with no metadata now has a signed scheme to compare against. **Attack closed:** an
attacker cannot downgrade an Ed25519 event to HMAC in any path — online, offline bundle, or a
verifier configured with raw public-key bytes — without invalidating the signature.

**Consequence for the shipped result model.** `_NEVER_SIGNED = {"global_seq", "scheme_id"}`
(`_verification.py:217`) becomes version-dependent: for v6, `scheme_id` is authenticated and
must appear in `authenticated_fields`. `global_seq` remains never-signed in every version, and
the `__post_init__` invariant forbidding it in `authenticated_fields`
(`_verification.py:430-434`) is unchanged.

### 3.2 `project_instance_id` and `trust_domain_id` close S9

**Today.** No envelope version signs any project or tenant identity (`AUDIT-REPORT.md` §2, S9;
`_signing.py:15-194` — none of the five builders emits one). A correctly signed event replays
verbatim into a different project. Project isolation is schema-per-project, and the projects
catalog keys on `schema_name` (`037_projects_catalog.sql:18-19`) — a **renameable label**, and
not in the signed scope of anything.

**What v6 closes.** `project_instance_id` is a UUID allocated once per project instance and
never reused, and it is inside the signed bytes. **Attack closed:** cross-project replay. An
event lifted from project A and inserted into project B fails verification in B, because B's
verifier requires `envelope.project_instance_id == <B's pinned instance id>`. This also closes
the weaker variant where an operator renames a schema to impersonate another project: the name
is not what is bound.

`trust_domain_id` closes the estate-level version of the same attack. Two estates can
independently allocate the same `principal_id` and the same `key_id` string — the identifiers
are opaque and locally chosen. Without a trust-domain binding, a credential (or a whole event)
from estate X could be imported into estate Y and resolve against Y's coincidentally-identical
identifiers. **Attack closed:** cross-estate credential import.

**Where the verifier's expected value comes from — and where it must not.** The pinned
`project_instance_id` and `trust_domain_id` come from the auditor's trust policy
(`ARCHITECTURE-0.6.0.md` §2, "Trust root and WI-209") or, for an online verifier, from the
signed cutover checkpoint. They must **never** come only from a mutable projection row; a
projection may cache them but a verifier that reads them from a table it is also verifying has
reconstructed the circular-trust defect (S5).

### 3.3 The `authorization` block closes WI-008

**Today.** `on_behalf_of` is signed in every version (FIELD-MATRIX §2.2), which authenticates
only *that the acting agent asserted somebody authorized it*. It proves the agent said so; it
proves nothing about the purported issuer. Worse, the pre-S1 verifier had a candidate branch
that dropped `on_behalf_of` entirely (`_signing.py:548-552` pre-S1), so an event whose row
carried a delegation could verify against an envelope that signed none — that branch is deleted
post-S1 (RESULT-MODEL §4).

**What v6 closes.** `authorization.mode` and the embedded credential hashes make the
authorization claim *checkable against independently signed artifacts*. A `delegated` event is
only authorized if a chain of separately Ed25519-signed credentials, each with its own
key-binding proof, runs from a trusted principal to `actor.principal_id` and covers this
project, entity kind, workflow and transition, unrevoked at this event's chain position.
**Attack closed:** an agent unilaterally asserting delegation it was never granted. The agent
can still *sign* such an assertion, but with v6 there is nothing for it to assert into — the
`credentials` array is empty for `direct`, and a non-empty array that does not resolve is
`INVALID`, not "delegated".

**What it does not close** (stated here because the field name invites the stronger reading):
delegation credentials prove authorization under the configured trust root, **not subjective
human intent** (`ARCHITECTURE-0.6.0.md` § "WHAT 0.6.0 STILL CANNOT CLAIM", item 9).

### 3.4 `workflow.definition_hash` and `registration_event_hash` bind replay's oracle (S6)

**Today.** Replay resolves the transition by reading `workflow_registry.definition` directly —
post-S1 at `_replay.py:1331-1344` (the architecture cites the pre-S1 `_replay.py:1165-1183`).
The `content_hash` column that could prove the definition had not changed (added by
`004_workflow_content_hash.sql:1`, computed at `_workflow.py:535-540`) **is never consulted on
that path**. `workflow_registry` is an ordinary mutable table.

**Attack.** One `UPDATE workflow_registry SET definition = …` retroactively changes what every
historical event meant. Every signature still verifies — the events signed
`workflow_name`/`workflow_version`, which did not change — and replay produces a different
final state. Nothing in the log records that the meaning of the log changed.

**What v6 closes.** `definition_hash` puts the exact definition inside the signed event, and
`registration_event_hash` makes the event causally dependent on the *signed* registration event
that introduced it. **Attack closed:** silent retroactive redefinition. A verifier reconstructs
definitions from signed `workflow_registered` events, requires the reconstructed definition's
digest to equal `workflow.definition_hash`, and treats `workflow_registry` as a rebuildable
projection with no evidentiary standing.

`registration_event_hash` also closes the weaker variant that `definition_hash` alone leaves
open: a definition digest with no signed introduction is an unattributed blob. Requiring the
registration event, at a chain position preceding this event, gives **definition-before-use**
on the same chain — the same shape as `key_binding_event_hash` gives enrollment-before-use.

### 3.5 `signing.key_binding_event_hash`

**Today.** `principal_keys` is mutated directly — post-S1 the path is
`_principal_keys.py:124-154` inside `register_principal_key_conn` (`:77`): an
`UPDATE … SET status='superseded'` at `:132-136` followed by a plain `INSERT` at `:138-146`, no
event appended anywhere. (`ARCHITECTURE-0.6.0.md` §3 cites the pre-S1 `_principal_keys.py:102-153`
for the same code.) So "this key was authorized in this project at this time" rests on a mutable
row. Cross-schema key use is worse: `agent_provenance` already carries 48k+ Ed25519
signatures whose registration evidence lives in another schema (WI-241).

**What v6 closes.** Every v6 event names the project-local `principal_key_accepted` event that
authorized its signer. Since that event is itself on the project chain, "was this key
authorized *before* it signed?" becomes a chain-position question answerable from signed
artifacts alone — no `global_seq` comparison, no cross-schema clock alignment. **Attack
closed:** back-dated key authorization, and post-revocation signing that the registry was
edited to hide.

**What it does not close:** for *historical* Ed25519 events, the retrospective attestation
(`legacy_key_binding_attested`, sibling B) does not prove contemporaneous enrollment-before-use
(`ARCHITECTURE-0.6.0.md` § "WHAT 0.6.0 STILL CANNOT CLAIM", item 4). v6 events get the real
property; legacy events get an honest label. See `CUTOVER-CLASSIFICATION.md` §3.

---

## 4. What is NOT in the envelope, and what a verifier may therefore not conclude

### 4.1 `global_seq` — permanently outside the signed scope

`global_seq` is a `BIGSERIAL` database locator assigned by `INSERT … RETURNING global_seq`
(`_events.py:257-294`), i.e. strictly after signing (`spec.md:677-679`: *"`global_seq` is
assigned **post-signing** and is NOT in the signed envelope"*). For pre-017 rows it was
**backfilled** by `ROW_NUMBER() OVER (ORDER BY timestamp, event_id)`
(`017_events_global_seq.sql:8-14`), whose own migration comment calls it "the closest stable
proxy for arrival order" — ties break on a random UUID, so the backfilled order is not append
order. Measured: 0 of 351,371 live estate envelopes contain a `global_seq` key
(FIELD-MATRIX §9).

The architecture explicitly rejects fixing this with a second signature:
per-event signed `global_seq` attestations are named in
`ARCHITECTURE-0.6.0.md` § "Work that should not enter 0.6.0", and §1 gives the reasons — a
second signature artifact per event, crash states between the two signatures, new
reconciliation rules, and no protection beyond the predecessor hash.

**v6 therefore does not contain `global_seq`, and 0.6.0 adds no ordering attestation.**

**What a verifier may NOT conclude from ordering.** Stated as prohibitions because each one is a
claim someone will otherwise make:

1. **May not** conclude that event A happened before event B because `A.global_seq <
   B.global_seq`. Order is established *only* by walking `chain.previous_project_event_hash`
   (project order) and `chain.previous_entity_event_hash` + `entity_seq` (entity order).
2. **May not** conclude completeness from a contiguous `global_seq` range. Gaps are normal
   (rolled-back transactions consume sequence values) and contiguity is trivially forgeable by
   an attacker with row-write access.
3. **May not** report `global_seq` in `authenticated_fields`, in any version. This is asserted
   as a class invariant, not a convention (`_verification.py:430-434`).
4. **May not** use a `global_seq` watermark as a security boundary. It bounds *policy scope*
   only (`_verification.py:332-345`); `CUTOVER-CLASSIFICATION.md` §6 replaces it for v6 with a
   chain-position boundary, which is cryptographically determined.
5. **May not** conclude that the chain is complete at the tail. Truncation after the last
   externally published checkpoint remains undetectable
   (`ARCHITECTURE-0.6.0.md` § "WHAT 0.6.0 STILL CANNOT CLAIM", item 6).

Signed checkpoints and bundle membership statements may carry an **informational maximum
`global_seq`** (`ARCHITECTURE-0.6.0.md` §1) — informational meaning it may be displayed and
compared, and may never be the sole proof of order or completeness.

### 4.2 Other things deliberately absent

| Absent | Why | What a verifier may not conclude |
|---|---|---|
| `work_item_id` | Superseded by `entity` (§7) | Nothing: the row column survives but is unsigned and constrained to equal `entity.id`. |
| `on_behalf_of` | Superseded by `authorization` (§3.3) | A v6 event never carries a bare delegation assertion; any `on_behalf_of` found in a v6 row is a row-only artifact and must be reported, not read. |
| `event_hash` / `signature` / `payload_canonical_hash` | Outputs of signing, not inputs to it (FIELD-MATRIX §3.4) | They are never reconcilable envelope fields and never appear in `authenticated_fields`. |
| `scheme_id` for the *bundle* signer, anchor state, segment membership | Not event properties | Segments and anchoring are deleted in 0.6.0 (`ARCHITECTURE-0.6.0.md` §7, §8). |
| A `previous_epoch` marker on ordinary events | Only the checkpoint carries epoch data | Epoch membership is a chain-position property, not a per-event claim (`CUTOVER-CLASSIFICATION.md` §2). |

### 4.3 `actor.metadata` is signed but is only an assertion

`actor.metadata` is inside the signed bytes because lineage and actor-kind policy consume it
(`ARCHITECTURE-0.6.0.md` §1). Per the owner's binding decision on open question 3, 0.6.0 claims
only a **principal-signed model-lineage assertion**. A signature proves *who asserted*, never
*what generated the action*. Any verifier field derived from `actor.metadata` must be named so
that the name does not promise more than the check performs — the rule the owner applied to
both WI-263 and assurance-level naming.

---

## 5. Canonicalization and what the signature covers

### 5.1 What is canonicalized

Exactly the 16-key top-level object of §1, with its nested objects, and nothing else. Not the
row. Not the signature. Not the event hash. Not any derived column.

### 5.2 In what order

RFC 8785 (JCS), unchanged, as vendored at `src/regista/_vendor/rfc8785.py` and reached through
`regista._jcs.canonicalize` (`_jcs.py:8-9`). The ordering rule is JCS's: at **every** object
level, keys sort by their **UTF-16BE code-unit encoding** (`_vendor/rfc8785.py:164`), not by
Unicode code point and not by UTF-8 bytes. Arrays keep their given order. There is no
whitespace and no insignificant formatting.

Concretely, the top-level key order in the canonical bytes is:

```
actor, authorization, chain, entity, entity_seq, event_id, occurred_at,
payload, producer, project_instance_id, signing, transition, trust_domain_id,
type, version, workflow
```

— which is frozen by `tests/vectors/v6/v6-envelope-canonical-order.json` and is *not* the
declaration order of §1.1. The inline worked example in §10 is explicitly obsolete and does not
contain `producer`. Implementations must never assume declaration order.

### 5.3 The signing pipeline, exactly

```text
canonical_envelope := JCS(v6_object)                       # bytes, stored verbatim

signature_input    := b"regista.event.v6\x00" || canonical_envelope

signature          := Sign(signing_key, signature_input)   # Ed25519 over signature_input

payload_canonical_hash := SHA256(signature_input)          # the row column, see §9.2

event_hash := SHA256(
                 b"regista.event.hash.v1\x00"
              || uint64be(len(canonical_envelope))
              || canonical_envelope
              || signature
              )
```

`uint64be` is 8 bytes, big-endian, unsigned.

**The signature covers `signature_input`** — the domain tag *and* the canonical envelope. It
does not cover the event hash (which contains the signature and therefore cannot), nor
`global_seq`, nor any row column not represented in the envelope.

**Why the domain tag goes above the scheme, not inside it.** `Ed25519Scheme.sign` signs exactly
the byte string it is handed (`_signing_scheme.py:143-144`) and returns `hash_fn(envelope)`
alongside (`:145-147`). Passing `signature_input` as that argument gives, with **no change to
either scheme**: a signature over the domain-tagged bytes, and a `payload_canonical_hash`
that is the hash of the same tagged bytes. The `scheme_id` stays `"ed25519"` — the domain is a
property of the *envelope version*, not of the algorithm, and inventing `"ed25519-v6"` would
put version information in a field that the trusted key registry also has to agree with (§3.1),
which is a second source of truth for one fact.

**Why the tag makes cross-version confusion structurally impossible.** A v1–v5 signature input
is `JCS(obj)`, which always begins with `{` (`_vendor/rfc8785.py` object serialization). A v6
signature input always begins with `regista.event.v6\x00`. No byte string is both. Therefore no
v5 signature can ever be presented as a v6 signature, or vice versa, even if an attacker could
construct colliding JSON — which JCS's fail-closed rejections (§0) already prevent.

**Why the length prefix is in the event hash.** `event_hash` concatenates two variable-length
byte strings (`canonical_envelope` and `signature`). Without a length prefix, `(env, sig)` and
`(env', sig')` with `env ‖ sig == env' ‖ sig'` hash identically. Ed25519 signatures are fixed at
64 bytes, so the ambiguity is not currently reachable — but the legacy construction
(`sha256(canonical_envelope ‖ signature)`, `_events.py:227-228`, `:318-322`) has no length
prefix and no domain tag, and would become genuinely ambiguous the moment a variable-length
scheme is registered. v6 fixes it once.

### 5.4 The stored bytes are authoritative — and must be a JCS fixed point

The S1 rule is unchanged and non-negotiable: **verify the exact stored bytes; never rebuild a
candidate from row columns** (RESULT-MODEL §4; the fallback is deleted, not disabled).

v6 adds one requirement that v1–v5 do not have:

> **JCS fixed-point.** After strict parsing, `JCS(parsed_object)` MUST equal the stored bytes,
> byte for byte. If it does not, the envelope is `INVALID` (`ENVELOPE_UNCANONICAL`).

`parse_envelope_strict` (`_verification.py:260-274`) already rejects duplicate keys, NaN/Infinity
and a non-object top level — everything JCS could not have emitted *structurally*. The
fixed-point check additionally rejects everything JCS could not have emitted
*lexically*: unsorted keys, non-minimal number forms, alternative escape sequences, inserted
whitespace. Without it, two byte strings that parse to the same object can both be presented,
and only one of them is what the signer signed. With it, there is exactly one acceptable
encoding of any v6 event.

This check is specified for **v6 only**. Applying it to v1–v5 would be a behaviour change
affecting 351k+ existing events, and this document has not measured whether all of them are JCS
fixed points. Recommended for sibling D's preflight: measure it. If it is 100% across the
estate, the rule can be extended to legacy in a later release; until measured, extending it
would risk converting honest history into `INVALID`. (Least-confident item LC-3.)

---

## 6. Hash domains

### 6.1 The registry

Every hash regista computes gets a distinct, non-empty ASCII domain tag terminated by a `0x00`
byte, prepended to the hashed input. The `0x00` terminator matters: without it, tags where one
is a prefix of another (`regista.event.hash.v1` and `regista.event.hash.v10`) could be made to
collide by shifting a byte from the tag into the message.

| Domain tag (ASCII, `\x00`-terminated) | Hashes what | Produces | Owner |
|---|---|---|---|
| `regista.event.v6` | `canonical_envelope` | the **signature input** (not itself hashed by us; hashed internally by Ed25519) | this document |
| `regista.event.hash.v1` | `uint64be(len(env)) ‖ env ‖ signature` | `event_hash` | this document |
| `regista.workflow-definition.v1` | `uint64be(len(JCS(definition))) ‖ JCS(definition)` | `workflow.definition_hash` | this document (§1.9, §6.4) |
| `regista.action-delegation.v1` | `uint64be(len(doc)) ‖ JCS(credential_document − signature)` | action-delegation signature input | `TRUST-DOMAIN.md` §5.12 |
| `regista.action-delegation.hash.v1` | the credential document | `credential_hash` | `TRUST-DOMAIN.md` §5.12 |
| `regista.key.fingerprint.v1` | — | **WITHDRAWN — see the marker below** | — |
| `regista.checkpoint.v1` | `JCS(checkpoint_statement)` | externally published checkpoint digest | `CUTOVER-CLASSIFICATION.md` §4 |
| `regista.audit-bundle.v3` | `JCS(membership_statement)` | bundle membership signature input | sibling C (tag fixed by `ARCHITECTURE-0.6.0.md` §2) |
| `regista.bundle.member.v1` | `uint64be(scope_ordinal) ‖ event_hash` | membership-tree leaf | `BUNDLE-V3.md` §3.3 |
| `regista.bundle.node.v1` | `left ‖ right` | membership-tree interior node | `BUNDLE-V3.md` §3.3 |
| `regista.review-subject.state.v1` | `JCS(reduce(E[0..k]))` | `content_state_digest` | `REVIEW-VERDICTS.md` §2.3 |
| `regista.review-subject.v1` | `JCS(review_subject)` | `subject_digest` | `REVIEW-VERDICTS.md` §2.3 |

> **SUPERSEDED — `RECONCILIATION.md` Resolution 4, collisions 8, 10 and 15.** Four rows of the
> frozen registry changed:
>
> 1. **Key fingerprint is not domain-separated.** `regista.key.fingerprint.v1` is **withdrawn**.
>    The fingerprint is `ed25519:sha256:<SHA256(raw_public_key)>` — the deployed construction
>    (`TRUST-DOMAIN.md` §3.2), which matches values already in the estate. Compatibility wins
>    over tidiness here because the alternative silently invalidates every recorded fingerprint.
>    If a domain-separated digest of key material is wanted for another purpose, it is called
>    `key_material_digest` and it is **not** a fingerprint.
> 2. **`regista.review-verdict.v1` is withdrawn.** The review-specific domains
>    (`regista.review-subject.state.v1`, `regista.review-subject.v1`) own the concept. Reinstate
>    a whole-verdict digest only if one is specified, and then under a distinct name.
> 3. **The bundle leaf has no leading `0x00` beyond the tag terminator**, is ordinal-framed by
>    `scope_ordinal` (local to the signed scope, and derived from **chain traversal, never
>    `global_seq`**), and interior nodes use `regista.bundle.node.v1` with RFC-6962
>    split-at-largest-power-of-two. Freeze byte vectors for both (P0.3).
> 4. **The delegation document** is `regista.action-delegation/v1` with two domains (signature
>    input and hash), owned by `TRUST-DOMAIN.md` §5.12. The old single `regista.delegation.v1`
>    row is replaced. `regista.workflow.definition.v1` is likewise renamed to
>    `regista.workflow-definition.v1` and is now length-framed (§1.9).

The tags marked "fixed by `ARCHITECTURE-0.6.0.md`" are reproduced here only so the registry is
complete and collisions are visible in one place. The owning documents named in the last column
own their rows; if one chooses a different string, **this table is the defect report**, not the
place to diverge — the whole point of a registry is that it is one table.

### 6.2 `event_hash` is the single event identifier for hash references

`signing.key_binding_event_hash`, `workflow.registration_event_hash`,
`chain.previous_entity_event_hash` and `chain.previous_project_event_hash` all carry an
`event_hash` as defined in §5.3. They are the same *kind* of value; their differing *roles* are
carried by the signed field name (§6.3).

### 6.3 How a value from one domain cannot be replayed as another

Three mechanisms, in decreasing order of strength:

1. **Preimage disjointness.** No two domains hash inputs with the same tag, and every tag is
   `\x00`-terminated, so no message in domain X can be parsed as a message in domain Y. To
   present a workflow-definition digest as an event hash, an attacker would need
   `SHA256("regista.workflow-definition.v1\x00" ‖ L' ‖ D) == SHA256("regista.event.hash.v1\x00" ‖ L ‖ E ‖ S)`
   — a SHA-256 collision across differing prefixes.
2. **Role binding by signed field name.** Within the envelope, a hash's role is fixed by the
   key it sits under, and that key is part of the canonical bytes the signature covers. Moving
   a value from `previous_entity_event_hash` to `previous_project_event_hash` changes the
   canonical bytes and invalidates the signature. **This is why the two chain links share the
   `event_hash` domain rather than getting wrapper domains of their own** — see §6.7 and DD-1.
3. **Length and shape.** Every digest field is the fixed 71-character `sha256:`+64-hex form
   (§2.2), so a raw 32-byte value, a base64 digest, or a longer digest is a parse rejection
   before any comparison happens.

### 6.4 `workflow.definition_hash` vs the existing `content_hash`

`compute_content_hash` today is `sha256(JCS(definition − raw_yaml))` with **no domain tag**
(`_workflow.py:535-540`), stored in `workflow_registry.content_hash`
(`004_workflow_content_hash.sql:1`). v6's `definition_hash` is
`sha256("regista.workflow-definition.v1\x00" ‖ uint64be(len(b)) ‖ b)` where `b = JCS(definition)`
(§1.9 — the domain was renamed and length-framed by `RECONCILIATION.md` Resolution 2, and
`definition` must not contain `raw_yaml` in the first place).

They are therefore **different values over the same input**, deliberately. Consequences an
implementer must handle:

- The existing `content_hash` column is not a valid `definition_hash` and must not be copied
  into one.
- The `workflow_registered` event carries the complete canonical definition
  (`ARCHITECTURE-0.6.0.md` §3), so `definition_hash` is always recomputable from signed data;
  the column becomes a projection like everything else.
- The `raw_yaml` exclusion is preserved exactly as `_workflow.py:536` does it — the digest
  covers the parsed definition, not the source text, so reformatting YAML does not invalidate
  history. This is existing behaviour and is being kept, not chosen anew.

### 6.5 Hash-algorithm agility is deliberately not exercised in 0.6.0

`chain.hash_algorithm` is a signed field, and the registry (`_signing_scheme.py:8-15`) has six
algorithms. **0.6.0 accepts only `"sha-256"`.** The reason is that the domain tags above do not
encode the algorithm: `regista.event.hash.v1` names a construction, not a digest function, so
two events using different algorithms would produce values in the *same* domain with different
semantics. Introducing a second algorithm requires a tag that names it (e.g.
`regista.event.hash.sha512.v1`), which is a schema change, not a configuration change. Fixing
this now costs nothing and prevents an agility feature from silently reopening domain
confusion.

The field is nevertheless *present and signed* so that the future change is expressible without
a new envelope version — the same reasoning the owner applied to leaving format room for a
custodian countersignature in the publication channel.

### 6.6 The legacy seam: the one event whose links are not v6-domain hashes

The cutover checkpoint's `chain.previous_project_event_hash` must equal **the legacy head**
(`ARCHITECTURE-0.6.0.md` §4, "The checkpoint's own `previous_project_event_hash` must equal the
legacy head"). The legacy head is computed by the legacy construction, `sha256(canonical_envelope ‖ signature)`
with no domain tag and no length prefix (`_events.py:227-228`, `:318-322`).

So the checkpoint carries, in a v6 field, a value computed in the **legacy** hash domain. This
is unavoidable — the legacy head is what it is, and re-hashing it in the v6 domain would break
the property the checkpoint exists to provide, namely that an auditor can walk the legacy chain
by its own rules and arrive at exactly the named value.

**Normative seam rule.**

1. Exactly one v6 event per `project_instance_id` may carry a legacy-domain
   `previous_project_event_hash`: the cutover checkpoint (§ `CUTOVER-CLASSIFICATION.md` §4).
2. The checkpoint's payload MUST state the construction explicitly, so no verifier has to infer
   it. This document requires a field the architecture's payload sketch does not have:
   `previous_epoch.head_hash_construction`, whose only permitted 0.6.0 value is
   `"sha256(canonical_envelope||signature)"`. See DIVERGENCES D-2.
3. Every other v6 event's `previous_project_event_hash` is a v6-domain `event_hash`.
4. The checkpoint's `previous_entity_event_hash` is `null` and its `entity_seq` is `1`: it is
   the first event on a *new* project-system entity, which has no predecessor.

A verifier that does not implement rule 2 will silently accept either construction, which
reintroduces exactly the domain confusion §6.3 exists to prevent.

### 6.7 Why the two chain links share one domain

The brief for this document asked for distinct domains for the event hash, the entity-chain
link and the project-chain link. This document specifies **one** domain (the event hash) for
both links. The reasoning, stated rather than assumed:

- The role of a link is already cryptographically bound, by the signed field name it appears
  under (§6.3, mechanism 2). Wrapping adds no coverage against an attacker who cannot forge a
  signature, and against an attacker who *can* forge one, wrapping is irrelevant.
- A wrapped link would make the legacy seam (§6.6) worse: the checkpoint's link would have to
  be `H(domain ‖ legacy_head)`, so an auditor walking the legacy chain would not see the value
  they computed. The whole binding argument becomes an extra derivation step the auditor must
  trust the tooling to have done correctly.
- Bundle v3's membership leaves already wrap `event_hash` in their own domain
  (`regista.bundle.member.v1`, `ARCHITECTURE-0.6.0.md` §2), which is the case where a bare
  value *does* travel outside its signed context and therefore *does* need wrapping. That is
  the correct discriminator: wrap when a value leaves the object that names its role; do not
  wrap when the object names it.

If the owner prefers wrapped links, the change is mechanical — two new domain tags,
`regista.chain.entity.v1` and `regista.chain.project.v1`, applied to the predecessor's
`event_hash` — plus an explicit exemption for the checkpoint. This is recorded as DD-1 so the
decision is reversible with a known diff.

---

## 7. `work_item_id` vs `entity_id`, and the column's fate

### 7.1 The alias direction, corrected

An earlier brief described `work_item_id` as "a compatibility alias per migration 031". The
dependency runs the **other way**, and it matters:

- `work_item_id` is the **original** column, `NOT NULL` since `001_initial.sql:3`.
- `entity_id` is the **derived** one, added by `031_entity_generalization.sql:13`, backfilled
  unconditionally by `UPDATE events SET entity_id = work_item_id` (`031:16`), and filled on
  insert from `work_item_id` by the `events_set_entity_id` BEFORE INSERT trigger (`031:34-47`).

The security consequence is unchanged and is what matters: **from v4 onward the signature covers
`entity_id`, and `work_item_id` is unauthenticated** (FIELD-MATRIX §2.1). This is already
enforced post-S1: the alias check at `_verification.py:1039-1059` requires
`row.work_item_id == row.entity_id` for v4 and v5, treating a NULL on either side as a mismatch
because both columns are `NOT NULL` in the schema — a NULL is already evidence that something
other than the append path wrote the row.

That shipped check also **resolves FIELD-MATRIX §8.1's open question** ("all entity kinds, or
only `work_item`?") in favour of universal enforcement: `_verification.py:1044` scopes it by
*envelope version*, not by entity kind. v6 keeps that answer.

### 7.2 v6 is `entity` only

Per the owner's approval of the stricter default (`ARCHITECTURE-0.6.0.md` §1, "`work_item_id`
versus `entity_id`"):

- **The v6 envelope has no `work_item_id`.** `entity.kind` + `entity.id` is the whole identity.
- The double representation is gone from the signed scope, so there is nothing to reconcile
  between two spellings of the same fact.

### 7.3 What happens to the column

| Concern | Rule |
|---|---|
| Does the column survive 0.6.0? | **Yes**, `NOT NULL`, unchanged. Dropping a `NOT NULL` column that ~20 read paths use is not a cutover-week change, and the architecture explicitly permits retaining it "as a work-item projection/FK convenience". |
| What does a v6 writer put in it? | `entity.id`, for **every** entity kind — matching the existing segment-seal precedent, which writes the segment id into both columns (`_archive_segments.py:518,521`, inside the insert at `:508-540`). |
| What does a v6 verifier require? | `row.work_item_id == row.entity_id`, universally, exactly as the shipped v4/v5 check does (`_verification.py:1039-1059`). A NULL on either side is a mismatch. Failure is `ENTITY_ALIAS_MISMATCH` → `INVALID`. |
| Is it authenticated? | **No.** `work_item_id` appears in `unsigned_fields` for v6, as it does for v4/v5 (`_verification.py:951-952`). It is *constrained* to equal a signed value, which makes it safe to read; it is not itself signed. |
| The `events_set_entity_id` trigger | **Drop it in 0.6.0** (forward migration; do not edit `031`). v6 writers always supply `entity_id`, so the trigger is inert for new events, and its continued existence means a bug that omits `entity_id` gets silently papered over instead of failing. Note it is a BEFORE **INSERT** trigger only — it never fired on UPDATE, which is why the alias check is load-bearing (`_verification.py:894-899`). |
| When may it be dropped? | After 0.6.0, as a separate release, once every read path uses `entity_id`. Not during the cutover. |

---

## 8. Strict parsing: the acceptance predicate

### 8.1 The failure this replaces

The pre-S1 classifier used `issuperset`, so any *subset* of a version's fields — including
`{}` and an attacker-authored object — fell through to `return 1` and was treated as a v1
envelope, the weakest possible claim and therefore the most attractive target (RESULT-MODEL §3;
the replacement is documented in place at `_signing.py:277-289` and implemented at
`_verification.py:277-296`). v6 must not merely inherit the fix; it must be *unable* to
participate in it.

### 8.2 Version dispatch — total, and one-way

No v1–v5 envelope contains a `type` or a `version` key: the complete legacy field sets are
`_verification.py:157-185`, and neither name appears in any of them. That makes dispatch
unambiguous:

```
CLASSIFY(obj):
    if "type" in obj or "version" in obj:
        # Only v6 has these. There is NO fallback to the legacy classifier from
        # here: an object that announces a version and then fails v6 validation
        # is UNKNOWN_SCHEMA, never "maybe it's a v1".
        return V6 if ACCEPT_V6(obj) else UNKNOWN_SCHEMA
    return LEGACY_CLASSIFY(obj)        # _verification.py:277-296, unchanged
```

The one-way property is the point. The pre-S1 defect was that failing to be a high version
*promoted* an object to a low one. Here, failing to be v6 after claiming to be versioned is
terminal.

### 8.3 `ACCEPT_V6` — the exact predicate

```
ACCEPT_V6(bytes B) :=

  S1.  len(B) <= 1_048_576                                    else UNKNOWN_SCHEMA
  S2.  obj := parse_envelope_strict(B)                        else UNPARSEABLE
         # _verification.py:260-274 — rejects duplicate keys, NaN/Infinity,
         # and a non-object top level
  S3.  depth(obj) <= 32                                       else UNKNOWN_SCHEMA
  S4.  JCS(obj) == B                                          else UNCANONICAL   (§5.4)
  S5.  obj["type"] == "regista.event"                         else UNKNOWN_SCHEMA
       and obj["version"] is int and obj["version"] == 6
       and obj["version"] is not bool
  S6.  set(obj.keys()) == V6_TOP_KEYS                         else UNKNOWN_SCHEMA
         # EQUALITY, not superset and not subset. 16 keys, §1.1.
  S7.  set(obj["entity"].keys())        == {"kind","id"}
       set(obj["actor"].keys())         == {"principal_id","kind","metadata"}
       set(obj["signing"].keys())       == {"scheme_id","key_id","key_binding_event_hash"}
       set(obj["authorization"].keys()) == {"mode","credentials"}
       set(obj["producer"].keys())      == {"harness","harness_version",
                                            "model","model_lineage"}
       set(obj["chain"].keys())         == {"hash_algorithm",
                                            "previous_entity_event_hash",
                                            "previous_project_event_hash"}
       and if obj["workflow"] is not None:
           set(obj["workflow"].keys())  == {"name","version",
                                            "definition_hash",
                                            "registration_event_hash"}
       and every credential element's keys == {"credential_id","credential_hash"}
                                                                else UNKNOWN_SCHEMA
  S8.  every field satisfies its type/format rule (§1, §2)      else UNKNOWN_SCHEMA
  S9.  cross-field consistency:
         obj["transition"] is a non-empty string             # §1.6, always
         obj["entity"]["kind"] in {"work_item","project","principal",
                                   "trust_domain","project_instance","workflow"}
         (obj["authorization"]["mode"] == "direct")
             == (obj["authorization"]["credentials"] == [])
         (obj["chain"]["previous_entity_event_hash"] is None)
             == (obj["entity_seq"] == 1)
         obj["signing"]["key_binding_event_hash"] is None
             ⇒ obj["transition"] in {"trust_domain_established",
                                      "project_cryptographic_epoch_started",
                                      "project_initialized"}   # §1.4(a); position and
                                                               # external authorisation are
                                                               # checked by the verifier, not
                                                               # by the parser
         no key of obj["actor"]["metadata"] is in
             {"harness","harness_version","model","model_lineage"}   # §1.8
                                                                else UNKNOWN_SCHEMA
  => V6
```

> **SUPERSEDED — the predicate above is the overlay-corrected one.** Three changes against the
> frozen text, all forced by `RECONCILIATION.md`: S6 counts **16** keys; S7 requires `producer`;
> S9 drops `(workflow is None) == (transition is None)` in favour of "`transition` is always a
> non-empty string" (Resolution 3), adds the closed entity-kind set (collision 5), adds the
> bootstrap-only rule for a null `key_binding_event_hash` (Resolution 1), and forbids the four
> producer keys inside `actor.metadata` (collision 20).
>
> A parser cannot tell whether a null key binding is *legitimately* at a bootstrap position —
> that needs chain position and external trust material. So the parser checks the transition
> name only, and the verifier is what returns
> `INVALID` / `KEY_BINDING_BOOTSTRAP_NOT_PERMITTED` when the position or the external
> authorisation does not hold. **Splitting the check must not soften it**: a build that
> implements the parse half and skips the verifier half accepts a forged bootstrap.

`UNKNOWN_SCHEMA`, `UNPARSEABLE` and `UNCANONICAL` all map to
`Applicability.INVALID`, never `UNVERIFIABLE` — the envelope exists and its bytes are wrong
(RESULT-MODEL §3, rule 3). `UNVERIFIABLE` remains reserved for "there is no envelope to
evaluate".

### 8.4 Fail-closed rules that follow

1. **Unknown fields are rejected**, at every nesting level. No forward-compatibility tolerance:
   an unknown key in a signed envelope is either a future version this build cannot evaluate or
   an attacker's field, and both must halt rather than degrade (RESULT-MODEL §3, rule 2).
2. **Unknown versions are rejected.** `version == 7` is `UNKNOWN_SCHEMA`. An old binary
   encountering a future envelope fails closed, which is the required behaviour at
   `ARCHITECTURE-0.6.0.md` § SEQUENCING Stage 6 ("old binaries fail safely after schema
   capability change").
3. **A missing required field is `UNKNOWN_SCHEMA`, never a lower version.** A v6 envelope
   missing `authorization` is not a v5 event.
4. **Unknown enum members are rejected**: an `entity.kind`, `actor.kind`,
   `authorization.mode`, `signing.scheme_id` or `chain.hash_algorithm` outside its closed set is
   a parse rejection, not an "unknown but tolerated" value. Adding a member is a schema change
   that requires updating this document.
5. **Nothing about the row informs the version.** Classification operates on the stored bytes
   only — the rule the post-S1 code already follows and the pre-S1 code violated by computing
   `has_chain_fields` from row values (RESULT-MODEL §3, rule 5).
6. **There is no policy flag that relaxes any of the above.** A flag would be the silent pass
   (RESULT-MODEL §6, mechanism 6).
7. **The producer keys are forbidden in `actor.metadata`.** `harness`, `harness_version`,
   `model` and `model_lineage` appearing there is `UNKNOWN_SCHEMA`, not a duplicate to
   reconcile. Two homes for one concept is the shape that produced WI-257 and WI-250; rejecting
   it at parse is what stops the second home from growing back. (Overlay collision 20.)

---

## 9. The row projection for v6

### 9.1 The governing rule is unchanged

> The stored canonical envelope is the cryptographic artifact. The row is its indexed
> projection. Verify the exact stored bytes; then require every field that envelope version
> signs to agree with its row representation before any consumer reads the row.

(FIELD-MATRIX, governing rule; implemented at `_verification.py:956-1062`.)

### 9.2 v6 field ↔ row column map

| v6 envelope field | Row column | Comparison rule | Notes |
|---|---|---|---|
| `event_id` | `events.event_id` | UUID equality | Both sides already canonical lowercase in v6. |
| `entity.kind` | `events.entity_kind` | exact string | |
| `entity.id` | `events.entity_id` | UUID equality against the **real** column, never `effective_entity_id` (`_verification.py:894-900`) | A NULL row value is a mismatch. |
| `entity_seq` | `events.event_seq` | integer equality | **Name change**: envelope `entity_seq` ↔ column `event_seq`. The column is not renamed (it is in indexes and a unique constraint, `031:28-29`). |
| `actor.principal_id` | `events.actor_id` | exact string | |
| `actor.kind` | `events.actor_kind` | exact string | Must satisfy the existing CHECK (`001_initial.sql:6`). |
| `actor.metadata` | `events.actor_metadata` | canonical JCS bytes (`_cmp_json`, `_verification.py:876-886`) | envelope `null` ⇔ row `NULL`. |
| `signing.scheme_id` | `events.scheme_id` | exact string, **and** equality with the trusted key's scheme | Now authenticated (§3.1). |
| `signing.key_id` | `events.key_id` | exact string | Key resolution uses the **envelope** value. |
| `occurred_at` | `events.timestamp` | lexical form (§2.3) **and** instant equality (`_cmp_timestamp`, `_verification.py:847-864`) | |
| `transition` | `events.transition` | exact string, null ⇔ NULL | |
| `payload` | `events.payload` | canonical JCS bytes | Never raw text; `jsonb` does not preserve key order. |
| `workflow.name` | `events.workflow_name` | exact string; envelope `workflow == null` ⇒ row `NULL` | Requires the migration in §9.3. |
| `workflow.version` | `events.workflow_version` | integer; envelope `workflow == null` ⇒ row `NULL` | Same. |
| `chain.previous_entity_event_hash` | `events.prev_event_hash` | decode `sha256:<hex>` → 32 bytes, compare to BYTEA; null ⇔ NULL | Column reused. |
| `chain.previous_project_event_hash` | `events.prev_global_event_hash` | same | Column reused. |
| `chain.hash_algorithm` | `events.hash_alg` | exact string | |
| — | `events.work_item_id` | constrained `== entity_id`, **unsigned** | §7.3. |
| — | `events.global_seq` | **never** compared, **never** authenticated | §4.1. |
| — | `events.canonical_envelope` | *is* the artifact | Verified, not compared. |
| — | `events.signature` | over `signature_input` | Not an envelope field. |
| — | `events.payload_canonical_hash` | `SHA256(signature_input)` | **Changed for v6**: legacy stores `SHA256(canonical_envelope)`. See §9.4. |
| `project_instance_id`, `trust_domain_id`, `signing.key_binding_event_hash`, `authorization.*`, `workflow.definition_hash`, `workflow.registration_event_hash`, `type`, `version` | **no column** | read from the envelope | §9.3, rule N1. |

### 9.3 Required schema changes (forward migrations only)

`ARCHITECTURE-0.6.0.md` § SEQUENCING Stage 4: "Do not rewrite old migration files; add forward
migrations so existing stores upgrade safely."

| # | Change | Why |
|---|---|---|
| M1 | `ALTER TABLE events ALTER COLUMN workflow_name DROP NOT NULL; ALTER COLUMN workflow_version DROP NOT NULL` | v6 project-system events have `workflow == null` (§1.6), and both columns are `NOT NULL` today (`001_initial.sql:9-10`). Without this, the cutover checkpoint cannot be inserted — or, worse, is inserted with the segment seal's `""`/`0` sentinels (`_archive_segments.py:527-528`), which v6 would then *sign*. **On the critical path of the ceremony**, and a **prerequisite of the first v6 append** — `RECONCILIATION.md` Resolution 3. Owned by P1.2; acceptance is that the migration applies *and rolls back* cleanly on a copy of the live schema set and that a checkpoint inserts with genuinely null workflow identity. Apply the same change to `events_archive` only if archive consolidation has not already removed that table. |
| M2 | `ALTER TABLE events ADD COLUMN envelope_version SMALLINT NULL` | Operational counting (the checkpoint payload needs per-version counts) and index-supported epoch queries. **Advisory only:** it must be reconciled against the derived classification and must never select the parser. NULL for pre-migration rows; the preflight (sibling D) backfills it from the classifier, and that backfill is one more unsigned column the verifier must reconcile rather than trust. |
| M3 | `ALTER TABLE events ADD COLUMN event_hash BYTEA NULL` + `CREATE UNIQUE INDEX … ON events (event_hash) WHERE event_hash IS NOT NULL` | Chain traversal by hash reference (§2.4) is O(n) without it. **Cache only:** every verifier recomputes it (§5.3) and compares; a mismatch is `INVALID`. |
| M4 | `CREATE TABLE project_identity (id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id), project_instance_id UUID NOT NULL, trust_domain_id UUID NOT NULL, cutover_event_id UUID NOT NULL)` — single-row | The project needs a local answer to "which instance am I?". **Projection only**, rebuilt from the signed cutover checkpoint; a verifier takes the expected value from the trust policy, not from this table (§3.2). |
| M5 | `DROP TRIGGER events_set_entity_id ON events` | §7.3. |
| M6 | Widen `events.actor_kind` CHECK **only if** a new execution kind is needed | Not currently needed; listed so the omission is deliberate. |

**Rule N1 — do not add a column for every new signed field.** `project_instance_id`,
`trust_domain_id`, the `authorization` block, `key_binding_event_hash` and the workflow digests
get **no** row columns. Every duplicated column is reconciliation surface and a place a
consumer can read the unsigned copy; the entire S1 defect class comes from consumers reading
row columns. Verifiers and consumers read these from the parsed envelope. If an index becomes
necessary later, add it as a column with mandatory reconciliation and add a row to §9.2 — never
as a convenience read.

### 9.4 Result-model extension required by v6

> **SUPERSEDED (ownership only) — `RECONCILIATION.md` Resolution 2.** These additions are no
> longer unowned: `RESULT-MODEL.md` §10 owns `VerificationResultV6` and is the normative list,
> which is **larger** than the table below (it adds `epoch_position`, `attribution`,
> `checkpoint_binding`, `unbound_properties`, `trust_domain_id`, `trust_root`,
> `root_governance`, `key_binding`, `revocation_status`, `identity_consistency`,
> `producer_consistency`, and the `PRODUCER_POLICY_MISMATCH` and
> `KEY_BINDING_BOOTSTRAP_NOT_PERMITTED` reasons). The table below is retained because each row
> names *which v6 section forces the addition* — implement from `RESULT-MODEL.md` §10 and use
> this as the rationale index. DIVERGENCES D-5 is discharged.

`RESULT-MODEL.md` is frozen for v1–v5. v6 needs these additions:

| Addition | Detail |
|---|---|
| `EnvelopeVersion.V6` | New member. |
| `FailureReason.ENVELOPE_UNCANONICAL` | §5.4. |
| `FailureReason.PROJECT_BINDING_MISMATCH` | §3.2. |
| `FailureReason.TRUST_DOMAIN_MISMATCH` | §3.2. |
| `FailureReason.KEY_BINDING_UNRESOLVED` / `KEY_BINDING_NOT_BEFORE_USE` | §3.5. |
| `FailureReason.WORKFLOW_DEFINITION_MISMATCH` / `WORKFLOW_REGISTRATION_UNRESOLVED` | §3.4. |
| `FailureReason.DELEGATION_CHAIN_INVALID` | §3.3. |
| `FailureReason.EPOCH_VIOLATION` | `CUTOVER-CLASSIFICATION.md` §5. |
| `_NEVER_SIGNED` becomes version-dependent | `scheme_id` is signed in v6; `global_seq` never is (`_verification.py:217`, §3.1). |
| `VerificationPolicy` gains `pinned_project_instance_id`, `pinned_trust_domain_id` | Both `UUID \| None`; `None` means the verifier cannot check project binding and must report it, not skip it. |
| `payload_canonical_hash` semantics are version-dependent | v1–v5: `SHA256(canonical_envelope)`; v6: `SHA256(signature_input)`. The defence-in-depth check at `_verification.py:1413-1452` must apply the domain tag for v6. **This is the single easiest place to introduce a v6 verification bug.** |

P1.1 exposes the byte-level v6 contract through the strict parser and focused
`verify_v6_signature` result. Project and trust pins can be supplied there; key-binding,
workflow-registration, delegation-chain and epoch referents remain the external verification
boundary assigned to P1.2/P1.3. The legacy `VerificationResult` therefore never treats a
cryptographically valid but externally unresolved v6 event as fully authenticated.

---

## 10. Worked example (test vector)

### 10.0 OBSOLETE — do not implement against §10.2–§10.4

> **SUPERSEDED — `RECONCILIATION.md` overlay change 5 / collision 4 and collision 8.**
> The vector below is a **15-key** envelope with no `producer` block, and its fingerprint line
> uses the withdrawn domain-separated construction (§6.1). Both are wrong. Every byte below —
> canonical bytes, signature input, signature, `event_hash`, `payload_canonical_hash` — is
> therefore obsolete. **Do not copy any value out of §10.2–§10.4 into code or into a test.**
> It is retained only so that the regeneration is a diff rather than a fresh authorship.
>
> **P0.3 replaces it.** The generator and the resulting vectors belong in the regista
> repository, not in a scratch directory and not inline in this document (collision 23):
>
> | Artifact | Repository location |
> |---|---|
> | Generator | `tools/make_v6_vectors.py` |
> | Vectors | `tests/vectors/v6/` (one JSON file per case, plus a manifest with each expected digest) |
> | Test | `tests/test_v6_vectors.py` — regenerates from a clean checkout and compares |
>
> P0.3's acceptance criterion: each vector is reproducible from a clean checkout by one
> documented command, and a deliberate one-byte change to each input flips its expected hash.
> The draft generator retained here as `make_vector-v6-draft.py` is **input to that work, not
> the deliverable** — it predates the producer block.

Reproducible with the vendored canonicalizer and PyNaCl; generated by
`make_vector-v6-draft.py`, which imports a byte-identical copy of
`origin/main:src/regista/_vendor/rfc8785.py` and touches no production source.

### 10.1 Test key — NOT FOR PRODUCTION

```
Ed25519 seed (hex) : 0101010101010101010101010101010101010101010101010101010101010101
public key   (hex) : 8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
fingerprint        : OBSOLETE — see the marker below
key_id             : pk_1bf310ecef19e79a
```

> **SUPERSEDED — `RECONCILIATION.md` collision 8.** The fingerprint line used the withdrawn
> `regista.key.fingerprint.v1` domain (§6.1). The correct value is
> `ed25519:sha256:<SHA256(raw_public_key)>` — including the `ed25519:` scheme prefix, which the
> old line also dropped. P0.3 regenerates it; the seed and public key above are still the test
> key.

### 10.2 The v6 object (declaration order — not the canonical order)

```json
{
  "type": "regista.event",
  "version": 6,
  "project_instance_id": "9f1c6a2e-3d5b-4c8a-9e07-1b2d3f4a5c6d",
  "trust_domain_id": "018f3a5c-7b21-4e6d-8f90-a1b2c3d4e5f6",
  "event_id": "3b9c1d7e-5f42-4a8b-9c1d-0e2f3a4b5c6d",
  "entity": { "kind": "work_item", "id": "7e4d2c1a-9b8f-4e3d-a2c1-5f6e7d8c9b0a" },
  "entity_seq": 17,
  "actor": {
    "principal_id": "agent:01J8ZC4M9QK3V7XN2R6TB5HFAD",
    "kind": "agent",
    "metadata": { "harness": "claude-code", "model_lineage": "anthropic/claude-opus-5" }
  },
  "signing": {
    "scheme_id": "ed25519",
    "key_id": "pk_1bf310ecef19e79a",
    "key_binding_event_hash": "sha256:5a2eec8b3359f2eb22e7b6ed93072475d38a2159c7e1c6221b171e427a8dc9f5"
  },
  "authorization": { "mode": "direct", "credentials": [] },
  "workflow": {
    "name": "agent-notes",
    "version": 3,
    "definition_hash": "sha256:cfa04ce00d0232015b0a64747381c30facd31d2d1e0bfbd6b7bff03ab56a12e9",
    "registration_event_hash": "sha256:1c3349a990e2d6133906fd469f78f8516c8571d6b5527dc391dfee08136bd917"
  },
  "occurred_at": "2026-08-08T12:34:56.123456Z",
  "transition": "note_added",
  "payload": { "note": "hello", "seq": 17 },
  "chain": {
    "hash_algorithm": "sha-256",
    "previous_entity_event_hash": "sha256:35f0496297f7071af2a70588bca69efb426cc1bf188c9fd1f6581a287beafd65",
    "previous_project_event_hash": "sha256:7317330027bcd0551cfc73dd971be9d8dbd11aba0fbda06b169235c2536d0f09"
  }
}
```

The three referenced hashes are placeholders standing in for a real key-binding event, workflow
registration event and predecessors; they are structurally valid `sha256:` digests, which is all
the canonicalization vector needs. A full end-to-end vector requires sibling B's key-binding
event schema.

### 10.3 Canonical bytes

**1251 bytes.** Wrapped below for presentation only — the byte string contains no newline and no
whitespace outside string literals. Concatenate the lines with nothing between them.

```
{"actor":{"kind":"agent","metadata":{"harness":"claude-code","model_lineage":
"anthropic/claude-opus-5"},"principal_id":"agent:01J8ZC4M9QK3V7XN2R6TB5HFAD"}
,"authorization":{"credentials":[],"mode":"direct"},"chain":{"hash_algorithm"
:"sha-256","previous_entity_event_hash":"sha256:35f0496297f7071af2a70588bca69
efb426cc1bf188c9fd1f6581a287beafd65","previous_project_event_hash":"sha256:73
17330027bcd0551cfc73dd971be9d8dbd11aba0fbda06b169235c2536d0f09"},"entity":{"i
d":"7e4d2c1a-9b8f-4e3d-a2c1-5f6e7d8c9b0a","kind":"work_item"},"entity_seq":17
,"event_id":"3b9c1d7e-5f42-4a8b-9c1d-0e2f3a4b5c6d","occurred_at":"2026-08-08T
12:34:56.123456Z","payload":{"note":"hello","seq":17},"project_instance_id":"
9f1c6a2e-3d5b-4c8a-9e07-1b2d3f4a5c6d","signing":{"key_binding_event_hash":"sh
a256:5a2eec8b3359f2eb22e7b6ed93072475d38a2159c7e1c6221b171e427a8dc9f5","key_i
d":"pk_1bf310ecef19e79a","scheme_id":"ed25519"},"transition":"note_added","tr
ust_domain_id":"018f3a5c-7b21-4e6d-8f90-a1b2c3d4e5f6","type":"regista.event",
"version":6,"workflow":{"definition_hash":"sha256:cfa04ce00d0232015b0a6474738
1c30facd31d2d1e0bfbd6b7bff03ab56a12e9","name":"agent-notes","registration_eve
nt_hash":"sha256:1c3349a990e2d6133906fd469f78f8516c8571d6b5527dc391dfee08136b
d917","version":3}}
```

```
SHA256(canonical_envelope) = 99defe2aaf4d53fe1908386cbf44a6fd6ec78e16c9dc292892c98ae0022f591e
```

Note the key order: `actor, authorization, chain, entity, entity_seq, event_id, occurred_at,
payload, project_instance_id, signing, transition, trust_domain_id, type, version, workflow`
(§5.2) — nested objects sorted independently, so `signing` reads
`key_binding_event_hash, key_id, scheme_id`.

### 10.4 Signature input, signature, hashes

```
signature_input        = b"regista.event.v6\x00" || canonical_envelope        (1268 bytes)
SHA256(signature_input)= 08613509c6306b8dc40b720f3128b03ba6fb9f2be5f8405aa70c9a79ea9416fb
                         ^ this is the value stored in events.payload_canonical_hash (§9.4)

signature (hex)        = 8b46e13cb0ea9074a8fbbfe5ade50130a806405805d574fef3c4bcf5535a9461
                         6378b5e69b4947f5bd2cc96a6ea2a397a8aa34c09e2f87b6a3848547d2b75a00
signature (base64)     = i0bhPLDqkHSo+7/lreUBMKgGQFgF1XT+88S89VNalGFjeLXmm0lH9b0syWpuoqOX
                         qKo0wJ4vh7ajhIVH0rdaAA==

event_hash = SHA256( b"regista.event.hash.v1\x00"
                   || uint64be(1251)                  # = 00 00 00 00 00 00 04 e3
                   || canonical_envelope
                   || signature )
           = sha256:bcacc15ba1dbec4ef59e328610774eeac49e541fc56236ea308bc25f44684dff
```

`event_hash` is the value a successor event puts in
`chain.previous_entity_event_hash` / `chain.previous_project_event_hash` (§6.2, §6.7), verbatim
and unwrapped.

### 10.5 Negative vectors an implementation must reject

| Mutation | Expected outcome |
|---|---|
| `occurred_at` → `2026-08-08T12:34:56.123456+00:00` | `UNKNOWN_SCHEMA` (lexical form, §2.3) — **before** any signature check |
| `"version": 6` → `"version": 6.0` | `UNKNOWN_SCHEMA` (integer rule, §1.1) |
| Any key added at any level | `UNKNOWN_SCHEMA` (§8.4 rule 1) |
| `workflow` → `null` while `transition` stays `"note_added"` | `UNKNOWN_SCHEMA` (§8.3 S9) |
| `mode` → `"delegated"` with `credentials: []` | `UNKNOWN_SCHEMA` (§8.3 S9) |
| Re-serialize with a space after `:` | `UNCANONICAL` (§5.4) — signature would also fail, but the parse must reject first |
| Signature recomputed over `canonical_envelope` without the `regista.event.v6\x00` tag | `SIGNATURE_INVALID` |
| `event_hash` recomputed without the `uint64be` length | mismatch against successor's `previous_*_event_hash` |
| `project_instance_id` replaced with another project's | `SIGNATURE_INVALID`; if the attacker re-signs with a key of their own, `PROJECT_BINDING_MISMATCH` against the pinned policy value |
| Row `scheme_id` set to `hmac-sha256`, envelope untouched | `SCHEME_MISMATCH` → `INVALID` (§3.1) — the shipped v4/v5 behaviour (`_verification.py:1356-1375`) extended by the signed value |

---

## 11. Design decisions this document had to make

The architecture did not settle these. Each is recorded with its alternative so it can be
reversed with a known diff.

**DD-1 — chain links carry a bare `event_hash`, not a domain-wrapped one.** §6.7. Alternative:
two wrapper domains plus a checkpoint exemption. Chosen because role binding is already given by
the signed field name, and wrapping degrades the legacy seam.

**DD-2 — the v6 domain tag is applied above the `SigningScheme` layer; `scheme_id` stays
`"ed25519"`.** §5.3. Alternative: a `"ed25519-v6"` scheme id. Rejected because the scheme id
must agree with the trusted key registry (§3.1), and versioning it would put envelope-version
information into key metadata.

**DD-3 — `payload_canonical_hash` stores `SHA256(signature_input)` for v6.** §9.2, §9.4. This
falls out of DD-2: the scheme returns `hash_fn(bytes_it_was_given)`
(`_signing_scheme.py:145-147`). Alternative: keep hashing the untagged envelope, which would
require a scheme change. Flagged as the easiest place to introduce a v6 verification bug.

**DD-4 — `occurred_at` has exactly one lexical form, with six fractional digits, always `Z`.**
§2.3. Alternative: keep `datetime.isoformat()` and compare instants only. Rejected because a
canonical artifact should have one spelling; the instant-comparison rule stays as a second
check, not the only one.

**DD-5 — v6 adds a JCS fixed-point requirement that legacy versions do not have.** §5.4, with
the measurement that would let it be extended to legacy assigned to sibling D's preflight.

**DD-6 — concrete numeric bounds: 1 MiB canonical size, depth 32, 8 credentials.** §2.6. The
size bound matches `_contract.py:14`; the other two are new. Without them two implementations
will disagree about validity.

**DD-7 — `entity.kind` is a closed set and the checkpoint lives on a `project` entity.** §1.2.
The architecture says "a project-system entity" without naming the kind. **Overlay: the closed
set is six values** (`work_item`, `project`, `principal`, `trust_domain`, `project_instance`,
`workflow`), not two — `RECONCILIATION.md` collision 5. The decision to close the set at all
stands; its membership was wrong.

**DD-8 — `authorization.credentials` elements are `{credential_id, credential_hash}` objects,
not bare hash strings.** §1.5.1. The id makes a credential locatable in a bundle section without
a full scan; the hash is what binds.

**DD-9 — no row column for the new signed fields (rule N1).** §9.3. Alternative: project them
all for queryability. Rejected because every duplicated column is a place a consumer reads the
unsigned copy — the entire S1 defect class.

**DD-10 — `work_item_id` survives 0.6.0 as a `NOT NULL` constrained projection; the trigger is
dropped.** §7.3.

---

## 12. DIVERGENCES from `ARCHITECTURE-0.6.0.md`

The most valuable section if it has entries. It has nine.

**D-1 — the architecture's `file:line` citations are pre-S1; five are now wrong, and one
describes code that no longer needs fixing.** Concordance:

| `ARCHITECTURE-0.6.0.md` says | Post-S1 (`334b995`) location | Status |
|---|---|---|
| §1: `_signing.py:276-319`, permissive field-set classification | `_signing.py:277-289`, delegating to `_verification.py:277-296` | **Already strict.** Do not "fix" it |
| §1: `_signing.py:194-220`, signing defaults to HMAC | `_signing.py:221-222` | still true |
| §1: `_replay.py:1165-1183`, replay reads `workflow_registry.definition` | `_replay.py:1331-1344` | still true |
| §3: `_principal_keys.py:102-153`, direct key mutation | `_principal_keys.py:124-154` (UPDATE `:132-136`, INSERT `:138-146`) | still true |
| §4: `_replay.py:1004-1038`, unverified events applied to replay state | `_replay.py:1150-1160`, gated by `if key_entry is not None:` at `:1161` | still true |

**The architecture's description of what still needs fixing is correct; its line numbers are
stale, and one item is already done.** An implementer who takes the first row at face value will
go looking for a permissive classifier that no longer exists.

**D-2 — the checkpoint payload needs a `head_hash_construction` field the architecture omits.**
§6.6. The checkpoint's `previous_project_event_hash` is a legacy-domain hash while every other
v6 link is a v6-domain hash, and nothing in the architecture's payload sketch says so. Without
an explicit statement a verifier must infer the construction, which is domain confusion by
another name. Added as `previous_epoch.head_hash_construction`, sole permitted 0.6.0 value
`"sha256(canonical_envelope||signature)"`.

**D-3 — `workflow: null` is unimplementable without a schema change the architecture does not
mention.** §1.6, §9.3 M1. `events.workflow_name` and `events.workflow_version` are `NOT NULL`
(`001_initial.sql:9-10`), so the cutover checkpoint — the first v6 event in every project —
cannot be inserted until they are made nullable. This is on the critical path of the production
ceremony (`ARCHITECTURE-0.6.0.md` § SEQUENCING Stage 7, step 6 "apply schema migrations", step 7
"cut over each project") and, if missed, fails *during* the ceremony rather than in rehearsal
only if rehearsal skips the migration ordering.

There is direct precedent showing what happens without the migration: the segment seal is the
existing non-workflow event, and it writes the sentinels `workflow_name = ""` and
`workflow_version = 0` (`_archive_segments.py:527-528`) purely because the columns are
`NOT NULL`. In v4/v5 those sentinels are *signed* — the seal's envelope really does commit to
`workflow_name: ""`. Carrying that pattern into v6 would mean the envelope signs a workflow that
does not exist, which is a signed falsehood rather than a harmless placeholder. Making the
columns nullable is therefore correctness, not tidiness.

**D-4 — the architecture's `scheme_counts` in the checkpoint payload implies a per-project
count, but the estate's numbers are quoted globally.** `ARCHITECTURE-0.6.0.md` §4 shows
`scheme_counts` inside `previous_epoch`, which is per project; §3 and Stage 6 quote 48,688 and
48,689 Ed25519 signatures in two places for what appears to be the same population. One of the
two is off by one — plausibly the cutover boundary event, plausibly a measurement drift. This
must be resolved by sibling D's preflight *inside the cutover transaction*, not by choosing a
number now.

**D-5 — RESOLVED by `RECONCILIATION.md` Resolution 2.** `RESULT-MODEL.md` §10 owns
`VerificationResultV6`, including the class invariants and the policy inputs. §9.4 remains the
index of *which v6 section forces each addition*; the normative list is §10 there, and it is
larger than §9.4's. Original finding, retained for the record: Stage 0 item 3 is
"`VerificationResult` states and policy evaluation"; `RESULT-MODEL.md` covered v1–v5 only and
the three named siblings did not own the extension.

**D-6 — RESOLVED by `RECONCILIATION.md` Resolution 2: this document owns it.** The schema is
§1.9 (`regista.workflow-registration/v1`, `regista.workflow-retirement/v1`, the entity-id
derivation, the length-framed definition digest, and the one-registration-per-`(name, version)`
rule). Original finding, retained: the payload was neither identity/key lifecycle (sibling B)
nor bundle/verdict (sibling C) nor envelope (me), and
`workflow.registration_event_hash` cannot be validated without it.

**D-7 — RESOLVED by `RECONCILIATION.md` Resolution 2: `TRUST-DOMAIN.md` owns it.** The
document is `regista.action-delegation/v1`, frozen at `TRUST-DOMAIN.md` §5.12, and it is
distinct from `registrar_delegated` (which authorises lifecycle administration only). This
document keeps the **reference** (§1.5.1) and the chain conditions. Original finding, retained:
the credential is an identity artifact with its own signature and key-binding proof, so placing
it in the envelope section was a misassignment; unowned, WI-008 had no implementable contract.

**D-8 — the architecture's "`principal_keys` can remain as a cache" and this document's rule N1
are the same rule, applied inconsistently in the architecture.** §3 demotes `principal_keys` and
`workflow_registry` to projections, but §1's v6 shape and §2's bundle index leave open how much
gets duplicated into columns. Rule N1 (§9.3) states the general form: duplicate nothing unless
an index demands it, and reconcile anything duplicated. I believe this is what the architecture
intends; it does not say so.

**D-9 — "Optional semantic values use JSON `null`; absent and null must not collapse" is
stronger than it needs to be, and I have made it stronger still.** The architecture's rule
implies presence-significance still exists somewhere. In v6 as specified here, **every key is
always present**, so absent-vs-null cannot arise at all: the acceptance predicate is exact
key-set equality (§8.3 S6/S7). This is a deliberate strengthening — it removes the entire
presence-reconciliation class that FIELD-MATRIX §5 had to specify for v3–v5. Flagged because an
implementer reading only the architecture might build presence-tolerant parsing.

---

## 13. What I am least confident about

**LC-1 — the `payload_canonical_hash` semantics change (DD-3).** Making that column mean
"hash of the tagged bytes" for v6 and "hash of the untagged bytes" for v1–v5 is correct and
falls out of the scheme protocol, but it is a version-conditional rule in the defence-in-depth
check at `_verification.py:1413-1452`, and that check is exactly the sort of code that gets
written once and not revisited. If an implementer applies the legacy formula to a v6 event, the
event fails `CANONICAL_HASH_MISMATCH` and looks like tamper. A conformance test with the §10
vector is mandatory, not optional.

**LC-2 — whether `entity.kind` should be a closed set at all (DD-7).** Migration 031's stated
intent was to generalize entities, and 0.6.0 closes the set to two members. If a real third
kind appears mid-release, it is a schema change and therefore an envelope-version conversation.
I think closed is right for a cutover release; I am not certain it will survive contact with
the first new entity kind.

**LC-3 — whether legacy envelopes are JCS fixed points (DD-5).** I specified the check for v6
only, precisely because I have not measured it for the 351,371 legacy events. If they all are,
the check should be extended and the legacy corpus gets stronger. If some are not, that is
itself a finding — a stored envelope that is not what the canonicalizer would emit is either a
bug in a historical release or evidence of a rewrite. Sibling D's preflight should measure it;
I could not, read-only, without connecting to the estate store.

**LC-4 — the chain-link domain decision (DD-1).** I am confident the security argument is
right — role binding by signed field name is genuine cryptographic binding. I am less confident
it is the right *engineering* call, because a future artifact that carries a bare link value
outside the envelope (a diff format, a repair tool, a partial-chain proof) would then need to
add wrapping retroactively, and retrofitted domain separation is historically where these
mistakes live.

**LC-5 — `authorization.credentials` max length 8, depth 32, and 1 MiB (DD-6).** These are
defensible but arbitrary. They must be *some* fixed numbers or implementations diverge; whether
these are the right numbers is a judgement I made without operational evidence, because there
are zero delegation credentials in existence today.

**LC-6 — whether `envelope_version` (M2) should exist at all.** It is genuinely useful for the
checkpoint payload's counts and for epoch queries, and it is genuinely one more unsigned column
that a careless consumer can read instead of classifying. I specified it as reconciled-advisory,
which is the same compromise `scheme_id` had — and `scheme_id` became S2. The safer choice is
to omit it and pay the classification cost on every scan; I did not choose that because the
cutover ceremony needs per-version counts under a lock, at a point where a full re-classification
scan of 350k events is a real duration.
