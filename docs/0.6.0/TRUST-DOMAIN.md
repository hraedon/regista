# TRUST-DOMAIN.md — trust-domain genesis and key/identity lifecycle

**Status:** FROZEN CONTRACT, Stage 0 of the 0.6.0 cutover. Normative.
**Owns:** trust-domain genesis, publication and pinning, principal identity, key
enrolment/rotation/revocation/witness enrolment as signed events, and how a verifier obtains
trust material.
**Does not own:** the v6 envelope field list (sibling A — this document defines the *meaning* of
`trust_domain_id` and `signing.key_binding_event_hash`, not their encoding), the bundle v3
membership statement and review-verdict schemas (sibling C), the preflight tool (sibling D).
Where this document names a field that lives in another sibling's artifact, it states the
semantic obligation and marks it `[→ sibling X]`.

**Code baseline.** Every `file:line` citation is against `origin/main` at
`334b995` (`fix(signing): authenticate the row, not just the envelope (WI-267)`), i.e. the
post-S1 tree. Note that the local `main` branch in the working clone is **stale** and does not
contain `334b995`; only `origin/main` does. Statements about `_verification.py` describe the
S1 keystone code, not the audit's description of the pre-S1 code.

**Authority.** Owner decisions (WI-272) are binding and are reproduced inline where they
constrain a design choice. `ARCHITECTURE-0.6.0.md` §3 and §5 are the adopted architecture;
where this document departs from it, the departure is in §10 DIVERGENCES and nowhere else.

---

## OVERLAY APPLIED — 2026-08-09 (P0.1)

`RECONCILIATION.md` governs this document. The overlay has been applied in place: each
superseded clause carries a **SUPERSEDED** marker stating the replacement rule where the clause
sits. Where a marker and the surrounding prose disagree, the marker wins; where a marker and
`RECONCILIATION.md` disagree, the overlay wins and the marker is a defect to report, not a
choice to make.

| Clause | Superseded by | Replacement |
|---|---|---|
| §3.3 consequence 1 — governance derived into `trust_domain_id` | WI-280 (`ARCHITECTURE-FINAL.md` §3 decision 1) | §3.3 — governance is a **monotone signed log inside** the domain; threshold may never decrease, signers are replaceable at the current threshold |
| §3.4/§3.6/§4.3/§4.6 — `co_signed` / `solo_effective` wire spellings | Resolution 4 | `co_signed`, `solo`, `solo_effective` everywhere; `single_signer_lab` retired |
| §4.3 — published document set | collisions 19, 20, 21, 22 | §4.3 — adds `producer-policy.json`, `attestations/`, `catalog_kind: project_heads`; `index.json` never lists its own digest; one signer block shape |
| §4.4 — `publish` has no signed-document input | collision 17 | §4.4 — `regista trust publish --kind <kind> --input <signed.json> --repo <clone> [--push]` |
| §4.1/§4.5 — "a rewrite is detectable" | collision 18 | §4.1 — a coherent rewrite is **not** detectable from a fresh clone; detection needs a prior clone, commit or digest |
| §4.6 — `accept_hmac_prefix` | Resolution 4 | §4.6 — `accept_legacy_shared_secret_events`; the legacy region is mixed, not a prefix |
| §5.2/§5.3 — entity kinds, trust-log genesis | Resolution 1, collisions 3, 5 | §5.2 — six-value shared registry; genesis-only root-threshold rule |
| §5.5 — enrolment payload | WI-273 | §5.5 — enrolment **must carry public key bytes**; a fingerprint alone makes the projection unrebuildable |
| §5.8 — the first acceptance signs itself | Resolution 1 (Bootstrap B), collision 2 | §5.8 — withdrawn; the checkpoint/initialisation event is the first anchor |
| §5.9 — `principal_keys` rebuilt from signed lifecycle events | overlay change 3 | §5.9 — rebuild is valid **only for the v6 epoch**; legacy resolution is a labelled compatibility input, never lifecycle evidence |
| §5.6/§5.7/§10 — recovery at registrar authority | Resolution 5, overlay change 9 | §5.6 — recovery requires the **current root threshold** |
| §7 — witness enrolment | `RECONCILIATION.md` FINAL SCOPE | §7 — **cut from 0.6.0**; zero registrations and zero receipts exist |
| §8.3 — `VerificationResult` additions | Resolution 2 | `RESULT-MODEL.md` §10 owns `VerificationResultV6` |
| (absent) — action-delegation credential | Resolution 2, collision 16 | **§5.12 — new; this document owns `regista.action-delegation/v1`** |

---

## 1. The shape of the trust chain

Nine links, each one a signed artifact or an externally held pin. A verifier that cannot
traverse a link reports the gap; it never bridges it with a database row.

```
  operator ──(direct exchange)──▶  auditor holds: trust_domain_core_digest + root fingerprints
                                             │
  public git repo (custodian account) ───────┤ re-check: substitution detectable
                                             ▼
  [1] genesis document        regista.trust-genesis/v1, k-of-n root signatures
        │  determines trust_domain_id (§3.3) — governance is IN the identifier
        ▼
  [2] trust-root rotation     signed trust-log events, threshold preserved
        ▼
  [3] registrar delegation    scoped, expiring, signed by root at threshold
        ▼
  [4] principal registration  principal_registered      (trust-log project)
        ▼
  [5] key enrolment + PoP     principal_key_enrolled    (trust-log project)
        ▼
  [6] trust-log checkpoint    regista.trust-checkpoint/v1, published
        ▼
  [7] project acceptance      principal_key_accepted    (the *using* project's chain)
        ▼
  [8] the event               v6 envelope: trust_domain_id + signing.key_binding_event_hash
        ▼
  [9] bundle v3 statement     [→ sibling C] carries trust_domain_id + root_governance
```

Two chains are involved and they cannot be totally ordered with respect to each other.
Link [6] is the *only* cross-chain ordering primitive. §6.6 states exactly how much ordering it
buys and names the window it does not cover.

---

## 2. Identity model (WI-055)

WI-055 (agent-suite) was ratified 2026-08-01 with a follow-up historical-authority ratification
the same day. This section restates the ratified grammar as a regista-side contract, resolves
the two items the ratification left to the implementer, and fixes a fourth convention the
ratification did not know about.

### 2.1 Canonical form

```abnf
principal-id = kind ":" subject
kind         = "human" / "agent" / "service"
subject      = 1*247 subject-char
subject-char = ALPHA / DIGIT / "." / "_" / "-" / "~" / ":" / "/"
```

Additional rules, all enforced:

- Total length ≤ 256 bytes UTF-8. ASCII only; NFC is therefore a no-op but is still asserted so
  a future relaxation cannot silently change bytes that were already signed.
- `kind` is matched against the closed set above, case-sensitively and lowercase. There is no
  `unknown` kind and no extension mechanism in 0.6.0.
- `subject` must not begin or end with `:`, `.`, `-`, `_` or `/`.
- `subject` is parsed as *everything after the first colon*, so an IdP subject containing colons
  (`service:idp:tenant-a/svc-7`) is legal and unambiguous.
- `key:*` is never a principal. This is ratified WI-055 wording; regista enforces it by
  rejecting `key` as a kind at every creation path, and by never minting a principal id from a
  key id.
- `subject` should be a stable opaque identifier (IdP object id, UUID), never a mutable login or
  display name. This is a **documented obligation on the caller**, not a check regista can
  perform, and is stated as such in §11.

> **CONFIRMED AND EXTENDED — `RECONCILIATION.md` overlay change 13 and
> `ARCHITECTURE-FINAL.md` §3 decision 5.** The three-kind closed set above is correct and
> binding. Three consequences that this document must state, because the estate does not
> currently satisfy them:
>
> 1. **Principals are hosts and services, never models.** Host principals are `agent:mvmcc03`,
>    `agent:mvmcc02`, `agent:mvmhermes01`; service principals are the tooling identities; the
>    human is `human:itadmin`, with `plm` a bound alias for the same person via
>    `principal_alias_bound` and `binding_effect: reporting_join_only` — which joins records for
>    reporting and **never** satisfies signature binding. Identities that are really models,
>    harnesses or roles (`claude-fable-5`, `kimi-reviewer`, `adversarial-reviewer-*`,
>    `opencode-session`, …) **cease to be principals** and become `producer.*` fields on an event
>    signed by the host principal (`V6-ENVELOPE.md` §1.8). A model holds no private key; treating
>    one as a principal is why the review gate has been comparing self-asserted strings.
> 2. **The `actor_id → principal_id` mapping does not exist in the store and must be assigned
>    deliberately.** The preflight found no such mapping anywhere. It is **never** inferred from
>    string similarity, and the result is recorded as signed scoped mappings (Gate 1). An
>    unmapped writer is `identity_consistency: mapping_absent`, not a guess.
> 3. **Host custody is not project authority.** The WI-223/WI-278-era incident had an Ed25519
>    key registered in one project signing another while four surfaces stayed green. The selected
>    key, the canonical principal, the host and the allowed producer harness must **all**
>    reconcile — see `V6-ENVELOPE.md` §1.8 and the producer policy at §4.3.

### 2.2 Backend-safe naming

Secret backends (Azure Key Vault, Windows credential store) forbid `:`. The ratified decision is
a collision-resistant derived name, **not** `:`→`-` substitution.

```
backend_name = "rp-" || lowercase_hex( SHA256( "regista.principal-name.v1\x00" || utf8(principal_id) )[0:16] )
```

The canonical principal id is stored *inside* the secret as a field
(`{"principal_id": "...", "scheme": "...", ...}`), and a lookup verb
(`regista principal resolve-backend-name <backend_name>`) must exist, or the KV tree becomes
unauditable by hand — which the migration posture depends on.

### 2.3 The fourth convention: `witness:` — resolved

WI-055 enumerated three conventions. There is a fourth in regista itself:
`_witness.py:17` defines `_WITNESS_PRINCIPAL_PREFIX = "witness:"` and `_witness.py:20-21`
mints `witness:<uuid>` principal ids, which `_witness.py:157-163` then registers in
`principal_keys`. `witness` is not one of the three canonical kinds, so **every witness principal
in the estate is non-canonical**, and `spec.md:698` documents this non-canonical id as a trust
root.

**Decision.** Witnesses are services. The canonical form is:

```
service:witness.<witness_id>          # witness_id is the existing lowercase UUID
```

Existing `witness:<uuid>` principals are legacy, get a `principal_alias_bound` event (§2.5), and
their historical events keep binding to the exact old id. `witness_principal_id()` returns the
canonical form after cutover; a compatibility reader accepts both when *reading* history and
neither when *writing*.

`spec.md:698`'s phrase "the anchored `principal_keys` registry" is false today and must be
corrected in the same change (see WI-264, §7).

### 2.4 The two rejected conventions

| # | Convention | Where | Live examples | Disposition |
|---|---|---|---|---|
| 1 | Kind-prefixed `kind:name` | cairn `_config.py:211-228`, agent-wake, 230,976 `human:itadmin` events in `agent_provenance` | `human:itadmin`, `agent:mvmcc03-claude` | **Becomes canonical.** |
| 2 | Bare enrolled name `[A-Za-z0-9._-]{1,256}` | `_provision.py:234-247` (regista's *only* validator), mirrored in dossier `keys.py:19-32` and agent-suite `identity.py:566-578` | `human-1`, `suite-service`, `mvmcc03-agent` | Rejected at creation after cutover; aliased. |
| 3 | Bare host-scoped `PRINCIPAL_ID` | `suite.env:38`, `settings.json` | `mvmcc03-agent` | Grammatically (2). Config collapse is agent-suite's job (WI-055 ratified `AGENT_SUITE_ACTOR_ID` / `AGENT_SUITE_ON_BEHALF_OF`); regista's job is only to refuse the bare form. |

The mechanical crux WI-055 identified holds in the post-S1 tree: `_provision.py:234-247` rejects
the colon, so the canonical grammar cannot currently be enrolled, while `append` takes `actor_id`
unvalidated. 0.6.0 **inverts** this: `_validate_principal_id` is replaced by the §2.1 grammar,
and append validates it too (post-cutover, per project).

### 2.5 Migration: an alias map, not a data migration

Both, and they are different things:

- **No historical row, envelope, signature or hash is ever rewritten.** Not for identity, not for
  anything. This is `CUTOVER-POLICY` doctrine and is restated here because identity is the most
  tempting place to break it.
- An alias map **is** required, and it is a set of signed trust-log events, designed for N hops
  (today's locally-minted subject will itself need remapping when an IdP lands —
  agent-provenance WI-015).

```json
{
  "type": "regista.principal-alias",
  "version": 1,
  "alias_id": "uuid",
  "trust_domain_id": "uuid",
  "from_principal_id": "human:itadmin",
  "to_principal_id": "agent:0f6c...",
  "relation": "same_subject | legacy_conflated_execution | renamed",
  "scope": {
    "kind": "unscoped | project | event-set",
    "project_instance_id": "uuid | null",
    "event_hash_set_root": "sha256:... | null",
    "event_count": 230976,
    "first_event_hash": "sha256:... | null",
    "last_event_hash": "sha256:... | null"
  },
  "asserted_by": { "principal_id": "human:...", "method": "operator-inspection", "evidence": "..." },
  "asserted_at": "2026-08-08T00:00:00.000000Z",
  "binding_effect": "reporting_join_only"
}
```

Rules:

- `binding_effect` is the literal `"reporting_join_only"` and there is no other permitted value
  in v1. **An alias never satisfies signature binding.** The two live binding checks —
  `_bundle.py:705-716` (`_verify_event_signatures`: "key.principal_id must equal event.actor_id")
  and `verify_principal_binding` (`_principal_keys.py:373-384`, a literal `principal_id !=
  actor_id` raise) — continue to compare *exact* strings; the alias is invisible to both. This is
  ratified WI-055 wording and is enforced structurally by the fact that no verifier code path may
  load aliases before the binding check.

  *Implementation note:* `FailureReason.PRINCIPAL_ACTOR_MISMATCH` exists in the common verifier
  (`_verification.py:127`) but is not raised there — the comparison still lives in `_bundle.py`
  and `_principal_keys.py`. Consolidating it into `verify_event_strict` is part of the "one
  primitive, all consumers" discipline (`AUDIT-REPORT.md:262-266`) and should land before the
  alias contract, or a future consumer will add a third comparison that *does* consult aliases.
- The ~231k `human:itadmin` / `actor_kind=agent` corpus is bound with
  `relation="legacy_conflated_execution"` and `scope.kind="event-set"`. WI-055 explicitly forbids
  a *global* alias from `human:itadmin` to a new agent id, because that id also names genuine
  human activity elsewhere; the mandatory `scope` object is how that prohibition is enforced
  rather than merely stated. **This replaces the separately-proposed `identity_cutover_attested`
  record** — one event kind with a mandatory scope is strictly better than two kinds that differ
  only in whether scope is optional (see §10 D-4).

### 2.6 `principal_kind_conflict` must be computed, not merely defined

Ratified refinement (1) of WI-055: the conflict state must be *surfaced*. Concretely, for every
event the verifier emits:

- `actor_id_kind` — the prefix, or `null` for a bare legacy id;
- `actor_kind` — the row/envelope field;
- `identity_consistency` — `consistent | principal_kind_conflict | actor_id_ungrammatical`;
- and for pre-v5 envelopes, `actor_kind_authenticated: false`.

Ratified refinement (2) is a hard rule: **pre-v5 `actor_kind` is unsigned**, so on those events
the field made authoritative for execution classification is only as trustworthy as the store.
It is a reporting label there, never security-relevant evidence. `_verification.py`'s
`unsigned_fields` (`_verification.py:405`) is the existing mechanism; `actor_kind` must appear in
it for every envelope version below v5, and any consumer that reads `actor_kind` for a security
decision must assert `"actor_kind" in result.authenticated_fields`.

Verified consequence worth preserving in the doc, because it is the first question a reader asks:
`_assurance.py:267-270` (and `:374-375`) computes `human_accepted = (accepter_kind == "human")`
from `actor_kind`, so the ~231k conflicted events never counted as human judgment. No retroactive
correction is required. (WI-055's ratification cites `_assurance.py:87` from the pre-S1 tree; the
line moved, the behaviour did not.)

### 2.7 Enforcement boundaries

| Path | Enforce canonical grammar? |
|---|---|
| `principal_registered`, `principal_key_enrolled` (trust log) | **Yes**, always |
| `principal_key_accepted` (project) | **Yes**, always |
| Delegation credential issue/subject [→ sibling A, WI-008] | **Yes**, always |
| `append_event` actor_id | **Yes**, per project, from its cutover event onward |
| Witness registration | **Yes**, always (§2.3) |
| Verification, replay, bundle import, historical key lookup | **Never** |

Legacy principals stay eligible for rotation and revocation after enrolment goes strict — a
legacy principal that can no longer be revoked is a worse outcome than a legacy principal that
exists.

**Strictness test hook (owner's standing preference).** A conformance test enumerates every
distinct `actor_id` and `principal_id` in the preflight output [→ sibling D] and asserts each is
either canonical or covered by a `principal_alias_bound` event. It is a failing test, not a
warning, and a genuine exception surfaces there rather than being pre-authorised by a
permissive rule.

---

## 3. Trust-domain genesis

### 3.1 Owner constraint, restated because it drives the whole design

> Single-signer mode must be **visible in the artifact, not merely in configuration**. The
> genesis document carries its own signer set and threshold; verification reports which it
> actually saw; and an estate rooted by a solo signer says so in every bundle it produces. If
> lab mode is invisible, anyone can claim co-signed governance and no verifier can check — the
> default becomes theater. Do not implement the opt-in as a config flag that leaves the artifact
> identical. — WI-272

The design satisfies this by making governance a **determinant of `trust_domain_id` itself**
(§3.3). Not an adjacent field that a verifier might forget to read, and not a flag: the
identifier that every single v6 event carries is a function of the signer set and threshold. An
estate cannot restate its governance without becoming a different trust domain.

### 3.2 The genesis document

```json
{
  "type": "regista.trust-genesis",
  "version": 1,

  "binding_core": {
    "type": "regista.trust-genesis.core",
    "version": 1,
    "governance": {
      "mode": "co_signed",
      "threshold": 2,
      "signer_count": 2
    },
    "signers": [
      {
        "signer_id": "root-a",
        "scheme_id": "ed25519",
        "public_key": "base64-raw-32",
        "fingerprint": "ed25519:sha256:3f9a...",
        "custody": {
          "declared_mode": "offline-airgapped | offline-host | online-vault | unspecified",
          "declared_holder": "human:...",
          "attestation": null
        }
      },
      {
        "signer_id": "root-b",
        "scheme_id": "ed25519",
        "public_key": "base64-raw-32",
        "fingerprint": "ed25519:sha256:c114...",
        "custody": { "declared_mode": "offline-host", "declared_holder": "human:...", "attestation": null }
      }
    ],
    "created_at": "2026-08-20T00:00:00.000000Z",
    "nonce": "64-hex-chars"
  },

  "trust_domain_core_digest": "sha256:...",
  "trust_domain_id": "uuid",

  "trust_log": {
    "project_instance_id": "uuid",
    "project_name_hint": "regista_trust",
    "initial_head_event_hash": "sha256:... | null"
  },

  "publication": {
    "kind": "git",
    "url": "https://github.com/<custodian-account>/<repo>",
    "path": "trust-domain.json",
    "bootstrap": "direct-exchange"
  },

  "signatures": [
    { "signer_id": "root-a", "fingerprint": "ed25519:sha256:3f9a...", "scheme_id": "ed25519",
      "signed_at": "2026-08-20T00:01:00.000000Z", "signature": "base64" },
    { "signer_id": "root-b", "fingerprint": "ed25519:sha256:c114...", "scheme_id": "ed25519",
      "signed_at": "2026-08-20T00:14:00.000000Z", "signature": "base64" }
  ],

  "countersignatures": [],
  "anchors": []
}
```

**Fingerprints.** `"<scheme_id>:sha256:<lowercase-hex>"` over the *raw* public key bytes (32 for
Ed25519). This is exactly `_compute_fingerprint` (`_principal_keys.py:45-46`) and must not be
changed to SPKI/DER — consistency with 48k-odd existing fingerprints is worth more than DER
tidiness. Fingerprint equality is therefore key-material equality, which is what a pinning
auditor needs.

**`custody.attestation` is `null` in 0.6.0 and is a reserved extension point.** `declared_mode`
is an unverified operator claim and every report that displays it must label it as such
(OPERATOR-FORGERY R1). It exists in the artifact anyway, because a claim that is written down
and later contradicted is evidence, and a claim that was never written down is not.

### 3.3 `trust_domain_id` derivation — governance is in the identifier

```
core_bytes   = JCS(binding_core)
core_digest  = SHA256( b"regista.trust-genesis.core.v1\x00" || uint64be(len(core_bytes)) || core_bytes )
trust_domain_core_digest = "sha256:" || lowercase_hex(core_digest)
trust_domain_id          = UUIDv5( NAMESPACE_OID, "regista.trust-domain:" || lowercase_hex(core_digest) )
```

Consequences, all intended:

1. **Governance downgrade changes the epoch.** `threshold` and `signer_count` are inside
   `binding_core`. An estate cannot move from `co_signed` to `solo` without producing a
   different `trust_domain_id`, and every v6 event carries `trust_domain_id`, so the change is
   visible in every artifact from that moment. A verifier holding a pin sees a *different domain*,
   not a reconfigured one. This is the mechanism that makes the owner's constraint structural.

> **SUPERSEDED — WI-280, recorded at `ARCHITECTURE-FINAL.md` §3 decision 1.** Consequence 1 is
> withdrawn: **`threshold` and `signer_count` are NOT in `binding_core` and NOT in the
> `trust_domain_id` derivation.** Governance is a **monotone signed log inside the trust
> domain**, with two rules a verifier enforces directly:
>
> - **The threshold may never decrease.** A verifier rejects a lowering event *no matter who
>   signed it*. Downgrade is structurally impossible, not merely expensive.
> - **Signers may be replaced at the current threshold.** A compromised co-signer key is
>   therefore removable — which a pure append-only signer set would have prevented.
>
> Why the change: deriving governance into the identifier made *upgrade* as expensive as a full
> epoch cutover **and** left downgrade equally available. Expensive in both directions is worse
> than impossible in one. Under the corrected design, upgrading `solo_effective` → `co_signed`
> is a cheap signed event with **no epoch change**, and no downgrade exists to police.
>
> **What is preserved.** Governance stays *visible in the artifact, not in configuration*: it is
> replayed from the signed log and stamped into verification output, every bundle and every
> published artifact (§3.7 is unchanged in force). The initial estate posture is
> `solo_effective`, deliberately and visibly.
>
> **Implementation consequences.** `binding_core` loses `threshold` and `signer_count`; the
> genesis signer set still anchors the epoch; `root_governance` in every artifact is the
> *replayed current* state, not a copy of a genesis field; and a verifier that cannot replay the
> governance log reports `root_governance: unknown` rather than assuming genesis values.
2. **The UUID is plumbing; the digest is the security value.** UUIDv5 truncates to 122 usable
   bits. A trust policy therefore pins `trust_domain_core_digest` (full SHA-256) and treats
   `trust_domain_id` as an index. `[→ sibling A]` the envelope carries only the UUID, which is
   correct: the UUID's job in the envelope is to prevent importing a credential from another
   estate (`ARCHITECTURE-0.6.0.md:78`), and 122 bits is ample for that. It is *not* the
   auditor's pin.
3. **Root-key rotation does not change the epoch.** The genesis *signer set* is immutable and
   anchors the epoch; the *current* signer set is derived by replaying `trust_root_rotated`
   events (§5.4) authorised at the genesis threshold. A custodian countersignature or a public
   anchor added later lives outside `binding_core` and outside the signature input (§3.5), so it
   changes nothing — satisfying the owner's "without a new epoch" constraint.

### 3.4 Governance modes and threshold semantics

`governance.mode` is a **derived, restated** value: it must equal the function of `threshold` and
`signer_count` below, and a document where it does not is invalid, not merely mislabelled.

| `signer_count` | `threshold` | Required `mode` | Meaning |
|---|---|---|---|
| n ≥ 2 | k ≥ 2, k ≤ n | `co_signed` | No single signer could produce this document alone. |
| 1 | 1 | `solo` | Lab/dev. One key rooted the estate. |
| n ≥ 2 | 1 | `solo_effective` | Multiple signers listed, but any **one** of them suffices. |

> **SUPERSEDED (spelling, normatively) — `RECONCILIATION.md` Resolution 4.** The wire values are
> `co_signed`, `solo` and `solo_effective` — underscores, everywhere, in every document and
> every artifact. The hyphenated spellings used elsewhere in this document and
> `ARCHITECTURE-0.6.0.md`'s `single_signer_lab` are **retired**. A spelling difference between
> two implementations of an enum is a verification failure that reads as a policy disagreement,
> which is the worst kind to debug.
>
> Per WI-280 (§3.3), the values below are read from the **replayed governance log**, not from a
> genesis field; the derivation rule from `threshold`/`signer_count` is unchanged.

`solo_effective` exists specifically to close the obvious theater hole: listing three signers and
setting `threshold: 1` would otherwise let an estate display three fingerprints while being
solo-rooted in fact. It is named separately, it is not `co_signed`, and a trust policy that
requires `co_signed` rejects it.

Further rules:

- `threshold ≥ 1`, `threshold ≤ signer_count`, `signer_count = len(signers)` — all three checked;
  disagreement is invalid.
- Signer `fingerprint`s must be pairwise distinct. Two entries with the same key material is
  invalid, not `co_signed`.
- `signers` is sorted by `fingerprint` ascending in `binding_core` (so the digest is independent
  of authoring order). `signatures` is *not* required to be sorted, and its order is not signed.
- `signatures` must contain **at least `threshold`** entries that verify. Extra valid signatures
  are permitted and reported. Entries that do not verify, or whose `signer_id` is not in
  `binding_core.signers`, make the document **invalid** — not "invalid signature ignored".
  Silently dropping a bad signature is how a k-of-n check becomes a 1-of-n check.
- `signed_at` values are actor claims. They are not ordered, not trusted, and not used for
  anything. They exist because an operator triaging a stale co-signature will want them.

### 3.5 Signature input

```
document_core = the genesis object MINUS { "signatures", "countersignatures", "anchors" }
sig_bytes     = JCS(document_core)
signature_input = b"regista.trust-genesis.v1\x00" || uint64be(len(sig_bytes)) || sig_bytes
```

Each root signature is over the **same** bytes, so signers can sign independently, in any order,
without seeing each other's signature. That is the point: a co-signature ceremony that requires
serialisation is a ceremony that will not happen.

`document_core` includes `trust_domain_core_digest` and `trust_domain_id`, so a signer commits to
the derivation as well as the inputs; a verifier recomputes both and rejects disagreement rather
than trusting the stated values.

`countersignatures` and `anchors` are excluded from *both* `binding_core` and `sig_bytes`, which
is what makes them addable later with no epoch change. Their own schemas:

```json
{ "custodian_id": "...", "scheme_id": "ed25519", "fingerprint": "ed25519:sha256:...",
  "over": "trust_domain_core_digest",
  "signature": "base64", "signed_at": "...", "statement": "observed at <url> on <date>" }

{ "kind": "rfc3161 | opentimestamps | git-tag | other", "over": "trust_domain_core_digest",
  "obtained_at": "...", "evidence": { } }
```

`over` is restricted to `"trust_domain_core_digest"` in v1 so a countersignature can never be
retargeted at a mutable part of the document. 0.6.0 **produces** neither; it produces the fields
and a verifier that reports them as `present_unverified`. Verifying an anchor requires the
anchoring work that `ARCHITECTURE-0.6.0.md` §7 deliberately deletes from this release, and
claiming otherwise would repeat exactly the S7 defect.

### 3.6 How a verifier distinguishes co-signed from solo-rooted

The verifier does **not** read `governance.mode` and report it. It:

1. Recomputes `core_digest` from `binding_core` and compares to `trust_domain_core_digest`.
   Mismatch → `root_governance = unknown`, document invalid.
2. Recomputes `trust_domain_id` and compares. Mismatch → invalid.
3. Recomputes the required `mode` from `threshold`/`signer_count` (§3.4 table) and compares to
   the stated `mode`. Mismatch → invalid.
4. Verifies each entry in `signatures` against the signer set. Counts the valid ones as `k_seen`.
   Any invalid or unknown-signer entry → invalid.
5. Requires `k_seen ≥ threshold`.
6. Emits:

```json
"root_governance": {
  "mode": "co_signed | solo | solo_effective | unknown",   // underscores — Resolution 4
  "threshold": 2,
  "signer_count": 2,
  "signatures_seen": 2,
  "signer_fingerprints_verified": ["ed25519:sha256:3f9a...", "ed25519:sha256:c114..."],
  "independence": "unverifiable",
  "custody_declared": ["offline-airgapped", "offline-host"],
  "custody_verified": false
}
```

`independence` is the literal `"unverifiable"` in 0.6.0 and there is no code path that sets it to
anything else. Two distinct keys are two distinct keys; nothing in the artifact shows two distinct
*people*. That is OPERATOR-FORGERY R2 and it is named in the field rather than left to the
reader.

### 3.7 Propagation: "says so in every artifact it produces"

Three carriers, all mandatory:

1. **Every v6 event** carries `trust_domain_id` `[→ sibling A]`. Because the id is derived from
   governance (§3.3), the governance mode is *implied* by every event to any verifier holding the
   genesis document. This is the structural guarantee; the next two are ergonomics.
2. **Every bundle v3 membership statement** `[→ sibling C]` carries a `trust_root` block:
   `{ trust_domain_id, trust_domain_core_digest, root_governance: {mode, threshold, signer_count},
   genesis_document_digest }`. The bundle verifier reconciles this against the genesis document it
   was given; disagreement is a verification failure, not a display difference. A bundle produced
   by a solo-rooted estate therefore says `"mode": "solo"` in a signed statement.
3. **Every project cutover checkpoint** (`project_cryptographic_epoch_started`,
   `ARCHITECTURE-0.6.0.md:444-473`) carries `new_epoch.trust_domain_id` and, added here,
   `new_epoch.trust_domain_core_digest` and `new_epoch.root_governance` — so the governance claim
   is inside the first signed event of the epoch, not only in an external file. `[→ sibling A]`

**Report obligation.** Any verification report, CLI output or bundle verdict that reaches a human
and does not display `root_governance.mode` when it is `solo` or `solo_effective` is
non-conformant. This is a test, not a style note: a report renderer test asserts the string
appears.

---

## 4. Publication and pinning

### 4.1 What the channel is for

> The channel *cannot prevent* an operator publishing a false fingerprint; nothing short of a
> real transparency log can. Its job is to make **substitution detectable**. The properties that
> matter are retention, history and third-party hosting, not authority. — WI-272

Design consequences, stated so an implementer does not accidentally build authority semantics:

- The repository is **not** a trust root. It is a *retention and history* service. A verifier
  never derives trust from "it was in the repo"; it derives trust from "the fingerprint I was
  given by direct exchange at time T is still what the repo shows at time T+1, and the history
  shows no rewrite".
- Therefore the tooling must never fetch-and-trust. `regista bundle verify` does **not** reach
  out to the publication URL. Pinning is an auditor action with an auditor-held artifact.
- Force-push detection is the mechanism. It works only for a party holding a prior clone or a
  prior commit sha. Every published document therefore records the commit sha of the *previous*
  publication (§4.3), so a single fresh clone still exhibits a chain an auditor can check for
  gaps, and a rewrite that removes an intermediate publication becomes a broken `prev_commit`
  link rather than an absence nobody notices.

> **SUPERSEDED (claim strength) — `RECONCILIATION.md` collision 18, per
> `OPERATOR-FORGERY.md` §5.** A **coherent** malicious rewrite is not detectable from a fresh
> clone. An operator who rewrites the whole history — genesis, every checkpoint, every
> `prev_commit` link, `index.json` — produces a clone that is internally consistent and passes
> every check in §4.5. `prev_commit` detects **gaps in a presented history**, not a fully
> rewritten one.
>
> Detection therefore requires a *prior* observation: a previous clone, a recorded commit sha, or
> a digest obtained by direct exchange. Every statement in this section that reads "a rewrite is
> detectable" means "detectable **to a party holding a prior observation**", and the tooling must
> print that qualification rather than let a fresh-clone auditor infer a property they do not
> have.

### 4.2 Repository layout

Under a GitHub account **distinct from the estate's operational identity**. The estate already
holds two separate accounts; the operational estate signs as one, the custodian repo lives under
the other. (The account names are deliberately not written here — the repository's committed
identifier gate forbids one of them, and the property that matters is *distinctness*, not which
pair of names it is. The operator supplies both during Gate 1.) This costs nothing and is the
whole of the "third-party hosting" property available at this budget. It is *not* independence
(OPERATOR-FORGERY R3).

```
README.md                              # bootstrap instructions, direct-exchange fingerprint block
trust-domain.json                      # THE genesis document. Written once. Never modified.
checkpoints/<trust_domain_id>/NNNNNNNN-<utc>.json     # trust-log checkpoints, zero-padded seq
catalogs/<utc>-cutover.json                            # estate cutover catalogs
index.json                             # append-only manifest of every file above, with digests
```

Invariants enforced by the publish command and re-checkable by anyone with a clone:

- `trust-domain.json` is created by exactly one commit and never appears in a later diff. A
  change to it is the substitution the channel exists to expose.
- Checkpoint filenames are zero-padded and monotone; a gap is detectable without reading content.
- `index.json` is append-only: every entry is `{path, sha256, published_at, prev_commit}` and
  entries are only ever added. The publish command refuses to rewrite an existing entry.
- One commit per publication. Deterministic commit message:
  `regista: publish <kind> <identifier> <sha256-prefix>`.

### 4.3 Published documents besides genesis

**Trust-log checkpoint** — the document that makes trust-log state externally known, and the
cross-chain ordering primitive of §6.6.

```json
{
  "type": "regista.trust-checkpoint",
  "version": 1,
  "trust_domain_id": "uuid",
  "trust_domain_core_digest": "sha256:...",
  "checkpoint_seq": 12,
  "trust_log": {
    "project_instance_id": "uuid",
    "event_count": 418,
    "genesis_event_hash": "sha256:...",
    "head_event_hash": "sha256:...",
    "max_global_seq": 418
  },
  "root_governance": { "mode": "co_signed", "threshold": 2, "signer_count": 2 },
  "active_root_fingerprints": ["ed25519:sha256:..."],
  "prev_checkpoint_digest": "sha256:... | null",
  "prev_commit": "<git sha> | null",
  "created_at": "...",
  "signer": { "scheme_id": "ed25519", "key_id": "pk_...", "principal_id": "service:...", "fingerprint": "ed25519:sha256:..." },
  "signature": "base64",
  "countersignatures": [],
  "anchors": []
}
```

Signature input: `b"regista.trust-checkpoint.v1\x00" || uint64be(len(b)) || b` where
`b = JCS(document minus {signature, countersignatures, anchors})`.

The checkpoint may be signed by the root **or** by a scoped registrar credential (§5.4). Which
one signed is reported; a policy may require the root. `max_global_seq` is informational and is
never the binding — `ARCHITECTURE-0.6.0.md:477`.

**Producer policy** — `producer-policy.json`, added by `RECONCILIATION.md` collision 20. It is
what makes a v6 event's `producer` block (`V6-ENVELOPE.md` §1.8) cross-checkable instead of a
bare assertion.

```json
{
  "type": "regista.producer-policy",
  "version": 1,
  "trust_domain_id": "uuid",
  "trust_domain_core_digest": "sha256:...",
  "entries": [
    { "host": "mvmcc03",     "principal_id": "agent:mvmcc03",
      "key_fingerprints": ["ed25519:sha256:..."],
      "allowed_harnesses": ["claude-code"] },
    { "host": "mvmcc02",     "principal_id": "agent:mvmcc02",
      "key_fingerprints": ["ed25519:sha256:..."],
      "allowed_harnesses": ["claude-code", "opencode", "codex"] },
    { "host": "mvmhermes01", "principal_id": "agent:mvmhermes01",
      "key_fingerprints": ["ed25519:sha256:..."],
      "allowed_harnesses": ["hermes"] }
  ],
  "prev_commit": "<git sha> | null",
  "created_at": "...",
  "signer": { },
  "root_signatures": [],
  "countersignatures": [],
  "anchors": []
}
```

Domain separator `b"regista.producer-policy.v1\x00"`, same framing. Root-threshold signed, or
signed under an explicitly scoped authority that the genesis grants. The mapping is
**many-to-many by design** — one signing key per *host principal*, and a host principal may
assert any of its allowed harnesses. An externally pinned contradiction between an event's
`producer` block and this policy is `INVALID` / `PRODUCER_POLICY_MISMATCH`; an unsupplied policy
is explicitly `policy_not_supplied` and never a silent skip.

**Estate cutover catalog** — one document, all 26 project checkpoints, per
`ARCHITECTURE-0.6.0.md:694`.

```json
{
  "type": "regista.estate-catalog",
  "version": 1,
  "trust_domain_id": "uuid",
  "trust_domain_core_digest": "sha256:...",
  "root_governance": { "mode": "...", "threshold": 2, "signer_count": 2 },
  "catalog_kind": "cutover",
  "projects": [
    { "project_instance_id": "uuid", "project_name_hint": "agent_notes",
      "cutover_event_hash": "sha256:...", "legacy_head_event_hash": "sha256:...",
      "legacy_event_count": 12345, "scheme_counts": { "hmac-sha256": 12000, "ed25519": 345 },
      "new_epoch_head_event_hash": "sha256:..." }
  ],
  "trust_log_checkpoint_digest": "sha256:...",
  "prev_commit": "<git sha> | null",
  "created_at": "...",
  "signer": { },
  "signature": "base64",
  "countersignatures": [],
  "anchors": []
}
```

Domain separator `b"regista.estate-catalog.v1\x00"`, same framing.

> **AMENDED — `RECONCILIATION.md` collisions 19, 21, 22.** Four rules govern every document in
> §4.3, including the two above:
>
> 1. **The signer block has one shape**, everywhere, and is never left `{}`:
>    `{principal_id, key_id, scheme_id, fingerprint, authority_kind, authority_event_hash}`.
>    A **direct root-threshold** authorisation does **not** invent a principal id for the root —
>    it uses `root_signatures: []` (an array of `{signer_id, fingerprint, signature}`) and leaves
>    `signer` absent. Reporting *which* authority signed is mandatory; a policy may require the
>    root.
> 2. **`index.json` cannot list its own digest.** It lists every immutable artifact *except
>    itself*. An index that claims to contain its own hash is either lying or stale, and building
>    a verifier around the paradox is worse than omitting the entry.
> 3. **Later countersignatures and anchors are new immutable records**, not mutations:
>    `attestations/<subject-digest>/<ordinal>.json`. Each references the original core digest.
>    They never modify genesis, never change `trust_domain_id`, and never require a new epoch.
> 4. **`catalog_kind: project_heads`** exists, using this same signed catalog envelope, for
>    publishing current project heads. It is **optional** and is *not* a release gate: only
>    genesis, producer policy, trust checkpoint and the cutover catalog are. Without a published
>    head, every report retains `tail_truncation_undetectable` — which is the honest state, and
>    the reason the option exists at all. Automatic periodic head publication is **cut from
>    0.6.0**; the format and the command support it, nothing schedules it.

### 4.4 One command

> Publication must be **one command emitting canonical JSON**. A ceremony that takes an hour will
> not happen at cutover time under pressure, and an unpublished checkpoint is worth nothing.
> — WI-272

```
regista trust publish --kind <genesis|checkpoint|catalog|producer-policy|attestation> \
                      --input <signed.json> \
                      --repo <path-to-clone> [--push] [--dry-run]
```

> **SUPERSEDED — `RECONCILIATION.md` collision 17.** The frozen form had no **input**: it named
> a document kind and a repository but never said where the signed document comes from. Since
> `publish` touches no private key (below), it cannot be the thing that produces the document —
> so it must take one. The implementable command parses, canonicalises, verifies, writes,
> indexes, commits and optionally pushes **in one invocation**, and refuses at the first step
> that fails.
>
> `--kind attestation` writes to `attestations/<subject-digest>/<ordinal>.json` (§4.3 rule 3).

Contract:

- Emits **canonical JCS bytes** to the target path, `git add`, `git commit` with the deterministic
  message, and `git push` only when `--push` is given.
- **Idempotent.** Re-running with unchanged content is a no-op that exits 0 and says so. Content
  that differs from an existing file is refused (exit non-zero) unless the path is a new
  checkpoint/catalog path.
- **Refuses** a dirty working tree under the paths it touches; refuses a detached HEAD; refuses if
  `trust-domain.json` exists and differs.
- **Self-verifies before committing:** re-reads the file it wrote, re-parses, re-verifies
  signatures, recomputes `trust_domain_core_digest`. A file that does not verify is not
  committed. (Same discipline the architecture requires of bundle export,
  `ARCHITECTURE-0.6.0.md:314`.)
- `--dry-run` prints exactly the bytes and the paths, changing nothing. This is what makes the
  command runnable during rehearsal (Stage 6) without polluting the channel.
- Target under 5 seconds and zero interactive prompts. The root **signing** step is separate and
  offline (§5.4); `publish` never touches a private key. That separation is what lets publication
  be one fast command while the root stays offline.

**Failure to publish is a ceremony failure, not a warning.** Stage 7 step 9 gates on this command
exiting 0.

### 4.5 The verifier's pinning workflow

Bootstrap (once, per auditor):

1. Obtain out of band, by direct exchange: `trust_domain_core_digest`, the root fingerprints,
   `threshold`, and the repository URL. A printed/dictated block; the fingerprints are
   `ed25519:sha256:<64 hex>` and are comparable by eye at the first and last 8 characters, which
   is what people actually do — so the tooling prints them in 8-character groups.
2. Clone the repository. Record the commit sha.
3. `regista trust pin --repo <clone> --expect-core-digest sha256:... --expect-fingerprint ... [x n] --out trust-policy.json`
   verifies the genesis document, checks the expectations, and emits a trust policy file.

Re-check (every time, cheap):

4. `git fetch && git log --oneline` — confirm the recorded commit is still an ancestor of the
   remote head. A non-ancestor is a **rewrite** and is the alarm this channel exists to raise.
5. Confirm `trust-domain.json` is unchanged since the recorded commit.
6. Confirm `index.json` grew by append only and `prev_commit` links are contiguous.

Steps 4–6 are `regista trust recheck --repo <clone> --policy trust-policy.json`, which is
read-only, network-optional, and reports `channel_status: consistent | rewritten | diverged |
not_checked`.

**What this does not do**, and must be printed by `recheck` itself: it does not prove the
fingerprint was ever honest. An operator who published a key they control at T=0 and still
controls it at T=1 passes every check here. The channel detects *substitution*, not *initial
dishonesty*. OPERATOR-FORGERY R3.

### 4.6 Trust policy file

The artifact sibling C's bundle verifier consumes (`--trust-policy`), and the concrete form of
`ARCHITECTURE-0.6.0.md:262-271`.

```json
{
  "type": "regista.trust-policy",
  "version": 1,
  "trust_domain_id": "uuid",
  "trust_domain_core_digest": "sha256:...",
  "genesis_document_digest": "sha256:...",
  "required_root_governance": ["co_signed"],
  "root_signer_fingerprints": ["ed25519:sha256:...", "ed25519:sha256:..."],
  "min_root_signatures": 2,
  "publication": {
    "kind": "git",
    "url": "https://github.com/<custodian>/<repo>",
    "observed_commit": "<sha>",
    "observed_at": "2026-08-20T12:00:00.000000Z"
  },
  "accepted_project_instance_ids": ["uuid", "..."],
  "min_trust_log_checkpoint": { "checkpoint_seq": 12, "head_event_hash": "sha256:..." },
  "known_project_checkpoints": {
    "<project_instance_id>": { "head_event_hash": "sha256:...", "event_count": 352509 }
  },
  "bundle_signing": { "permitted_principal_ids": ["service:..."], "permitted_schemes": ["ed25519"] },
  "legacy_epoch_policy": {
    "accept_legacy_partial": true,
    "accept_legacy_shared_secret_events": true,
    "require_cutover_checkpoint": true,
    "accept_retrospective_key_binding": true
  }
}
```

> **SUPERSEDED — `RECONCILIATION.md` Resolution 4.** `accept_hmac_prefix` is renamed
> **`accept_legacy_shared_secret_events`**. The old name encodes a false model of the estate: the
> legacy region is **mixed**, not an HMAC prefix — `agent_provenance` alone already carries both
> HMAC and Ed25519 on one chain. A policy field named "prefix" invites a range check where only a
> per-event check is correct.
>
> Two further corrections to this section:
>
> - `required_root_governance` values use the underscore spellings (§3.4). The default when the
>   field is absent stays `["co_signed"]` — the strict direction.
> - `known_project_checkpoints[*].event_count` belongs to a **named snapshot** measured inside
>   the cutover transaction, never a figure copied from a preflight run
>   (`RECONCILIATION.md` overlay change 12). The `352509` in the example above is illustrative
>   and is **not** a current count; see `preflight-live.json` for the measured snapshot and
>   `preflight-s1.json` for the S1-era one.
>
> **This document owns the one trust policy.** `BUNDLE-V3.md` §4.2 consumes this schema and does
> not define a competing one (collision 11). Key *material* may travel in a bundle; **trust**
> comes only from an auditor pin.

Rules: the policy is a *caller* artifact and is never read from the store, never embedded in a
bundle, and never defaulted. `required_root_governance` defaults to `["co_signed"]` when the
field is absent — the strict direction, so a lab estate must say so explicitly and a policy
written without thought rejects a solo root rather than accepting it.

---

## 5. Key lifecycle as signed events (audit S6)

### 5.1 The "started and abandoned" claim — checked, and more precise than the audit states

The audit says (`AUDIT-REPORT.md:67`) that `principal_entity_id()` exists at
`_principal_keys.py:53` and is unused by the lifecycle functions. Verified against `origin/main`,
with an important refinement:

- `principal_entity_id` (`_principal_keys.py:53-54`) is **not** globally unused. It is used by
  `_api_meta.py:408,431`, `_api_meta.py:475,479`, `_in_mem_workflow.py:497-499`, and
  `principal_lifecycle.py:49,836`.
- It **is** unused by `register_principal_key_conn` (`_principal_keys.py:77-154`),
  `rotate_principal_key_conn` (`:266-318`) and `revoke_principal_key_conn` (`:334-370`), all
  three of which are pure `INSERT`/`UPDATE` against `principal_keys` with no event emission.
- Two *different* callers each emit a signed event around those mutations:
  - `_api_meta.py:430-446` appends a `principal_enrolled` event on the principal entity —
    **after** `provision_principal` has already written the row, in a separate transaction, and
    only for the enrol path.
  - `principal_lifecycle.py:820-899` (Plan 031) does it properly: same transaction, event
    (`_store_append_event`, `:887`) plus registry commit (`_commit_key`, `:878` →
    `_principal_keys` conn functions, `:1286/1296/1305`), with transitions
    `principal_enrolled`/`principal_rotated`/`principal_revoked` (`:1271-1278`).
- **But** three unguarded paths bypass all of it: `regista principal rotate`
  (`_cli.py:1594-1597`), `regista principal revoke` (`_cli.py:1648-1650`), and every witness
  operation (`_witness.py:157-163`, `:205-210`, `:256-262`). `_ops.py:1184,1200` too.

So: the intended design is not merely started, it is **implemented once, correctly, in
`principal_lifecycle.py`, and then bypassed by the paths operators actually use.** That is a
sharper and more actionable statement than "unused". Two concrete defects follow.

**Defect A — the projection cannot be rebuilt from the events that do exist.**
`principal_lifecycle.py:838-851` builds the payload with `principal_id`, `principal_kind`,
`actor_id`, `reason`, `policy_version`, and conditionally `fingerprint`, `scheme`, `old_key_id`.
It never carries the **public key bytes**, and never the `key_id` of the new key. `_api_meta.py`'s
payload (`:432-437`) carries `key_id`/`fingerprint`/`scheme`, also no key bytes. A verifier
replaying these events therefore obtains a *fingerprint* it can check a candidate key against, but
cannot *obtain* the key. The projection is not rebuildable, which is the entire S6 remedy.

**Defect B — the events are signed with the project's key set**, which in the estate today is
HMAC. An HMAC-signed key-lifecycle log is not externally verifiable, so it cannot be the trust
root. This is why the trust-domain log must itself be a v6/Ed25519 project from its first event
(§5.2) and has no legacy epoch.

### 5.2 The trust-domain log

One estate-wide project (`ARCHITECTURE-0.6.0.md:343`), with:

- its own `project_instance_id`, named in the genesis document (`trust_log.project_instance_id`);
- **no legacy epoch.** Its genesis event is a v6 Ed25519 event. There is no HMAC prefix, no
  `project_cryptographic_epoch_started`, no cutover checkpoint. A trust log with a legacy prefix
  would root the estate in exactly the semantics the epoch exists to leave behind.
- entity `kind = "principal"`, `id = principal_entity_id(principal_id)` for all
  principal/key/witness events; `kind = "trust_domain"`, `id = trust_domain_id` for root and
  domain-level events; `kind = "project_instance"`, `id = project_instance_id` for registrations.

> **AMENDED — `RECONCILIATION.md` Resolution 1 and collision 5.** Two rules:
>
> 1. **The entity-kind registry is shared and closed at six values** — `work_item`, `project`,
>    `principal`, `trust_domain`, `project_instance`, `workflow` (`V6-ENVELOPE.md` §1.2).
>    `project_system` (used in §5.3's catalogue row for `trust_log_checkpoint_observed`) is
>    prose, **never a wire value**; that event's entity kind is `project`.
> 2. **The trust-log genesis exception.** `trust_domain_established` is the first v6 event in the
>    log and has no predecessor acceptance to point at, so it carries
>    `signing.key_binding_event_hash = null`. It is authorised **externally**: its hash equals
>    `trust_genesis.trust_log.initial_head_event_hash`, the genesis document verifies at root
>    threshold, and the signing key is a genesis root key. This is Bootstrap A; it is the *only*
>    null permitted in the trust log, and it is what resolves the "universal project acceptance
>    has no predecessor" circularity (collision 3).

**Entity id scoping note.** `principal_entity_id` is `uuid5(NAMESPACE_OID, "principal:" + id)`
(`_principal_keys.py:53-54`) and is therefore *not* trust-domain-scoped: the same principal id in
two estates yields the same entity uuid. This is deliberate and safe, because scoping comes from
`project_instance_id` + `trust_domain_id` in the envelope `[→ sibling A]`, and changing the
derivation would orphan the `principal_enrolled` events `_api_meta.py:431` has already written.
Keep the v1 derivation. Do not "fix" it.

### 5.3 Event catalogue

All are v6 Ed25519 events in the trust-domain log unless marked *(project)*.

| Transition | Entity | Purpose |
|---|---|---|
| `trust_domain_established` | trust_domain | First event; restates `binding_core` and `trust_domain_core_digest`. |
| `trust_root_rotated` | trust_domain | Replace/add/remove a root signer. Threshold and signer_count **must not change** (§5.4). |
| `registrar_delegated` | trust_domain | Scoped, expiring online credential. |
| `registrar_revoked` | trust_domain | |
| `project_instance_registered` | project_instance | Binds `project_instance_id` ↔ name hint ↔ trust domain. |
| `principal_registered` | principal | Creates the principal; declares canonical id and kind. |
| `principal_key_enrolled` | principal | The one that matters. §5.5. |
| `principal_key_rotated` | principal | New key + named superseded key. §5.6. |
| `principal_key_revoked` | principal | §5.7. |
| `principal_alias_bound` | principal | §2.5. |
| `legacy_key_binding_attested` | principal | §6. |
| `witness_registered` | principal | §7. |
| `witness_key_rotated` / `witness_paused` / `witness_resumed` / `witness_revoked` | principal | §7. |
| `bundle_signing_authority_granted` / `_revoked` | principal | Which principal may sign bundle v3 statements `[→ sibling C]`. |
| `trust_log_checkpoint_published` | trust_domain | Records the digest of a §4.3 checkpoint *inside* the log, so the log commits to its own publications. |
| `principal_key_accepted` *(project)* | principal | §5.8. The binding every v6 event points at. |
| `principal_key_acceptance_revoked` *(project)* | principal | §5.8. |
| `trust_log_checkpoint_observed` *(project)* | project | §6.6. Imports trust-log ordering into a project chain. (`project_system` is prose, never a wire value — Resolution 4.) |

### 5.4 Root and registrar

**Root signing is offline and is never a regista code path.** `regista trust sign-genesis
--core <file> --out <sig>` is an offline helper that reads a `binding_core`, prints the bytes it
will sign, and writes a detached signature. It never contacts a database and never writes to the
publication repo. This is what allows §4.4's publish command to be fast and keyless.

**`trust_root_rotated`** payload: `{ added: [signer], removed: [fingerprint], reason,
effective_from_checkpoint_seq }`. Constraints, all checked by the verifier when replaying the
trust log:

- The event must carry ≥ `threshold` detached root signatures over its own canonical bytes,
  by keys in the *current* signer set (genesis set, as evolved by prior rotations).
- ~~`threshold` and `signer_count` **must not change.**~~ **SUPERSEDED — WI-280 (§3.3).**
  Governance is a monotone signed log inside the domain, so a rotation event may change the
  signer set and may *raise* the threshold. The binding rules are: **the threshold may never
  decrease** (a verifier rejects a lowering event no matter who signed it), and **signers may be
  replaced at the current threshold**. Neither is an epoch change, and `trust_domain_id` does
  not move. Removing a compromised co-signer is therefore possible — the property the frozen
  rule accidentally forbade.
- The resulting signer set must have pairwise-distinct fingerprints and cardinality
  `signer_count`.

**`registrar_delegated`** payload: `{ registrar_principal_id, key_id, fingerprint, scheme_id,
scopes: ["principal_key_enrolled","principal_key_rotated","witness_registered", ...],
not_before, not_after, max_operations: int|null }`. Signed at root threshold. `not_after` is
mandatory and bounded (contract: ≤ 400 days). Routine lifecycle operations use the registrar; the
root is used for genesis, root rotation, registrar delegation, and nothing else.

A registrar cannot delegate. `registrar_delegated` naming a principal that is itself a registrar
is invalid — no chains, no depth question, no cycle check needed.

### 5.5 `principal_key_enrolled`

```json
{
  "type": "regista.key-enrollment",
  "version": 1,
  "trust_domain_id": "uuid",
  "principal_id": "agent:0f6c...",
  "principal_kind": "agent",
  "key_id": "pk_4f70570b481745a8",
  "scheme_id": "ed25519",
  "public_key": "base64-raw-32",
  "fingerprint": "ed25519:sha256:...",
  "not_before": "2026-08-20T00:00:00.000000Z",
  "not_after": null,
  "possession_proof": {
    "domain": "regista.principal-possession.v2",
    "challenge_id": "uuid",
    "verifier_nonce": "64-hex",
    "enrollment_request_digest": "sha256:...",
    "signature": "base64"
  },
  "authorized_by": {
    "authority": "root | registrar",
    "principal_id": "service:registrar-1",
    "key_id": "pk_...",
    "delegation_event_hash": "sha256:... | null"
  },
  "custody": { "declared_backend": "vault | azure | windows | file | operator", "declared_policy_ref": "..." },
  "supersedes_key_id": null
}
```

**`public_key` is mandatory and is the fix for Defect A (§5.1).** Base64 of the raw 32 bytes,
matching the storage form in `principal_keys.public_key` (`_principal_keys.py:181`,
`bytes(row["public_key"])`) and the 32-byte check already enforced for witnesses
(`_witness.py:126-131`). `fingerprint` must equal `_compute_fingerprint(public_key, scheme_id)`
(`_principal_keys.py:45-46`) and disagreement is invalid — the fingerprint is a convenience, the
bytes are the artifact.

**Proof of possession.** `principal_lifecycle.py` already implements a possession challenge
(`POSSESSION_DOMAIN = "regista.principal-possession.v1"`, `:63`; `PossessionChallenge`, `:290-317`;
JCS-canonicalised, `:303`). v2 keeps the object shape and adds `trust_domain_id` and
`enrollment_request_digest`, and changes the framing to the byte-prefix form used everywhere else
in v6:

```
p = JCS(challenge_object_including_domain_field)
possession_input = b"regista.principal-possession.v2\x00" || uint64be(len(p)) || p
```

The signature is by the **enrolling principal's new private key** and is verified with the
`public_key` in this same payload — i.e. it proves the enroller holds the private half of the key
being enrolled. It does not prove anything about who the enroller *is*; that comes from
`authorized_by`. Both are required; neither substitutes for the other.

The existing challenge store is process-local (`docs/principal-lifecycle-threat-model.md`,
"Trust boundaries") and Plan 031's own threat model names durable one-use challenge storage as
required before any commit path may rely on it. Migration 044 (`044_lifecycle_durable_challenges.sql`)
exists; enrolment through this contract **requires** the durable store, and the in-process store
is refused with `DURABLE_OPERATION_REQUIRED` (`principal_lifecycle.py:1264-1269`).

### 5.6 `principal_key_rotated`

Payload is `principal_key_enrolled` plus `supersedes_key_id` (non-null) and:

```json
"dual_authorization": {
  "old_key_signature": "base64 | null",
  "mode": "dual | recovery",
  "recovery_reason": "key-lost | key-compromised | custody-migration | null"
}
```

- `mode: "dual"` requires a signature by the **superseded** key over the same canonical rotation
  bytes, in addition to the registrar authorisation. This proves the rotation was requested by the
  holder of the outgoing key, not merely by the registrar.
- `mode: "recovery"` omits it and is **visibly classified as recovery** — the verifier reports
  `key_binding: recovery_rotated` and it propagates into `VerificationResult` (§8.3) and into
  bundle verdicts `[→ sibling C]`. Recovery is legitimate and must not be hidden;
  `ARCHITECTURE-0.6.0.md:363`.

> **SUPERSEDED (authority) — `RECONCILIATION.md` Resolution 5, overlay change 9.** Recovery
> rotation requires signatures from the **current root threshold**. The registrar may *prepare
> and submit* the request; it cannot authorise it.
>
> | Operation | Authority required |
> |---|---|
> | Normal rotation (`mode: dual`) | Outgoing-key signature **plus** registrar |
> | Recovery rotation (`mode: recovery`) | **Current root threshold** |
> | Root-key recovery | Current root threshold |
> | Registrar-key recovery | Current root threshold |
>
> Why: the registrar is **online**. Leaving recovery at registrar authority left it as the only
> residual takeover path that does not require host root
> (`OPERATOR-FORGERY.md` §5) — an attacker who compromises the online registrar rotates any
> principal's key to one they hold, and every later event verifies. Under WI-278's threat model
> that is not acceptable. Every recovery is still signed as `mode: recovery`, still reports
> `key_binding: recovery_rotated`, and still carries a reason: **visible classification is
> retained but is not a substitute for prevention.** This overrides `ARCHITECTURE-0.6.0.md:363`
> and §10 of this document wherever they disagree.
- The rotation **must** set `valid_to` on the superseded key in the projection. Local defect 1 of
  the audit (`_principal_keys.py:124-153`, register-as-rotation leaving `valid_to` unset) is
  structurally closed here because `valid_to` is derived from the signed event, not from whether
  a code path remembered the `UPDATE`. `rotate_principal_key_conn` does set it
  (`_principal_keys.py:295-299`); `register_principal_key_conn` also sets it now (`:131-136`).
  Both become projection appliers, not authorities.

### 5.7 `principal_key_revoked`

```json
{
  "type": "regista.key-revocation", "version": 1,
  "trust_domain_id": "uuid", "principal_id": "...", "key_id": "pk_...",
  "reason": "compromised | superseded | decommissioned | policy | unspecified",
  "revoked_at": "...",
  "effective_from": {
    "kind": "on_chain_position",
    "trust_log_event_hash": "self"
  },
  "retroactive_suspicion": {
    "declared": false,
    "suspect_from_event_hash": null,
    "note": null
  },
  "authorized_by": { "authority": "root | registrar", "...": "..." }
}
```

**Revocation is prospective by chain position, never by wall-clock.** `revoked_at` is a claim.
The binding fact is the revocation event's position in the trust-log chain, imported into a
project chain by §6.6. Three revocation semantics currently disagree in the tree (audit §3 local
defect 8); this collapses them to one rule:

> A signature is *revocation-valid* for event E in project P iff no `principal_key_revoked` for
> its key precedes, in P's chain, the most recent `trust_log_checkpoint_observed` at or before E,
> **and** the key was not already revoked at the checkpoint that acceptance imported.

`retroactive_suspicion` lets an operator record "this key may have been compromised since X"
without pretending that retroactively invalidates signatures. Its effect on verification is
exactly one thing: events in the suspect range are reported with
`revocation_status: "suspect_declared"`. It never turns a valid signature invalid and never turns
an invalid one valid. It exists so that a compromise disclosure is in the log rather than in an
email.

### 5.8 Project-local acceptance

A global enrolment does not establish *when a key became authorised in a particular project*
(`ARCHITECTURE-0.6.0.md:367`). Before a key signs its first event in project P, P's chain gets:

```json
{
  "type": "regista.key-acceptance", "version": 1,
  "trust_domain_id": "uuid",
  "project_instance_id": "uuid",
  "principal_id": "agent:0f6c...",
  "key_id": "pk_...",
  "fingerprint": "ed25519:sha256:...",
  "public_key": "base64-raw-32",
  "trust_event_hash": "sha256:...",
  "trust_log_checkpoint": {
    "checkpoint_seq": 12,
    "head_event_hash": "sha256:...",
    "document_digest": "sha256:..."
  },
  "scopes": {
    "entity_kinds": ["work_item", "principal"] ,
    "transitions": null,
    "may_sign_checkpoints": false,
    "may_sign_bundles": false
  },
  "accepted_by": { "principal_id": "...", "key_id": "pk_...", "key_binding_event_hash": "sha256:..." }
}
```

- `public_key` is repeated here **on purpose**. It makes a project bundle self-sufficient for
  key material without making it self-sufficient for *trust*: the bytes are present, the
  authority to believe them comes from the externally pinned root via `trust_event_hash`. A
  verifier that has the bundle but not the trust log can check signatures and must report
  `trust_root: bundled_only`; with the trust log and the pin it reports `externally_pinned`.
  Mismatch between this `public_key` and the enrolment event's is **invalid**, not a preference.
- The event's own hash is what `signing.key_binding_event_hash` refers to in every subsequent v6
  event by that key in that project `[→ sibling A]`.
- ~~Bootstrapping: the *first* acceptance in a project is signed by the key it accepts…~~
  **SUPERSEDED — `RECONCILIATION.md` Resolution 1 (Bootstrap B), collision 2.**
  The self-referential first acceptance is **withdrawn**. It nulled only
  `accepted_by.key_binding_event_hash` while leaving the *envelope* field
  `signing.key_binding_event_hash` impossible to fill — the event would have had to reference
  itself.

  The replacement: **the cutover checkpoint (or `project_initialized`) is the project's first
  key-binding anchor.** Its payload embeds `bootstrap_key_acceptance` — the exact object in
  `RECONCILIATION.md` Resolution 1 (`principal_id`, `key_id`, `scheme_id`, `public_key`,
  `fingerprint`, `trust_event_hash`, `trust_log_checkpoint`, and `scopes` including
  `may_accept_keys`, `may_sign_checkpoints`, `may_sign_bundles`) — and its own event hash is the
  anchor. The next event, **including the first standalone `principal_key_accepted`**, references
  that hash. Every later event references either the checkpoint anchor or a preceding standalone
  acceptance for the same principal/key/scope.

  So: Bootstrap A (§5.2) establishes external authority; Bootstrap B imports it and creates
  project-chain order; ordinary acceptance then runs with **no exceptions and no
  self-authorisation anywhere**. Subsequent acceptances are still signed by an already-accepted
  key holding `scopes.may_accept_keys`, or by the registrar.

### 5.9 `principal_keys` becomes a projection

Schema changes (forward migration, per `ARCHITECTURE-0.6.0.md:799` — never rewrite old
migrations):

```sql
ALTER TABLE principal_keys ADD COLUMN trust_domain_id uuid;
ALTER TABLE principal_keys ADD COLUMN source_event_hash text;   -- the trust-log enrolment/rotation event
ALTER TABLE principal_keys ADD COLUMN acceptance_event_hash text; -- the project acceptance event
ALTER TABLE principal_keys ADD COLUMN projection_version int NOT NULL DEFAULT 1;
```

`source_event_hash` and `acceptance_event_hash` become `NOT NULL` for every row created after
cutover; pre-cutover rows keep `NULL` and are reported as `legacy_unsourced`.

> **AMENDED — `RECONCILIATION.md` overlay change 3.** Projection rebuild is valid **only for
> v6 lifecycle state.** There are no signed lifecycle events for the HMAC epoch, and the
> dominant legacy key (`regista-prod-001`, 304,333 events) has **no `principal_keys` row in any
> project** — it resolves only from an operator key file (WI-275). So "rebuild `principal_keys`
> from signed events" cannot reconstruct the legacy epoch, and must not be described as if it
> could. Legacy resolution stays a **separately labelled compatibility input** and never becomes
> lifecycle evidence. `regista trust rebuild-projection` therefore rebuilds the v6 rows and
> leaves `legacy_unsourced` rows alone; a rebuild that *empties* them is a defect, and a rebuild
> that *invents* them is worse.
>
> Rule 2 below (private event-driven appliers that break bypass paths at **import** time) is
> P2.2 work and is load-bearing: documentation is not a control, and the bypass is what happened
> last time.

Hard rules:

1. **No verifier resolves a key from this table for a v6 event.** `TrustedKeySource.PRINCIPAL_REGISTRY`
   (`_verification.py:103`) is retained *only* for v4/v5 legacy verification, where using it forces
   `applicability = LEGACY_PARTIAL` and `"key_binding" ∈ unsigned_fields`. For a v6 event,
   resolving via `PRINCIPAL_REGISTRY` is a programming error and raises.
2. `register_principal_key_conn` / `rotate_principal_key_conn` / `revoke_principal_key_conn`
   (`_principal_keys.py:77`, `:266`, `:334`) are renamed to `_apply_*_projection` and become
   **private, event-driven appliers**. They gain a required `source_event_hash` parameter. Their
   current public names are removed from the package surface, which mechanically breaks the three
   bypass paths (`_cli.py:1594,1648`; `_ops.py:1184,1200`; `_witness.py:157,205,256`) at import
   time rather than at review time.
3. `regista doctor` gains `trust:projection_consistent:<project>`: rebuild the projection from
   the signed events in a temp table and diff. Any divergence is a **failure**, not a warning, in
   production posture.
4. The rebuild is a first-class command: `regista trust rebuild-projection --project <p>
   [--dry-run]`. If the table can be rebuilt on demand, the temptation to hand-fix a row
   disappears.

### 5.10 Enrolment-before-use: the decision procedure

For a v6 event `E` in project `P` signed by key `K` with
`E.signing.key_binding_event_hash = h_A`:

1. Resolve `h_A` within the presented material to an event `A`. Not found → **`key_binding:
   unresolved`**, §5.11.
2. `A` must be a `principal_key_accepted` in **this** project (`A.project_instance_id ==
   P`), for `A.principal_id == E.actor.principal_id` and `A.key_id == E.signing.key_id`. Any
   mismatch → **INVALID**, reason `KEY_BINDING_MISMATCH`.
3. `A` must precede `E` **by chain traversal**: `A` is reachable from `E` by following
   `chain.previous_project_event_hash`. Not by `occurred_at` (a signed actor claim,
   `ARCHITECTURE-0.6.0.md:75`) and not by `global_seq` (unsigned by design,
   `_verification.py:428-434`). Not reachable, or reachable in the wrong direction →
   **INVALID**, reason `ENROLLMENT_AFTER_USE`.
4. No `principal_key_acceptance_revoked` for `A` lies between `A` and `E` in `P`'s chain.
   Otherwise **INVALID**, reason `KEY_ACCEPTANCE_REVOKED`.
5. `A.trust_event_hash` must resolve to a `principal_key_enrolled` (or `principal_key_rotated`)
   for the same principal/key/fingerprint, whose position precedes `A.trust_log_checkpoint`. If
   the trust log is not presented → `key_binding: trust_log_only` is unavailable, so
   `trust_root: bundled_only` at best; see §8.
6. Revocation: apply §5.7's rule using the most recent `trust_log_checkpoint_observed` at or
   before `E` in `P`. Three outcomes: `not_revoked`, `revoked_before_use` (**INVALID**), or
   `indeterminate_window` (§6.6).

Ordering is therefore established entirely by hash-linked chain traversal plus one explicit
cross-chain import point. No clock, no sequence number, no side table.

### 5.11 A key whose enrolment event cannot be found

This is the case implementations get wrong by falling back, so it is specified exhaustively.

| Situation | Verdict | Reason code | Rationale |
|---|---|---|---|
| `h_A` not present in the material, and the material makes **no completeness claim** (bundle scope `declared-selection`, or a partial export) | `UNVERIFIABLE`, `key_binding: unresolved` | `KEY_BINDING_UNRESOLVED` | Absence of evidence. The signature may well be fine; the verifier cannot say. |
| `h_A` not present, and the material **claims completeness** (bundle scope `complete-store`, or an online store) | `INVALID` | `KEY_BINDING_MISSING_FROM_COMPLETE_SCOPE` | The completeness claim is false. That is a fact about the artifact, not an absence. |
| `h_A` resolves to an event that is not a `principal_key_accepted`, or is for a different principal/key/project | `INVALID` | `KEY_BINDING_MISMATCH` | Contradicted evidence. |
| `h_A` resolves but does not precede `E` in chain order | `INVALID` | `ENROLLMENT_AFTER_USE` | |
| `h_A` absent because the event predates the project's cutover (v4/v5) | `LEGACY_PARTIAL`, `legacy_reason: "pre_cutover_no_key_binding"` | — | Legacy semantics, bounded by the cutover checkpoint. |
| `h_A` absent but a `legacy_key_binding_attested` covers `E` | `LEGACY_PARTIAL`, `legacy_reason: "retrospective_key_binding"` | — | §6. Never `FULLY_AUTHENTICATED`. |
| A row exists in `principal_keys` naming the key | **irrelevant** | — | The table is a projection. It is never consulted for a v6 event. Consulting it is the S6 defect. |

The last row is the one that matters. **There is no fallback.** `_verification.py`'s existing
discipline — "never fall back to a rebuilt candidate after a failure" (`AUDIT-REPORT.md:208-210`)
— extends verbatim to key resolution.

### 5.12 Action delegation — `regista.action-delegation/v1` (owned here)

> **NEW — assigned by `RECONCILIATION.md` Resolution 2 (third ownerless artifact) and corrected
> by collision 16.** `V6-ENVELOPE.md` §1.5.1 specifies the *reference* an event embeds; this
> section freezes the *document*. Without it WI-008 has no implementable contract.

**Registrar delegation and action delegation are distinct and are not interchangeable.**
`registrar_delegated` (§5.4) authorises **lifecycle administration** — enrolling, rotating and
revoking keys. It never authorises writing work-item events. Action delegation authorises a
subject principal to take **actions** within a named scope. Conflating them would let a
credential minted for key administration sign business events, which is the shape of every
"scope creep by field reuse" defect this release exists to remove.

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
  "signature": { "scheme_id": "ed25519", "value": "base64" }
}
```

Signature input and hash use **two distinct domains** (`V6-ENVELOPE.md` §6.1):

```text
d = JCS(document minus {"signature"})
signature_input = b"regista.action-delegation.v1\x00"      || uint64be(len(d)) || d
credential_hash = SHA256(b"regista.action-delegation.hash.v1\x00" || uint64be(len(d)) || d)
```

Validity rules, all checked by the verifier, all fail-closed:

- A **non-root link requires** `parent_credential_hash` **and** a parent with
  `delegation_allowed: true`. Maximum chain depth is **eight** (matching the envelope's
  `authorization.credentials` bound).
- **Cycles are invalid.** **Scope widening is invalid** — a child's scope must be a subset of its
  parent's on every axis.
- An **expired** credential (`not_after` at or before the event's chain position) and a
  **revoked** credential are invalid, not degraded.
- `action_delegation_revoked` is a **signed project event**, and ordering is **project-chain
  ordering** — never `global_seq`, never wall-clock comparison across chains.
- The chain must begin at a directly trusted or authorised principal and end at
  `actor.principal_id`, and every `credential_hash` in the event must equal the recomputed hash
  of the presented document.

**An action credential never manufactures human identity.** `principal_kind` comes from a
root/registrar-authorised `principal_registered` event (§5.3) and from nowhere else. Therefore
`accepted_by_credentialed_human` means *"the accepting principal has an authenticated human
registration"*, **not** *"a delegation document said human"*. This corrects the dependency at
`REVIEW-VERDICTS.md` §5.3 (collision 16): the review gate's `reviewer_evidenced_non_model` reads
principal registration, not the credential's assertion.

What a valid credential proves: **authorisation under the configured trust root**. What it does
not prove: human intent, authorship, or which model produced the action.

---

## 6. Cross-schema key scoping (WI-241)

### 6.1 The finding, and a correction to its magnitude

WI-241 records **12,866** `agent_provenance` Ed25519 events signed by `pk_4f70570b481745a8`
(principal `mvmcc03-agent`), a key registered in the **`agent_notes`** schema, measured
2026-08-02. `ARCHITECTURE-0.6.0.md:402` says **48,688**, and `:819` says **48,689** for
"all historical Ed25519 signatures". These are three different numbers for three different
populations at three different times:

- 12,866 — `agent_provenance` cross-schema-signed events, 2026-08-02.
- 48,688 / 48,689 — estate-wide Ed25519 events (`303,820 + 48,689 = 352,509`, the architecture's
  own totals).

**Neither is a contract value.** No document, migration, test or cutover payload may hardcode any
of them. The preflight `[→ sibling D]` produces, per project: Ed25519 event count, count whose
`key_id` resolves in *this* schema, count resolving only in another named schema, and count
resolving nowhere. Stage 6 rehearsal asserts the *preflight* numbers, not the numbers in this
document. (See §10 D-1.)

### 6.2 Registry scoping in the epoch model

| Layer | Scope | Authority |
|---|---|---|
| Key existence and lifecycle | **Trust domain** (estate-wide) | The trust-domain log. One registry for the estate. |
| Key *authorisation to sign in a project* | **Project instance** | `principal_key_accepted` on that project's chain. |
| `principal_keys` table | Project schema | Projection only. Never authority. |

This is what closes WI-241 structurally: the reason a key registered in `agent_notes` could sign
in `agent_provenance` and leave the second project's bundle unverifiable is that *existence* was
project-scoped. Making existence domain-scoped and *authorisation* project-scoped separates the
two questions that were conflated. Cross-project signing becomes legal, explicit and provable
instead of accidental and unresolvable.

Bundle export consequences `[→ sibling C]`: a bundle must include the trust-log enrolment event
and the project acceptance event for every key that signed any included event
(`ARCHITECTURE-0.6.0.md:184-185`, "Required key-lifecycle proofs" and "Required project
key-acceptance events"). Export fails closed if it cannot resolve one — it does not ship a bundle
whose signatures it knows cannot be checked.

### 6.3 The existing events: `legacy_key_binding_attested`

The architecture is explicit that copying the `agent_notes` row into `agent_provenance` and
calling it contemporaneous enrolment is forbidden (`ARCHITECTURE-0.6.0.md:387`). Instead:

```json
{
  "type": "regista.legacy-key-binding-attestation",
  "version": 1,
  "attestation_id": "uuid",
  "trust_domain_id": "uuid",

  "subject": {
    "principal_id_as_recorded": "mvmcc03-agent",
    "canonical_principal_id": "agent:0f6c... | null",
    "key_id": "pk_4f70570b481745a8",
    "scheme_id": "ed25519",
    "public_key": "base64-raw-32",
    "fingerprint": "ed25519:sha256:..."
  },

  "source_registration": {
    "schema": "agent_notes",
    "table": "principal_keys",
    "registered_at": "2026-07-xx...",
    "registered_by": "system",
    "status_at_attestation": "active",
    "row_digest": "sha256:..."
  },

  "covers": {
    "target_project_instance_id": "uuid",
    "selector": "event-hash-set | chain-range",
    "event_count": 12866,
    "event_hash_set_root": "sha256:...",
    "first_event_hash": "sha256:...",
    "last_event_hash": "sha256:...",
    "all_covered_signatures_verified_at_attestation": true
  },

  "attested_by": {
    "principal_id": "human:...",
    "key_id": "pk_...",
    "method": "operator-inspection-of-source-schema",
    "attested_at": "..."
  },

  "proves": ["signature_verifiable_under_named_key"],
  "does_not_prove": [
    "contemporaneous_enrollment",
    "enrollment_before_use",
    "registry_chronology",
    "exclusive_custody_at_signing_time",
    "actor_attribution"
  ]
}
```

Design points that are not decoration:

- **`covers` is bounded and committed.** `event_hash_set_root` is a Merkle root over the covered
  event hashes, sorted ascending as raw bytes, leaves
  `SHA256(b"regista.legacy-binding.member.v1\x00" || event_hash_bytes)`. An operator cannot later
  widen coverage without a new, differently-hashed attestation. An attestation that says "all
  events by principal X" is forbidden — unbounded coverage is how a retrospective record turns
  into a blanket amnesty.
- **`does_not_prove` is inside the signed payload.** The limitation travels with the artifact.
  A downstream tool that renders the attestation without the limitation is contradicting a signed
  field, which is a bug a test can catch — unlike a limitation that lives only in release notes.
- The attestation is signed by a *human* principal with an authorised key, not by the registrar
  and not by `system`. It is a human claim about history, not a derivable fact
  (WI-055 ratification uses exactly this framing for identity mappings).
- `row_digest` is `SHA256(JCS({principal_id, key_id, scheme, public_key_hex, fingerprint, status,
  valid_from, valid_to, registered_by, registered_at}))` over the source row as read. It does not
  make the row trustworthy; it makes a later silent change to the row detectable by anyone holding
  the attestation.

### 6.4 Exactly what a retrospective attestation proves

**Proves.** For each event in `covers`: the stored signature verifies under the named public key
under the named scheme. Nothing about that verification depends on the attestation — the
attestation's contribution is to make the key *findable and nameable* by a verifier that has only
the target project's material. It also records, under a signature, that an identified principal
asserted at a stated time that this key material is what the named source registry held, and that
they checked every covered signature at that time.

**Does not prove** (this list is `does_not_prove` above, in prose, and matches
`ARCHITECTURE-0.6.0.md:873` limitation 4):

- *Contemporaneous enrolment.* The registry row may have been created, altered or backdated after
  the events were signed. `principal_keys` has no signed history, which is the whole of S6.
- *Enrolment before use.* No ordering evidence exists between the source registry and the target
  project's chain. There is no shared chain, no checkpoint, and `global_seq` is per-schema and
  unsigned.
- *Registry chronology.* `registered_at` is a database default, not evidence.
- *Exclusive custody at signing time.* The key may have been held by more than one party.
- *Actor attribution.* That the events' `actor_id` names the entity that actually acted.

**Verification effect.** An event covered only by a retrospective attestation is
`LEGACY_PARTIAL` with `legacy_reason = "retrospective_key_binding"` and
`key_binding = "retrospective"`. **It can never be `FULLY_AUTHENTICATED`,** under any policy,
including a policy that says it may. This is a class invariant in the same style as
`_verification.py:418-443`: assert it in `__post_init__`, do not leave it to a policy field.

### 6.5 Future cross-project signing

Legal, and provable: the key is enrolled once in the trust domain and *accepted* in each project
where it signs (§5.8). Two acceptances, two chains, both externally rooted. The failure WI-241
describes cannot recur, because a key with no acceptance in project P cannot produce a valid v6
event in P at all (§5.10 step 2).

### 6.6 The cross-chain ordering window — named, because it is real

The trust log and each project are separate chains. Chain traversal orders events *within* a
chain; it says nothing *across* chains. The only cross-chain fact is a checkpoint reference.

Rules:

- Every project appends `trust_log_checkpoint_observed` (payload:
  `{checkpoint_seq, head_event_hash, document_digest, observed_at}`) at minimum: at every
  `principal_key_accepted`, at every signed project checkpoint, and at least once per 24 hours of
  writing activity. The obligation is enforced by the doctor
  (`trust:checkpoint_freshness:<project>`), which fails production posture when the most recent
  observation is older than the configured bound.
- A trust-log revocation is enforceable in project P from P's first
  `trust_log_checkpoint_observed` whose checkpoint is at or after the revocation.
- Events in P between the revocation and that observation are `revocation_status:
  "indeterminate_window"`. They are **not** silently valid and **not** automatically invalid;
  policy decides, and the report always names the window
  (`{from_event_hash, to_event_hash, event_count}`).

Making this window explicit is the honest alternative to comparing `global_seq` across unrelated
schemas, which is what the architecture correctly refuses (`ARCHITECTURE-0.6.0.md:381`) but does
not replace with a stated bound.

---

## 7. Witness enrolment (WI-264)

> **CUT FROM 0.6.0 — `RECONCILIATION.md` FINAL SCOPE.** Positive witness-independence work does
> not ship in this release. There are **zero** `witness_registrations` and **zero**
> `witness_receipts` estate-wide (`preflight-live.json`), so there is nothing to migrate and no
> deployed evidence to preserve. What that means concretely:
>
> - The signed witness lifecycle below (`witness_registered`, `witness_key_rotated`,
>   `witness_paused`, `witness_resumed`, `witness_revoked`) is **not implemented in 0.6.0**, and
>   those rows are struck from the §5.3 event catalogue.
> - Webhook delivery is preserved only as **non-evidentiary transport** if consumers require it.
>   Every security claim attached to it is removed or hidden — not softened.
> - §7.4's BC-016 discussion stays, because the *finding* is the reason bundle v3 takes trust
>   material as a required argument with no default (`BUNDLE-V3.md` §4.1). That function-signature
>   change is the structural fix; witness enrolment was never the fix.
> - **§7.1's correction to `spec.md` still ships.** A false sentence in the repository
>   ("the anchored `principal_keys` registry") must be corrected whether or not the witness work
>   lands, and this is exactly the class of claim 0.6.0 exists to stop making.
>
> A signed witness lifecycle and a genuinely external witness belong in a later release that has
> an actual witness. Retained below for that release, not for this one.

### 7.1 Current state, verified

`register_witness` inserts into `witness_registrations` (`_witness.py:134-153`) and then calls
`register_principal_key_conn` (`_witness.py:155-163`) — a plain `INSERT` into `principal_keys`
(`_principal_keys.py:138-146`). No event is emitted anywhere. `rotate_witness_key` does an
`UPDATE` plus `rotate_principal_key_conn` (`_witness.py:246-262`); `unregister_witness` deletes
receipts and rows and revokes (`_witness.py:180-210`).

`spec.md:698` describes this as "the anchored `principal_keys` registry" and says downstream
verifiers "can treat the witness key as a trust root pinned in the same registry as actor
principals". That sentence is false — the registry is not anchored — and it is the sentence the
BC-016 resolution rests on. WI-264 says exactly this. The 0.5.6 CHANGELOG was already corrected
(`5deaf46`) so nothing ships overclaiming; **`spec.md:698` itself must be corrected in the same
change that lands this contract.**

### 7.2 Contract

Witness registration, key rotation, pause and revocation become signed trust-log events on the
witness's principal entity:

| Transition | Payload additions over §5.5/§5.7 |
|---|---|
| `witness_registered` | `witness_id`, `url`, `mode` (`witness`/`push`), `event_filter_digest`, `key` block identical to `principal_key_enrolled` |
| `witness_key_rotated` | as `principal_key_rotated` |
| `witness_paused` / `witness_resumed` | `reason` |
| `witness_revoked` | as `principal_key_revoked`, plus `unregistered: bool` |

Principal id is `service:witness.<witness_id>` (§2.3). `witness_registrations` and the witness's
`principal_keys` rows become projections of these events, with the same demotion rules as §5.9.
`unregister_witness`'s current `DELETE FROM witness_receipts` (`_witness.py:181-184`) discards
attestation evidence (audit §3 local defect 7) and is replaced by a revocation event plus
retention of receipts; deletion of evidence to satisfy a foreign key is not an acceptable
implementation of revocation.

### 7.3 When a witness receipt is evidence

Reproducing `ARCHITECTURE-0.6.0.md:417-424` as a checklist the verifier actually runs. All four:

1. The witness key chains to the externally pinned root: `witness_registered` (or
   `witness_key_rotated`) is in the trust log, authorised by root or registrar, and the trust log
   verifies to the pinned genesis.
2. Its enrolment **precedes** the receipt's subject, established by §5.10's traversal procedure
   plus §6.6's checkpoint import — not by the receipt's own timestamp.
3. The receipt signs a **content or checkpoint hash**, not an event UUID. (The estate's existing
   timestamping commits to `uuid.bytes`, `_timestamping.py:84-96`, which witnesses nothing; that
   subsystem is deleted in 0.6.0 and its mistake must not be re-created here.)
4. The auditor obtained the receipt **or** a corroborating checkpoint through a channel
   independent of the database under audit.

Condition 4 is the one that fails in the estate today, and it fails structurally:
`ARCHITECTURE-0.6.0.md:880` limitation 11 — a witness configured and stored by the same operator
is not an independent witness. `verify_witness_receipt` must therefore report
`witness_independence: "not_established"` whenever the receipt was read from the same store as its
subject, and must never emit a positive independence claim in 0.6.0. See OPERATOR-FORGERY R7.

### 7.4 BC-016

BC-016's recorded resolution — bundle-carried witness keys are display-only, the real root is
"enrolment in the anchored key registry" — becomes **true** only when §7.2 lands *and* the trust
log is externally pinned (§4). Until both hold, the resolution rests on a property the
implementation does not have, and the breadcrumb should stay reopened. When both land, the
correct restatement is:

> The trust root for a witness key is its signed enrolment in the trust-domain log, verified
> against externally pinned root fingerprints. The bundle's copy of the key is a convenience copy
> and is never a root. A verifier without external trust material reports
> `trust_root: bundled_only` and must not present the result as authenticated.

---

## 8. How a verifier obtains and pins trust material

This section is written against the **post-S1** `_verification.py`, so it is an extension of
existing structure rather than a parallel design.

### 8.1 Trusted-key resolution

`_verification.py:102-107` defines `TrustedKeySource` with `PRINCIPAL_REGISTRY`, `KEYSET_FILE`,
`SUPPLIED_PUBLIC_KEY`, `BUNDLE_EMBEDDED`, `NONE`, and `_verification.py:677-680` defines the
`TrustedKeyResolver` protocol (`resolve(key_id) -> TrustedKey | None`). Extend, do not replace:

```python
class TrustedKeySource(StrEnum):
    PRINCIPAL_REGISTRY = "principal_registry"   # legacy v4/v5 ONLY; forces LEGACY_PARTIAL
    KEYSET_FILE = "keyset_file"
    SUPPLIED_PUBLIC_KEY = "supplied_public_key"
    BUNDLE_EMBEDDED = "bundle_embedded"          # circular; S5
    TRUST_DOMAIN_LOG = "trust_domain_log"        # NEW: from signed lifecycle events
    EXTERNALLY_PINNED = "externally_pinned"      # NEW: chains to a pinned genesis root
    NONE = "none"
```

`TrustDomainResolver` implements the protocol and resolves by **replaying** the trust log and the
project's acceptance events, never by querying `principal_keys`:

```python
@dataclass(frozen=True)
class TrustDomainResolver:
    policy: TrustPolicy                    # §4.6, caller-supplied, never from the store
    genesis: GenesisDocument               # verified per §3.6
    trust_log: Sequence[VerifiedEvent]     # already strict-verified, Ed25519, v6
    project_acceptances: Mapping[str, AcceptanceEvent]   # keyed by acceptance event hash
    def resolve(self, key_id: str | None) -> TrustedKey | None: ...
```

`TrustedKey` (`_verification.py:655-673`) gains `trust_domain_id: str | None`,
`key_binding_event_hash: str | None`, and `binding_kind: Literal["accepted","retrospective",
"legacy_registry"]`. `scheme_id` continues to come from trusted metadata and never from the row —
that discipline is already correct (`_verification.py:391-392`, `scheme_id` "DERIVED from key
metadata, not the row") and this contract does not weaken it.

The resolver's `resolve()` takes `key_id` only, per the existing protocol. Key **binding** (the
`key_binding_event_hash` check, §5.10) is not resolution and belongs in the verifier alongside the
existing principal-binding check, so the protocol signature does not change.

### 8.2 `TrustedKeySource.BUNDLE_EMBEDDED` stays, and stays honest

`_verification.py`'s `BundleKeyResolver` docstring already says the registry is "*inside the
artifact under verification* — a circular trust root (S5)". Keep the resolver, keep the source
value, and make the consequence structural: any event resolved via `BUNDLE_EMBEDDED` yields
`trust_root: "bundled_only"`, and a bundle verdict of `externally_authenticated`
`[→ sibling C]` is unreachable when any event in the bundle resolved that way. That is S5 closed
at the verdict boundary, which is what the design review required
(`AUDIT-REPORT.md:240-245`).

### 8.3 `VerificationResult` additions

> **SUPERSEDED (ownership and completeness) — `RECONCILIATION.md` Resolution 2.**
> `RESULT-MODEL.md` §10 owns `VerificationResultV6` and is the normative list. The fields below
> are a **subset**: the owned model also carries `epoch_position`, `attribution`,
> `checkpoint_binding`, `unbound_properties`, `producer_consistency`, and adds
> `bootstrap_external` and `legacy_unbound` to `key_binding` and `mapping_absent` to
> `identity_consistency`. Implement from `RESULT-MODEL.md` §10; the invariants stated below
> remain in force and are reproduced there.

Added fields, all reported, none optional:

```python
trust_domain_id: str | None = None
trust_root: Literal["externally_pinned","trust_log_only","bundled_only","absent"] = "absent"
root_governance: Literal["co_signed","solo","solo_effective","unknown"] = "unknown"
key_binding: Literal["accepted_in_project","trust_log_only","retrospective",
                     "legacy_registry","unresolved","mismatched","after_use",
                     "recovery_rotated"] = "unresolved"
revocation_status: Literal["not_revoked","revoked_before_use","indeterminate_window",
                           "suspect_declared","unknown"] = "unknown"
identity_consistency: Literal["consistent","principal_kind_conflict",
                              "actor_id_ungrammatical"] = "consistent"
```

Class invariants, enforced in `__post_init__` alongside the four already there
(`_verification.py:418-443`):

- `key_binding ∈ {"mismatched","after_use"}` ⟹ `applicability is INVALID`.
- `key_binding == "retrospective"` ⟹ `applicability is not FULLY_AUTHENTICATED` and
  `legacy_reason == "retrospective_key_binding"`.
- `key_binding == "legacy_registry"` ⟹ `applicability is not FULLY_AUTHENTICATED` and
  `"key_binding" in unsigned_fields`.
- `revocation_status == "revoked_before_use"` ⟹ `applicability is INVALID`.
- envelope version is v6 ⟹ `key_binding != "legacy_registry"` (raises; programming error).
- `applicability is FULLY_AUTHENTICATED` and envelope version is v6 ⟹
  `key_binding == "accepted_in_project"` and `trust_root != "absent"`.

The last one is the load-bearing invariant of this whole document: **a v6 event cannot be reported
as fully authenticated without a project-local acceptance and some trust root.** It is an assert,
not a convention, for the same reason `_verification.py:422-427` is.

Note `trust_root == "trust_log_only"` (log present and internally consistent, but no
caller-supplied policy pinning the genesis) is deliberately *not* `absent` and deliberately *not*
`externally_pinned`. It is the honest middle state and the one most online verifications will
report.

### 8.4 What the verifier is given, and never fetches

| Input | Source | Required for |
|---|---|---|
| Trust policy (§4.6) | Caller, out of band | `trust_root: externally_pinned` |
| Genesis document | Caller, or the publication clone | `root_governance` other than `unknown` |
| Trust-log events | Bundle section, or an estate trust bundle | `TRUST_DOMAIN_LOG` resolution |
| Project acceptances | The project's own chain / the bundle | `key_binding: accepted_in_project` |

The verifier performs **no network I/O**. `regista trust recheck` (§4.5) is a separate,
explicitly-invoked command. A verifier that silently fetches its own trust material has no trust
root at all; it has whatever the network gave it.

---

## 9. Conformance criteria

Stage 0 freezes contracts; these are the tests that will show the contract was implemented as
frozen. They are listed here so an implementer cannot satisfy the prose and miss the point.

**Genesis**
1. A genesis document with `threshold: 1` and three signers is reported `solo_effective`, never
   `co_signed`.
2. Removing one of two signatures from a `threshold: 2` document makes it **invalid**, not
   "verified with one signature".
3. Editing `governance.mode` alone makes the document invalid (mode/threshold disagreement).
4. Editing `binding_core` at all changes `trust_domain_core_digest` and `trust_domain_id`; a
   pinned policy rejects the result as a *different domain*.
5. Adding a countersignature or an anchor changes neither digest and invalidates no signature.
6. A `solo` genesis produces bundles whose signed membership statement contains
   `"mode": "solo"`; a renderer test asserts the string reaches the report.

**Publication**
7. `regista trust publish --genesis` twice is a no-op the second time and exits 0.
8. Publishing a *different* genesis over an existing one is refused, non-zero.
9. `regista trust recheck` reports `rewritten` after a force-push that drops a checkpoint commit.
10. `--dry-run` produces byte-identical output to the real run and touches nothing.
11. Publish completes in under 5 seconds with no interactive prompt and with no private key
    available to the process.

**Key lifecycle**
12. `regista trust rebuild-projection` reproduces `principal_keys` byte-for-byte from signed
    events, for a store built entirely post-cutover.
13. An `UPDATE principal_keys SET status='active'` on a revoked key changes **no** verification
    outcome for any v6 event, and the doctor projection check fails.
14. A v6 event whose `key_binding_event_hash` names an acceptance later in the chain is `INVALID`
    with `ENROLLMENT_AFTER_USE`.
15. A v6 event whose acceptance is absent from a `complete-store` bundle is `INVALID`; the same
    event absent from a `contiguous-range` bundle is `UNVERIFIABLE`, with the missing acceptance
    named as outside scope. (`declared-selection` is cut from 0.6.0 — `BUNDLE-V3.md` §3.5.)
16. An enrolment event lacking `public_key` is rejected at write time (guards Defect A).
17. Importing `regista._principal_keys.register_principal_key` fails (guards the bypass paths).
18. A rotation without `dual_authorization.old_key_signature` is reported `recovery_rotated`
    everywhere it surfaces, including in a bundle verdict.

**Identity**
19. `enroll_principal("mvmcc03-agent")` is refused post-cutover; `enroll_principal("agent:...")`
    succeeds. (This is the inversion of `_provision.py:234-247`.)
20. The estate grammar sweep (§2.7) passes over real preflight output, or fails naming each
    exception.
21. An alias never affects `key.principal_id == actor_id` binding: a covered legacy event still
    binds to its exact old id.
22. `witness_principal_id()` returns `service:witness.<uuid>`; historical `witness:<uuid>` events
    still verify.

**Cross-schema**
23. The 12,866/48,688 figures appear in no source file, migration, test fixture or cutover
    payload; the rehearsal asserts against preflight output.
24. An event covered by a retrospective attestation is `LEGACY_PARTIAL` under **every** policy,
    including one that tries to accept it as full.
25. Widening an attestation's coverage changes `event_hash_set_root` and therefore the event hash.

---

## 10. DIVERGENCES

Where the architecture is ambiguous, silent, or in my judgement wrong. Each is flagged rather
than quietly chosen.

**D-1 — The event counts in the architecture are inconsistent with the tracker and should not be
frozen.** `ARCHITECTURE-0.6.0.md:402` says 48,688; `:819` says 48,689; WI-241 says 12,866 for
`agent_provenance`. They measure different populations at different times. I have specified that
no artifact hardcodes any of them (§6.1). *Owner check:* if 48,688 was intended as the
`agent_provenance` figure re-measured after 2026-08-02, the estate grew by ~36k Ed25519 events in
six days and that is worth knowing independently.

**D-2 — I made `trust_domain_id` a derivation of the genesis binding core; the architecture just
says "uuid".** `ARCHITECTURE-0.6.0.md:78` treats it as an opaque identifier preventing
cross-estate credential import. Deriving it from governance is a strictly stronger construction
and is, as far as I can see, the only way to satisfy the owner's "visible in the artifact"
constraint *structurally* rather than by convention. Cost: a governance change is an epoch change
(§3.3 consequence 1). I consider that correct — a governance downgrade *should* be an epoch
event — but it is a real constraint and the owner should confirm it. If rejected, the fallback is
`trust_domain_id` as a random UUID plus a mandatory `root_governance` block in every checkpoint,
catalog and bundle statement, which is weaker because it depends on every producer remembering.

**D-3 — `solo_effective` is mine, not the architecture's.** The architecture and WI-272 describe
two modes. A `threshold: 1, signer_count: 3` document is neither, and calling it `co_signed`
would be precisely the theater the owner's constraint forbids. Adding the third mode is cheap and
closes the hole.

**D-4 — I folded WI-055's "signed, scope-bounded identity-cutover record" into
`principal_alias_bound` with a mandatory `scope`.** WI-055's ratification describes it as a
separate record type. One event kind with a required scope object is simpler and makes the
"never a global alias for `human:itadmin`" prohibition structural rather than procedural. If the
owner prefers two kinds, the payloads are otherwise identical.

**D-5 — The architecture's §3 does not say how trust-log ordering enters a project chain, and
without that, "revocation at the event's position in the project chain"
(`ARCHITECTURE-0.6.0.md:137`) is undefined.** I have specified
`trust_log_checkpoint_observed` and a named `indeterminate_window` (§6.6). I believe this is a
genuine gap in the architecture rather than an omission of detail: two hash chains have no
mutual order, and the alternative the architecture rejects (comparing `global_seq` across
schemas) is correctly rejected but not replaced.

**D-6 — I think `ARCHITECTURE-0.6.0.md:383` is too permissive.** It says "`principal_keys` can
remain as a cache, but it must be rebuilt from these signed events and never be a verifier's
authority." "Can remain" plus a documented prohibition is exactly the arrangement S6 found
failing, four times over. I have specified that the public mutation functions are *removed from
the package surface* (§5.9 rule 2) so the bypass paths break at import. Documentation is not a
control.

**D-7 — Witness independence.** `ARCHITECTURE-0.6.0.md:424` says "a registered callback in the
same database is not an external witness", and `:880` limitation 11 repeats it, but §3's witness
contract still lists four conditions of which the fourth (independent acquisition) is not
checkable by regista at all. I have specified that `witness_independence` is reported as
`not_established` and that **no** code path sets it otherwise in 0.6.0 (§7.3). This means the
witness subsystem produces *no* positive independence claim in this release. If that is
unacceptable, the honest alternative is to delete the witness subsystem in 0.6.0 as the anchoring
subsystem is being deleted, for the same reason. I recommend keeping it, reporting honestly, and
flagging the deletion question for 0.7.0.

**D-8 — Recovery rotation and the co-signed default interact, and the architecture does not say
how.** `ARCHITECTURE-0.6.0.md:363` says recovery rotation "requires the registrar". But the
registrar is an *online* credential, so an attacker with the registrar key can recovery-rotate
any principal's key and then sign as them. That is a real escalation and it deserves an explicit
decision. My specification keeps recovery at registrar authority (matching the architecture) but
makes it *visibly classified* everywhere (§5.6) so the escalation leaves a permanent, externally
visible mark. **I think the stronger rule — recovery rotation requires root threshold, not
registrar — is probably correct for a co-signed estate**, and I have not adopted it only because
it contradicts the architecture. Owner decision requested; this is the residual with the shortest
path from "documented" to "exploited". Tracked in OPERATOR-FORGERY as R11.

**D-9 — The domain-separator convention is inconsistent in the existing tree and I have partially
diverged.** `principal_lifecycle.py:63-65` puts the domain *inside* the JCS object as a `"domain"`
field; the architecture (`:88-99`) uses a byte prefix. I have specified the byte-prefix framing
for all new artifacts and a `v2` possession challenge that keeps the object field *and* adds the
prefix (§5.5), which is belt-and-braces but avoids re-litigating a tested implementation. A purist
would pick one.

---

## 11. Obligations this contract places on callers, not on regista

Stated explicitly so they are not mistaken for guarantees.

1. `subject` in a principal id must be a stable opaque identifier. regista checks the grammar, not
   the stability. A caller that puts a mutable login there produces a grammatically valid,
   semantically worthless identity.
2. `custody.declared_mode` and `custody.declared_backend` are unverified claims (§3.2, §5.5).
3. Root private keys must be generated and held off the estate hosts. Nothing in the artifact
   proves this (OPERATOR-FORGERY R1).
4. The co-signer must be a different person with independently held key material. Nothing in the
   artifact proves this (R2).
5. The custodian GitHub account must not be controlled by the same operator in practice. Account
   separation is not control separation (R3).
6. The auditor must actually perform the §4.5 re-check. An unchecked pin is not a pin.

---

## 12. Handoffs

| To | Obligation |
|---|---|
| Sibling A (v6 envelope) | `trust_domain_id`: lowercase canonical UUID, derived per §3.3, required on every v6 event, non-null. `signing.key_binding_event_hash`: `"sha256:<hex>"` of the `principal_key_accepted` event in **this** project for **this** principal+key; non-null for every v6 event; semantics in §5.8/§5.10. Cutover checkpoint payload additions in §3.7 item 3. |
| Sibling C (bundle v3) | Bundle must carry the `trust_root` block (§3.7 item 2), the trust-log lifecycle events and project acceptances for every signing key (§6.2), and must surface `root_governance.mode` in the verdict. `externally_authenticated` is unreachable when any event resolved via `BUNDLE_EMBEDDED` (§8.2). Trust policy schema is §4.6. |
| Sibling D (preflight) | Per project: distinct `actor_id`/`principal_id` values with canonical/non-canonical classification (§2.7); Ed25519 events by key-resolution locus (this schema / named other schema / unresolved) (§6.1); `principal_keys` rows lacking a corresponding signed event; witness principals using the `witness:` prefix (§2.3); `principal_kind_conflict` counts (§2.6). Output canonical JSON. |
| Release notes | §11 obligations, and the non-claims in `OPERATOR-FORGERY.md` §6. |
