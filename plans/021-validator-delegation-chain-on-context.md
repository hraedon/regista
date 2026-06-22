# Plan 021 — Validator delegation chain on context (acting `on_behalf_of`)

**Status:** Draft RFC. Proposed 2026-06-22. Not started.
**Owner:** regista session 67
**Origin:** dossier `WI-004 / validator delegation gap` (`src/dossier/validators.py`).
The reviewer's own `on_behalf_of` is not on regista's `ValidatorContext`, so an
agent reviewing *on behalf of* an author is not caught as a self-review. Not
exploitable in the all-human MVP; latent for the mixed human+agent north star.
**Spec touched:** §19 (public API — `ValidatorContext` shape), FR-13 (validators),
FR-26 (delegation chains, via Plan 010 / BC-197).
**Related:** Plan 010 (delegation chain — `on_behalf_of` field), Plan 020
(validator context enrichment — `actor_kind` + `prior_events`), Plan 008
(strict roles), Plan 016 (privileged transitions — another actor-identity gate).

## 1. Problem statement

Plan 020 enriched `ValidatorContext` with `actor_kind` (the acting actor's
authoritative kind) and `prior_events` (the work-item's pre-transition event
history). Each `Event` in `prior_events` already carries its own
`on_behalf_of: dict | None` (Plan 010 / BC-197), so a validator can inspect the
*authorship-side* delegation chains of prior events.

What is still missing is the **acting actor's** `on_behalf_of` for the
transition currently under validation — i.e., the reviewer's delegation chain.
The transition machinery has it: `transition()` / `in_memory_transition()`
accept `on_behalf_of: dict | None = None` and use it both for chain validation
(`_validate_delegation_chain`) and for the emitted event. But it is **not**
placed on `ValidatorContext`.

The result: a validator that needs to encode "the reviewer is acting on behalf
of someone who is themselves in the author set" (the dossier
`adversarial_review` self-review-via-delegation rule) cannot do so from the
context alone. The author set is reachable via `prior_events`, but the
reviewer's delegation target is not.

### Worked example (the dossier gap)

- Author `human:A` creates and submits work (events have `actor_id=A`,
  `actor_kind=human`, `on_behalf_of=None`).
- Agent `agent:R` calls `transition(..., transition_name="adversarial_review",
  actor_id="agent:R", actor_kind="agent", on_behalf_of={"principal": "human:A"})`.
- The registered `adversarial_review` validator runs with:
  - `actor_id="agent:R"`, `actor_kind="agent"`,
  - `prior_events=(..., events by A, ...)`,
  - but **no** view of `on_behalf_of={"principal": "human:A"}`.

  So the validator sees "agent R is reviewing work authored by human A" — which
  is fine in isolation — and cannot see "agent R is reviewing *on behalf of*
  human A," which is the self-review that must be rejected. The structural
  gate's trust root leaks back into the caller (who must then pre-compute the
  conflict and stash it in `payload`, defeating the point of an in-regista
  validator — see Plan 020 §1).

### Why this is generally useful, not dossier-specific

Any consumer that encodes a separation-of-duties policy using delegation chains
needs the same fact. agent-provenance (cairn) attestation validators, future
"distinct-principal" gates, and any "the delegatee may not also be the reviewer"
rule are the same shape. This is a missing primitive on a public type, not a
dossier feature.

## 2. Proposed design

### 2.1 Extend `ValidatorContext`

Add one field to the frozen dataclass in `_types.py`, mirroring the shape of
`Event.on_behalf_of`:

```python
@dataclass(frozen=True)
class ValidatorContext:
    work_item_id: uuid.UUID
    workflow_name: str
    workflow_version: int
    work_item_type: str
    current_state: str
    new_state: str
    transition_name: str
    payload: dict | None
    custom_fields: dict
    actor_id: str
    actor_metadata: dict | None
    actor_kind: str                        # Plan 020
    prior_events: tuple[Event, ...]        # Plan 020
    on_behalf_of: dict | None              # NEW (Plan 021): acting actor's delegation chain
```

- `on_behalf_of` is the delegation chain of the actor performing *this*
  transition, identical to the value passed to `transition()`. It is the same
  dict shape `Event.on_behalf_of` already uses (Plan 010), validated by the
  same `_validate_delegation_chain` that already runs at the top of both
  transition implementations, so by the time the validator sees the context the
  chain is already well-formed.
- `None` means the actor is acting on their own behalf (no delegation), which
  is the common case and the historical default.

### 2.2 Population (zero-cost when no validator is registered)

Both transition implementations already (a) accept `on_behalf_of`, (b) validate
the chain near the top of the function, and (c) construct `ValidatorContext`
inside the registered-validator branch (zero-cost otherwise, per Plan 020 §2.2).
Plan 021 threads the already-in-scope `on_behalf_of` into that constructor
call — no new reads, no new locks, no new validation.

**Postgres** (`_transition.py`):

```python
ctx = ValidatorContext(
    ...,
    actor_kind=actor_kind,          # Plan 020
    prior_events=prior,             # Plan 020
    on_behalf_of=on_behalf_of,      # NEW (Plan 021)
)
```

**In-memory** (`_in_memory_transition.py`): identical threading.

### 2.3 Serialization round-trip

`ValidatorContext.to_dict()` / `from_dict()` are extended to round-trip
`on_behalf_of`. `from_dict` is tolerant of a missing key for forward
compatibility with contexts serialized before this plan (older sidecar payloads,
older hook/validator marshalling): a missing `on_behalf_of` decodes to `None`,
matching regista's historical "no delegation" default. The dict shape inside
`on_behalf_of` is opaque to regista (it is the consumer-defined delegation
structure validated by `_validate_delegation_chain`); we round-trip it as-is.

### 2.4 What the validator now sees

With Plan 020 + Plan 021 together, a validator has the full actor-identity
picture for a separation-of-duties gate:

- the acting reviewer: `actor_id`, `actor_kind`, `on_behalf_of` (Plan 021),
- the author set: derivable from `prior_events` (each event's `actor_id`,
  `actor_kind`, `on_behalf_of` — all Plan 010).

That closes the dossier WI-004 gap structurally: the self-review-via-delegation
check is `principal_of(ctx.on_behalf_of) in authors_of(ctx.prior_events)` and
runs inside the transition transaction, not in caller-attested payload.

## 3. Spec impact

- **§19 (public API):** `ValidatorContext` gains `on_behalf_of`. Additive;
  consumers that ignore the new field are unaffected. The field's shape is the
  same delegation-chain dict defined under FR-26 / Plan 010.
- **FR-13 (validators):** validators may now depend on the acting actor's
  delegation chain, provided transactionally-consistent with the transition,
  zero-cost when no validator is registered (inherited from Plan 020 §2.2).
- **§19.5 (error codes):** no change. Chain validation still runs through the
  existing `DELEGATION_CHAIN_*` codes from Plan 010.
- **Migrations:** none. No schema change; the chain is already on `events` and
  `on_behalf_of` is already a `transition()` parameter.

## 4. Security considerations

| Threat | Mitigation |
|---|---|
| Validator sees stale/inconsistent `on_behalf_of` | The value is the in-scope local `on_behalf_of` parameter, not a read from elsewhere; it is the same value the emitted event will carry. No consistency window. |
| `on_behalf_of` is caller-attested at the API boundary | Unchanged from today: `on_behalf_of` is already a `transition()` parameter, validated for shape by `_validate_delegation_chain`. In-process, the library trusts the caller (the host app resolves it server-side). The sidecar (Plan 005) maps it from the bearer token. Asymmetric signing (Plan 011) is the deeper fix for caller attestation; this plan does not weaken the existing model. |
| `on_behalf_of` is `dict`, not frozen — can the validator mutate it? | **Mitigated by shallow-copy at the boundary.** Both transition implementations pass `dict(on_behalf_of) if on_behalf_of is not None else None` into `ValidatorContext`, so a validator that rewrites `ctx.on_behalf_of["principal_id"] = "..."` cannot influence the chain that the appended event records and signs — that uses the original local. Matches the existing `payload` precedent (`_events.py` shallow-copies `dict(payload.value)` before the append; `_in_memory_transition.py` shallow-copies `dict(payload)`). Nested mutation (e.g. `ctx.on_behalf_of["scope"].append(...)`) is not blocked by the shallow copy; it is the same residual risk as nested mutation of `payload` / `custom_fields` / `actor_metadata`, and is tracked separately if it becomes a pattern. Validators remain trusted in-process code per BC-192; this is defense-in-depth, not the trust boundary. |
| Cross-backend divergence on the new field | Both backends thread the same local parameter; the property-based conformance suite (extended under Plan 020) is extended to assert equality of `on_behalf_of` across backends for validator-bearing transitions. |

## 5. Conformance and backward compatibility

- The in-memory and Postgres backends populate `on_behalf_of` identically.
  Coverage is the **manual** cross-backend conformance test
  `TestConformanceAcrossBackends.test_actor_kind_prior_events_on_behalf_of_equal`
  in `tests/test_validator_context_enrichment.py`, which asserts equality of
  `on_behalf_of` (alongside `actor_kind` and `prior_events`) across backends for
  a validator-bearing transition. The hypothesis property-based conformance
  suite (`tests/test_property_conformance.py`) does **not** exercise validator
  context — its workflow has no validators and its `_exec_op`/`_compare_state`
  helpers do not register a recording validator. Extending the property suite
  to cover validator context (filed as a follow-up breadcrumb, applies to both
  Plan 020 and Plan 021) is the clean remedy; this plan ships with the manual
  conformance test only.
- `ValidatorContext` is constructed only by regista internals and via
  `from_dict`. Adding a field with a default is non-breaking for any consumer
  that constructs the context (there are none outside regista internals — see
  Plan 020 §5).
- `from_dict` tolerates the field's absence for forward compatibility with
  contexts serialized by older code (see 2.3).

## 6. Implementation steps

1. `_types.py`: add `on_behalf_of: dict | None = None` to `ValidatorContext`
   (placed after `prior_events`); extend `to_dict()` to emit it when not `None`
   and `from_dict()` to read it with a `None` default.
2. `_transition.py`: in the `ValidatorContext(...)` constructor call inside the
   registered-validator branch, pass `on_behalf_of=on_behalf_of`.
3. `_in_memory_transition.py`: same threading in the same branch.
4. Tests (`tests/test_validator_context_enrichment.py` — extend the existing
   Plan 020 file, since this is the same surface):
   (a) a registered validator observes the `on_behalf_of` dict passed to
       `transition()` for both backends;
   (b) a transition with `on_behalf_of=None` (the common case) yields
       `ctx.on_behalf_of is None`;
   (c) a transition with no registered validator performs no extra work
       (inherited from Plan 020; assert behavior unchanged);
   (d) conformance equality across backends for a delegation-bearing
       validator-bearing transition — covered by extending the manual
       `TestConformanceAcrossBackends` class (the property-based suite does
       not currently exercise validator context — see §5);
   (e) `from_dict` tolerance of a payload lacking `on_behalf_of` (decodes to
       `None`) and round-trip equality when it is present;
   (f) a realistic separation-of-duties scenario: reviewer's
       `on_behalf_of={"principal_id": A}` is rejected by a validator when `A`
       is in the prior-events author set (the dossier WI-004 case, demonstrated
       on both backends);
   (g) **forge-via-mutation defense**: a validator that mutates
       `ctx.on_behalf_of["principal_id"]` cannot influence the chain recorded
       on the appended event (verified on both backends).
5. Extend `CHANGELOG.md` under an Unreleased entry (alongside Plan 020's).
6. `ruff check src/ tests/` and the full suite `pytest tests/`.

## 7. What this plan does NOT cover

| Topic | Reason |
|---|---|
| Asymmetric / cryptographic binding of the delegation chain | Out of scope; BC-196 / Plan 011 / Plan 019 cover the trust model. This plan threads an already-existing field. |
| The dossier `adversarial_review` validator itself | That is dossier WI-004; it consumes this plan's field. |
| Freezing the `on_behalf_of` dict at the boundary | See §4 — same posture as `payload`/`custom_fields`/`actor_metadata`; not introduced here. |
| Adding `on_behalf_of` to `HookContext` | Out of scope; hooks are async post-transition and have a different surface. File a follow-up if a consumer needs it. |

## 8. Risks

| Risk | Mitigation |
|---|---|
| Breaking a downstream consumer that constructs `ValidatorContext` | Consumers receive the context; they do not construct it (Plan 020 §5 audit). `from_dict` is the only external re-constructor and it is tolerant. |
| Conformance drift between backends on the new field | Covered by extending the property-based conformance suite (step 6d). |
| Future schema change to the delegation chain dict breaks the round-trip | The dict is opaque to regista; `_validate_delegation_chain` already gates shape at the API boundary. Round-trip preserves whatever the caller supplied. |
