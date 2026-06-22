# Plan 020 — Validator context enrichment (acting actor_kind + prior events)

**Status:** Draft RFC. Proposed 2026-06-22. Not started.
**Owner:** dossier player-coach
**Origin:** dossier `plans/005-adversarial-review.md` — the `adversarial_review`
sync validator must derive the work's author set from the event log and must know
the acting reviewer's `actor_kind`, but `ValidatorContext` exposes neither.
**Spec touched:** §19 (public API — `ValidatorContext` shape), FR-13 (validators)
**Related:** Plan 005 (HTTP sidecar), Plan 008 (trust hardening), Plan 016
(privileged transitions — another `actor_kind`-aware transition gate)

## 1. Problem statement

A sync validator (`register_validator`) receives a `ValidatorContext` and runs
inside the transition transaction. Today the context carries: `work_item_id`,
workflow refs, `current_state`/`new_state`, `transition_name`, `payload`,
`custom_fields`, `actor_id`, and `actor_metadata`.

Two things a non-trivial validator needs are **absent**:

1. **The acting actor's `actor_kind`.** The transition machinery has it (it is a
   parameter of `transition()`/`in_memory_transition()`), but it is not placed
   on the context. A validator that must distinguish a human reviewer from an
   agent reviewer (dossier Plan 005: "agent-authored work requires a human
   adversary") cannot do so from `actor_metadata` alone without an app-level
   convention, which is fragile and unenforceable.

2. **The work-item's prior event history.** A validator that must reason about
   *who authored this work* (dossier Plan 005: reject self-review) needs the set
   of prior actors and their kinds. That information lives in the event log,
   which is exactly the trustworthy record regista maintains — but the validator
   has no accessor for it. The handler signature is `Callable[[ValidatorContext],
   None]` with no connection or store handle, so an app cannot read the log from
   inside the validator without re-entering the database on a second connection
   (racy and incorrect mid-transaction).

Faced with this, a consumer today must either (a) pre-compute authorship in the
app layer *before* calling `transition()` and pass it via `payload` — which moves
the gate's trust root out of regista's transaction and into the caller, weakening
the guarantee — or (b) forgo history-aware validators entirely. Neither is
acceptable for a provenance instrument whose whole claim is that the workflow
enforces review structurally.

### Why this is generally useful, not dossier-specific

Any consumer that encodes a separation-of-duties or actor-kind policy as a
structural gate needs the same two facts. agent-provenance (cairn) attestation
validators, and any future "N-eyes" or "distinct-actor" gate, are the same shape.
This is a missing primitive on a public type, not a dossier feature.

## 2. Proposed design

### 2.1 Extend `ValidatorContext`

Add two fields to the frozen dataclass in `_types.py`:

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
    actor_kind: str                        # NEW: kind of the acting actor
    prior_events: tuple[Event, ...]        # NEW: work-item history, ascending event_seq
```

- `actor_kind` is the kind of the actor performing *this* transition
  (`"agent"` | `"human"` | `"system"`), identical to the value passed to
  `transition()`. It is the authoritative kind, not a metadata convention.
- `prior_events` is the work-item's complete event history **prior to** this
  transition, in ascending `event_seq`, as full `Event` objects (carrying each
  event's own `actor_id`, `actor_kind`, `on_behalf_of`, `transition`,
  `payload`, `timestamp`). This is everything a validator needs to compute
  authorship, recency, and actor-kind mix without a separate read path.

### 2.2 Population (zero-cost when no validator is registered)

Both transition implementations already branch on
`if validator_name: handler = validators.get(...)`. The history fetch happens
**only inside that branch**, so transitions with no validator (the common case)
pay nothing. The fetch runs on the transition's own connection / store handle,
under the same `SELECT FOR UPDATE` lock, so the view is transactionally
consistent with the row being transitioned.

**Postgres** (`_transition.py`):

```python
from ._events import read_events_by_work_item

_VALIDATOR_HISTORY_LIMIT = 100_000  # per-work-item cap; review logs are bounded

...
prior = tuple(read_events_by_work_item(
    conn, work_item_id, limit=_VALIDATOR_HISTORY_LIMIT,
))
ctx = ValidatorContext(
    ...,
    actor_id=actor_id,
    actor_metadata=actor_metadata,
    actor_kind=actor_kind,          # NEW
    prior_events=prior,             # NEW
)
```

**In-memory** (`_in_memory_transition.py`):

```python
prior = tuple(
    sorted(store.events.get(work_item_id, []), key=lambda e: e.event_seq,
)[-VALIDATOR_HISTORY_LIMIT:])
ctx = ValidatorContext(
    ...,
    actor_id=actor_id,
    actor_metadata=actor_metadata,
    actor_kind=actor_kind,          # NEW
    prior_events=prior,             # NEW
)
```

The sort is defensive and makes the in-memory path produce the identical
most-recent-N-ascending semantics as the Postgres path; the in-memory store
appends in `event_seq` order in practice, but both backends apply the same
`VALIDATOR_HISTORY_LIMIT` cap and ordering so the conformance contract holds.

Both backends populate identically — the property-based conformance suite
already equates the two; the new fields are inputs to it.

### 2.3 Serialization round-trip

`ValidatorContext.to_dict()` / `from_dict()` (used by the sidecar and by
hook/validator marshalling) are extended to round-trip both fields. `Event`
already has `to_dict()`/`from_dict()`, so `prior_events` serializes as a list of
event dicts. `from_dict` is tolerant of missing keys for forward-compatibility
with contexts serialized before this plan (older sidecar payloads): a missing
`actor_kind` decodes to `"agent"` (regista's historical default) and a missing
`prior_events` decodes to `()`.

### 2.4 The history cap

`_VALIDATOR_HISTORY_LIMIT` bounds the worst case for a work-item with an
pathologically long log. It is large enough (100k events) that any realistic
review-gated item is unaffected, and the cap is documented on the field. A
work-item exceeding it is already an operational anomaly. The cap is not a
correctness bound on author-derivation; it is a resource guard.

## 3. Spec impact

- **§19 (public API):** `ValidatorContext` gains `actor_kind` and
  `prior_events`. Additive; consumers that ignore the new fields are unaffected.
- **FR-13 (validators):** validators may now depend on the acting `actor_kind`
  and on prior history. State that both are provided transactionally-consistent
  with the transition and are zero-cost when no validator is registered.
- **§19.5 (error codes):** no change.
- **Migrations:** none. No schema change; the history is read from the existing
  `events` table / in-memory store.

## 4. Security considerations

| Threat | Mitigation |
|---|---|
| Validator reads stale/inconsistent history | Fetch is on the transition's own connection under `SELECT FOR UPDATE`; the work-item row is locked, so the history is consistent with the transition. |
| `actor_kind` is caller-attested at the API boundary | Unchanged from today: `actor_kind` is a `transition()` parameter. In-process, the library trusts the caller (the host app resolves it server-side — see dossier Plan 002). The sidecar (Plan 005) maps it from the bearer token. Asymmetric signing (Plan 011) is the deeper fix; this plan does not weaken the existing model. |
| Prior events expose data the validator shouldn't see | The validator is trusted code (BC-192 contract). It already sees `custom_fields` and `payload`. Prior events are the same work-item's own log — same trust scope. |
| A huge history stalls the transition | The history fetch is bounded by `_VALIDATOR_HISTORY_LIMIT` and the surrounding `statement_timeout = 5s` (already set by the transition impl). A validator that loops over 100k events is itself the risk; that is the consumer's responsibility per the trusted-code contract. |

## 5. Conformance and backward compatibility

- The in-memory and Postgres backends must populate `actor_kind` and
  `prior_events` identically. The hypothesis property-based conformance suite
  (`tests/test_property_conformance.py`) is extended to assert equality of both
  fields across backends for transitions that carry a validator.
- `ValidatorContext` is constructed only by regista internals and via
  `from_dict`. Adding required fields is therefore safe for consumers (validators
  receive the context; they do not construct it). Any regista-internal or
  test-side constructor is updated by this plan.
- `from_dict` tolerates the fields' absence for forward compatibility with
  contexts serialized by older code (see 2.3).

## 6. Implementation steps

1. `_types.py`: add `actor_kind: str` and `prior_events: tuple[Event, ...]` to
   `ValidatorContext`; extend `to_dict()`/`from_dict()` (tolerant `from_dict`).
2. `_transition.py`: in the registered-validator branch, fetch
   `read_events_by_work_item(conn, work_item_id, limit=_VALIDATOR_HISTORY_LIMIT)`
   and pass `actor_kind` + `prior_events` on the context. Define the cap as a
   module-level constant.
3. `_in_memory_transition.py`: in the registered-validator branch, set
   `prior_events=tuple(store.events.get(work_item_id, []))` and pass
   `actor_kind`.
4. Run `from_dict`/`to_dict` round-trip and the sidecar validator path if any.
5. Tests: (a) a registered validator observes the correct `actor_kind` for
   human/agent/system callers; (b) `prior_events` equals the work-item's
   pre-transition history in order, on **both** backends; (c) a transition with
   no registered validator performs no history read (assert via a validator
   counter or by observing unchanged behavior); (d) conformance equality across
   backends for a validator-bearing transition; (e) `from_dict` tolerance of a
   payload lacking the new keys.
6. Extend `CHANGELOG.md` under an Unreleased entry.
7. `ruff check src/ tests/` and the full suite `pytest tests/`.

## 7. What this plan does NOT cover

| Topic | Reason |
|---|---|
| A generic "event read" accessor/handle passed to validators | Out of scope; `prior_events` gives the full pre-transition history, which covers author-derivation and recency. A live-query accessor would invite validators to do unbounded I/O mid-transaction. |
| Enforcing that validators do not mutate `prior_events` | `Event` and `ValidatorContext` are frozen; mutation is already impossible by construction. |
| Per-actor `actor_kind` provenance beyond the caller-attested value | Requires asymmetric signing (Plan 011) + strict roles (Plan 008). This plan does not alter the trust model. |
| Dossier's `adversarial_review` validator itself | That is dossier Plan 005 WI-1; it consumes this plan's fields. |

## 8. Risks

| Risk | Mitigation |
|---|---|
| Breaking a downstream consumer that constructs `ValidatorContext` | Consumers receive the context; they do not construct it. `from_dict` is the only external re-constructor and it is tolerant. Audited: no public docs show constructing `ValidatorContext` by hand. |
| History fetch adds latency to review transitions | Bounded by the cap and `statement_timeout`; review transitions are low-frequency. Zero cost on non-validator transitions. |
| Conformance drift between backends on the new fields | Covered by extending the property-based conformance suite (step 5d). |
