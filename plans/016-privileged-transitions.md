# Plan 016 — Privileged Transitions

**Status:** Draft RFC
**Owner:** plm
**Origin:** BC-005 (agent-provenance) — scope attestation structurally indistinct from tool events
**Spec touched:** §17 (event envelope), §19 (public API), FR-11 (transition validation)
**Related:** Plan 010 (delegation chain), Plan 011 (pluggable signing), BC-196 (asymmetric signing)

## 1. Problem Statement

Consumers like cairn (agent-provenance) record privileged audit artifacts — scope attestations, session boundaries, degradation markers — that must be structurally distinguishable from ordinary domain events. Today, the only way to emit a state-changing event with a consumer-defined transition name is via `transition()`, which requires the transition to be defined in the workflow YAML and enforces role-gating and state-machine semantics.

Faced with this, cairn's `attest_scope()` (adapter.py:144-172) reuses `tool_call_begin`/`tool_call_end` transitions and identifies attestations by payload inspection (`"harnesses" in payload and "scope_statement" in payload`). This has two consequences:

1. **Operator injectability.** An operator who controls the event log can inject a second scope attestation using normal tool-call transitions with a crafted payload, and the verifier will surface it as legitimate.
2. **Deletion indistinguishability.** A scope attestation deleted from an export bundle is indistinguishable from a normal tool-call event deletion.

The verifier (verifier.py:274-290) identifies attestations by duck-typed payload key presence — a heuristic that depends on no other event accidentally carrying both `harnesses` and `scope_statement` keys.

### Why not just add a workflow-defined transition?

Cairn could define a `scope_attestation` transition in its workflow YAML and use it via `transition()`. This addresses the structural-distinctness problem but not the injectability problem: any actor with the right role can still emit a `scope_attestation` transition by calling `transition()` with a crafted payload.

What cairn needs is a transition name that:
- Is **structurally distinct** (different `transition` field in the event)
- Is **non-injectable** by domain actors (agents, humans) — only system-level code can emit it
- Carries the **same integrity guarantees** as any other signed event (HMAC or Ed25519)
- Participates in the **normal state machine** (advances the work-item's state)

## 2. Proposed Design

### 2.1 `privileged: true` flag on workflow transitions

Add an optional `privileged: boolean` field to transition definitions in the workflow YAML. When `true`, the transition can only be emitted by actors with `actor_kind: "system"`.

```yaml
transitions:
  - name: scope_attestation
    from: new
    to: attested
    privileged: true

  - name: tool_call_begin
    from: new
    to: running
    allowed_roles: [agent]
```

The flag is purely additive: existing workflows without `privileged` transitions are unaffected. The default is `false`.

### 2.2 Enforcement

In `_contract.py`, extend `resolve_transition()` to accept an `actor_kind` parameter. When a transition is marked `privileged`, reject unless `actor_kind == "system"`:

```python
def resolve_transition(transitions, current_state, transition_name, actor_kind, ...):
    for t in transitions:
        if t["name"] == transition_name and t["from_state"] == current_state:
            if t.get("privileged") and actor_kind != "system":
                raise RegistaError(
                    ErrorCode.PRIVILEGED_TRANSITION_REQUIRED,
                    f"Transition {transition_name!r} requires actor_kind='system'",
                )
            return t
    raise RegistaError(ErrorCode.INVALID_TRANSITION, ...)
```

The error code `PRIVILEGED_TRANSITION_REQUIRED` is new and distinct from `ROLE_NOT_PERMITTED` — an auditor seeing this code knows the event was rejected specifically because a non-system actor attempted a privileged transition.

### 2.3 `append_event()` interaction

Privileged transitions are **workflow-defined transitions** and therefore blocked from `append_event()` by the existing `check_append_blocked()` logic (no change needed). They must be emitted via `transition()` with `actor_kind="system"`.

### 2.4 TransitionDef update

```python
@dataclass(frozen=True)
class TransitionDef:
    name: str
    from_state: str
    to_state: str
    allowed_roles: list[str]
    validator: str | None
    hooks: list[str]
    privileged: bool = False
```

### 2.5 JSON Schema update

Add to `_workflow_schema.json` under the transition definition:

```json
"privileged": {
  "type": "boolean",
  "default": false
}
```

### 2.6 Semantic validation

No new semantic constraints. A `privileged` transition can have `allowed_roles` (both are checked), but in practice privileged transitions will typically have empty `allowed_roles` since the `actor_kind` check is the gating mechanism.

## 3. Spec Impact

- **FR-11** (transition validation): extended to check `privileged` flag against `actor_kind`.
- **§17** (event envelope): no change. The event shape is the same; the difference is in emission authorization.
- **§19** (public API): no new methods. The existing `transition()` method gains the behavior that `actor_kind="system"` is required for privileged transitions. This is consistent with the current API which already accepts `actor_kind` as a parameter.
- **§19.5** (error codes): add `PRIVILEGED_TRANSITION_REQUIRED`.

## 4. Cairn Integration

After this lands, cairn's workflow definition adds:

```yaml
states:
  - name: new
  - name: attested
    terminal: true

transitions:
  - name: scope_attestation
    from: new
    to: attested
    privileged: true
```

Cairn's `attest_scope()` is updated to:

1. Create a work item with a dedicated `scope_attestation` work-item type.
2. Call `transition()` with `transition_name='scope_attestation'`, `actor_kind='system'`, and the attestation payload.
3. The verifier identifies attestations by `transition == 'scope_attestation'` — no payload inspection needed.

This closes BC-005 (agent-provenance).

## 5. Security Considerations

| Threat | Mitigation |
|---|---|
| Agent actor emits privileged transition | Rejected by `actor_kind` check in `resolve_transition()` |
| Operator forges event with `transition='scope_attestation'` directly in DB | HMAC/Ed25519 signature covers `transition` field; forgery requires key material (same threat model as any event forgery) |
| Operator creates a second workflow without `privileged: true` | Cairn's verifier checks that the workflow definition contains the privileged transition; a modified workflow changes the `content_hash` which is pinned at session start (BC-006) |
| `actor_kind` is self-attested in the API call | True — `actor_kind` is caller-supplied. In-process, this is a trust boundary (the library trusts the caller). With the sidecar (Plan 005), `actor_kind` can be mapped from the bearer token, making it server-controlled. Full resolution requires asymmetric signing (Plan 011) + strict roles (Plan 008 WS-1). |

The privileged flag is a **structural distinguisher**, not a cryptographic guarantee. It raises the bar from "inject by including the right payload keys" to "inject by calling `transition()` with `actor_kind='system'` from in-process code." For the current trust model (single-operator, in-process library), this is the right granularity. The asymmetric-signing track (Plan 011 + Plan 015) addresses the deeper operator-forgery threat.

## 6. Implementation Steps

1. Add `privileged: boolean` to `_workflow_schema.json` (default `false`).
2. Add `privileged: bool = False` to `TransitionDef` in `_types.py`.
3. Wire `privileged` through `_workflow.py:build_definition()` (parse from YAML).
4. Add `ErrorCode.PRIVILEGED_TRANSITION_REQUIRED` to `_errors.py`.
5. Extend `resolve_transition()` in `_contract.py` to check `actor_kind` for privileged transitions.
6. Update InMemory `resolve_transition` in `_in_memory_transition.py` / `_contract.py` to match.
7. Add `privileged` to the hypothesis property-based tests in `test_property_conformance.py`.
8. Tests: privileged transition succeeds with `actor_kind='system'`, fails with `actor_kind='agent'` or `actor_kind='human'`. Non-privileged transitions unaffected.

## 7. What This Plan Does NOT Cover

| Topic | Reason |
|---|---|
| Cryptographic enforcement of `actor_kind` | Requires asymmetric signing (Plan 011) + bearer-token identity (Plan 005) |
| Per-actor transition allowlists beyond role gating | Out of scope; FR-24 + `strict_roles` (Plan 008 WS-1) address this |
| Workflow-level event type taxonomy | The `transition` name IS the type taxonomy. No additional classification layer is needed. |
| Dedicated `emit_privileged()` API method | Not needed — `transition()` already accepts `actor_kind`. Adding a separate method would be syntactic sugar that obscures the authorization model. |

## 8. Risks

| Risk | Mitigation |
|---|---|
| `actor_kind='system'` is caller-attested, not cryptographically proven | Acknowledged. This plan is a structural distinguisher, not a cryptographic one. The trust model matches the current in-process architecture. |
| Workflow authors mark too many transitions as `privileged` | Low risk. The flag is restrictive (blocks agent and human actors). Workflow authors will use it for genuinely privileged operations. |
| Breaking change for existing callers passing `actor_kind='system'` | No break. Existing transitions without `privileged` don't check `actor_kind`. New `privileged` transitions only reject non-system actors. |
