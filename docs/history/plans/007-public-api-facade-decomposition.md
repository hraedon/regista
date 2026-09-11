# Plan 007 — Public API Facade Decomposition

**Status:** Draft RFC
**Owner:** plm
**Prereq for:** multi-tenant deployment (Plan 008)
**Spec touched:** §19 (Public API Surface)

## 1. Problem Statement

`Regista` in `__init__.py` is a 1,200-line God class with 25+ public methods spanning six distinct capability domains:

| Domain | Methods | Extracted internal modules |
|---|---|---|
| Workflow registration | `register_workflow`, `register_workflow_file`, `get_workflow` | `_workflow_api.py` |
| Work-item CRUD | `create_work_item`, `query_work_items`, `update_not_before` | `_work_items_api.py` |
| Events | `append_event`, `read_events` | `_events_api.py` |
| Claims | `acquire_claim`, `heartbeat_claim`, `release_claim`, `sweep_expired_claims` | `_claims_api.py` |
| Transitions | `transition` | `_transition.py` |
| Links | `create_link`, `remove_link` | `_links_api.py` |
| Hooks | `register_validator`, `register_hook_handler`, `start_hook_consumer`, `stop_hook_consumer`, `poll_hooks`, `claim_hooks`, `complete_hook`, `fail_hook`, `sweep_expired_hook_leases`, `list_dead_lettered_hooks`, `requeue_dead_lettered_hook` | `_hooks.py` |
| Recurrence | `register_recurrence_rule`, `list_recurrence_rules`, `due_recurrences`, `fire_recurrence`, `cancel_recurrence_rule`, `update_recurrence_rule` | `_recurrence_api.py` |
| Replay | `replay` | `_replay.py` |
| Lifecycle | `create_project`, `close`, `ensure_event_partitions`, `connection_info` | `__init__.py` |

The internal logic is already extracted. The remaining 1,200 lines are docstrings + thin delegation wrappers. The problem is not performance — it's cognitive surface area. A consumer sees 25+ methods on a single class and must understand which combination of methods constitutes a valid lifecycle. The class violates the Interface Segregation Principle: an actor that only creates work-items sees claim, hook, and recurrence methods it never calls.

### Why this matters now

1. **The sidecar (Plan 005) exposes every method as an HTTP endpoint.** There is no way for a consumer to subscribe to just "work-item operations" — they get the full surface or nothing.
2. **Future trust hardening (Plan 008) will need per-domain policy.** Rate limiting, audit logging, and permission checks are domain-specific. A monolithic class makes per-domain policy invasive to implement.
3. **The CLI (Plan 002) already groups commands by domain.** The CLI's subcommand tree (`work-item`, `events`, `hooks`, `recurrence`, `schema`) implicitly acknowledges that the flat API is not the natural consumption shape.

## 2. Design Options

### (a) Facade sub-objects (Recommended)

Introduce namespaced accessors that return thin facade objects scoped to a domain:

```python
class Regista:
    @property
    def work_items(self) -> WorkItemOps: ...
    @property
    def events(self) -> EventOps: ...
    @property
    def claims(self) -> ClaimOps: ...
    @property
    def hooks(self) -> HookOps: ...
    @property
    def recurrence(self) -> RecurrenceOps: ...
    @property
    def links(self) -> LinkOps: ...
```

Each facade object holds a reference to the shared `ConnectionManager`, `KeySet`, and `Metrics` — exactly what `__init__.py` delegates today. Usage:

```python
sub = Regista(dsn, "my_project", hmac_key_path=...)

wi = sub.work_items.create(workflow_name=..., work_item_type=..., actor_id=...)
sub.claims.acquire(wi.work_item_id, actor_id=...)
sub.transitions.apply(wi.work_item_id, "submit", actor_id=...)
```

The top-level methods remain as deprecated aliases for two minor versions:

```python
def create_work_item(self, **kwargs):
    import warnings
    warnings.warn("Use sub.work_items.create()", DeprecationWarning, stacklevel=2)
    return self.work_items.create(**kwargs)
```

**Pros:** Backward compatible. ISP-compliant. Per-domain facades can carry per-domain policy (rate limits, audit annotations) without polluting the core class.

**Cons:** Two APIs to maintain during deprecation period. Property access creates objects on every call (cheap but not free — can be cached).

### (b) Mixin composition

Split `Regista` into mixins: `WorkItemMixin`, `ClaimMixin`, `HookMixin`, etc. The concrete `Regista` class inherits all mixins.

**Pros:** No API shape change. Consumers call `sub.create_work_item()` as before.

**Cons:** Doesn't reduce cognitive surface area — the consumer still sees 25+ methods. Doesn't help with per-domain policy. Mixins have implicit coupling through `self._mgr`, `self._keys`, etc.

### (c) Separate client classes

Split into independent classes: `WorkflowClient`, `WorkItemClient`, `ClaimClient`, etc. Each is constructed with its own config.

**Pros:** Maximum separation.

**Cons:** Breaks the "single handle" contract in §19. Consumers must manage multiple client lifecycles. Shared state (connection pool, key set) requires a shared context object, which is just a renamed `Regista` class.

## 3. Proposed Design (Option A in detail)

### Facade objects

```python
# src/regista/_ops/work_items.py
class WorkItemOps:
    __slots__ = ("_mgr", "_keys", "_metrics", "_project")

    def create(self, ...) -> tuple[WorkItem, Event]: ...
    def query(self, ...) -> QueryPage[WorkItem]: ...
    def get(self, work_item_id) -> WorkItem | None: ...
    def update_not_before(self, ...) -> Event: ...
```

### Lifecycle methods stay on Regista

`create_project`, `close`, `ensure_event_partitions`, `connection_info`, and `replay` remain on the top-level `Regista` class. They are infrastructure operations, not domain operations.

### Backward compatibility

All 25+ current methods remain on `Regista` with deprecation warnings. Removal targeted for regista 0.3.0 (two minor versions after introduction).

### What about `transition()`?

`transition` spans work-items, claims, hooks, and events. It is the most cross-cutting operation. Two options:

1. **Keep on Regista.** It's the "main loop" operation — claim, validate, transition, dispatch hooks. Conceptually it belongs at the orchestration level.
2. **Put on `TransitionsOps`.** More consistent with the decomposition but creates an awkward dependency (TransitionOps needs ClaimOps + HookOps internals).

Recommendation: keep `transition()` on `Regista` top-level. It is the primary consumer entry point and its cross-domain nature makes it a poor fit for a single facade.

## 4. Migration Path

1. **Phase A (non-breaking):** Add facade properties. Deprecation warnings on old methods. No removal.
2. **Phase B (documentation):** Update README, examples, AGENTS.md to show new API shape.
3. **Phase C (breaking, 0.3.0):** Remove deprecated top-level methods. Keep `transition()`, `replay()`, lifecycle methods.

## 5. Spec Impact

§19 "Public API Surface" must be amended to document the facade pattern. The amendment is additive (new accessors) during Phase A and reductive (removed methods) during Phase C. AC-34 (no Postgres internals leak) is unaffected — facades delegate through the same internal modules.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Deprecation noise in logs | Use `DeprecationWarning` (filtered by default in Python); add opt-in `strict_deprecation` flag |
| Facade object allocation per property access | Cache on first access via `__dict__` or `__slots__` + `_facade_cache` dict |
| Sidecar routes must be updated twice (old + new) | Sidecar already maps 1:1 to public methods; during Phase A, routes point to both old and new |
| Agent cognitive load during transition | Agents read AGENTS.md; update examples to show new shape immediately |
