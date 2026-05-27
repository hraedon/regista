# Plan 004 — YAML Workflow Composition (`!include` / inheritance)

Status: Proposed — proceed conditionally (see Motivation).
Spec anchor: spec.md L67, L337, L437, L493, L518 ("Loader can grow `!include` / merge conventions later without breaking existing files").
Loader code: `/projects/regista/src/regista/_workflow.py` (parse and validate); schema `/projects/regista/src/regista/_workflow_schema.json`.

## 1. Motivation — duplication audit of sf2 workflow files

Audit target: `/projects/software-factory-2/workflows/` (6 YAML files, 1,371 lines total).

Concrete findings:

- `phase2.yaml` and `phase3.yaml` are **byte-identical except the `version:` integer** (`diff` returns a single line: `version: 2` vs `version: 3`). 192 lines duplicated wholesale.
- `phase3.yaml` → `phase4.yaml` diff: adds 2 roles (`cross_family_reviewer`, `frontier_judge`) to 5 transition `allowed_roles` blocks, adds the 2 role declarations, adds 1 new `work_item_type` (`review`, ~76 lines). The other 192 lines are unchanged.
- `phase4.yaml` → `phase5.yaml` diff: adds 2 more roles (`integrator`, `outcome_verifier`) to the same 5 transition `allowed_roles` lists plus role declarations. ~84 lines new, ~286 unchanged.
- `phase1.yaml` (93 lines) shares the same 5 states, the same `interface_spec` work_item_type definition (~30 lines), and 5 of its 8 transitions with phase2+.
- `full_pipeline.yaml` (238 lines) shares states, the `software_factory` name, and the same transition skeleton.

Quantified: the `states:` block (5 states, ~12 lines) is duplicated **6 times**. The `interface_spec` work_item_type custom_fields block (~30 lines) appears **6 times**. The transition skeleton (`claim`/`submit`/`cannot_proceed`/`release`/`channel_fail`/`gate_pass`/`gate_fail`/`gate_escalation`) recurs in every file with only `allowed_roles` lists drifting. Roughly **800 of 1,371 lines (~58%) are mechanical duplication**.

Verdict: **YES, real duplication, pull forward.** This is not speculative — every new phase has copy-pasted the previous file and tweaked `version:` plus a role list. The drift cost is already visible (e.g., phase2/phase3 identical except version → strong evidence the workflow shape is stable and inheritance is the natural model).

## 2. Composition model — recommendation

**Recommended: top-level `extends:` field with single-base inheritance and explicit deep-merge semantics.** Not `!include`, not anchors, not `$ref`.

Rationale:

- **`!include` (custom YAML tag).** Inline file substitution. Powerful but unstructured: lets users splice anywhere, breaks JSON Schema validation of fragments, and forces a custom YAML loader (loses `yaml.safe_load` guarantees). Hard to error-report.
- **YAML anchors/aliases across files.** YAML spec scopes anchors to a single document. Cross-file aliases require a non-standard loader. Tooling (editors, linters) won't understand them. Rejected.
- **JSON Schema `$ref`.** Designed for schema composition, not data composition. Users would have to learn JSON Pointer syntax. Heavier than needed.
- **`extends: <path>`.** Plain YAML, no custom tags, schema-friendly (just an optional string field), one base file per child, override semantics specified in one place. Matches the observed sf2 pattern: each phase *is* the previous phase plus a delta.

Merge semantics (specified, not inferred):

- **Maps:** deep merge. Child keys override parent keys at the same path. (e.g., `attempt_threshold: 5` in child overrides parent's `3`.)
- **Top-level scalar fields (`name`, `version`, `regista_version`):** child wins. `version` MUST be set in the child (it is what distinguishes phase3 from phase2).
- **Lists of named objects** (`states`, `transitions`, `roles`, `work_item_types`, `link_types`): keyed merge by `name` (for transitions: `(name, from)`). Child entries with a matching key **deep-merge** into the parent entry; child entries with a new key are **appended**; a child entry with key plus `__remove: true` deletes the parent entry.
- **Plain lists** (`allowed_roles`, `enum_values`): default **replace**. Optional `__append: [...]` sibling key for additive cases (the common sf2 pattern: phase4 adds two roles to every transition's `allowed_roles`).

Example (phase4-like child):

```yaml
extends: ./phase3.yaml
version: 4
roles:
  - name: cross_family_reviewer
  - name: frontier_judge
transitions:
  - name: claim
    from: new
    allowed_roles__append: [cross_family_reviewer, frontier_judge]
work_item_types:
  - name: review
    custom_fields: [...]
```

That single file replaces ~286 lines of duplication with ~30.

## 3. Loader changes (`_workflow.py`)

New module `_workflow_compose.py`:

- `resolve_includes(path: Path, *, _seen: frozenset[Path] = frozenset()) -> tuple[dict, list[SourceMap]]` — recursive resolver. Returns merged dict plus a flat `SourceMap` list (`{json_pointer: "/transitions/2/allowed_roles", source_file: "phase3.yaml", source_line: 24}`) for error reporting.
- Path resolution: `extends:` is interpreted **relative to the file containing it**. Reject absolute paths and any path that escapes a configurable `compose_root` (default: directory of the entry file). Defense against `extends: /etc/passwd` and `extends: ../../../`.
- Cycle detection: maintain `_seen` set of canonical `Path.resolve()` paths; raise `WORKFLOW_VALIDATION_FAILED` with the cycle chain on hit.
- Caching: per-invocation `dict[Path, dict]` memo for the parsed-and-resolved form, so a diamond `A extends B, A also extends C extends B` parses B once. Cache is request-scoped, not process-global (avoids stale reads).
- Max include depth: hard cap at 8 (configurable). Prevents pathological chains.
- The merge step uses the rules in §2. Implemented as a pure function `deep_merge(parent: dict, child: dict, *, list_keys: dict[str, str]) -> dict` where `list_keys` declares the keying rule per list (e.g., `transitions` → `(name, from)`).

`parse_file(path)` becomes the composition entry point. `parse_workflow_yaml(raw_str)` keeps current single-document behavior (no composition without a filesystem context). `parse_and_validate(raw_yaml)` keeps current single-doc behavior — callers without files (e.g., string-fed tests, the `_in_memory.register_workflow_yaml` path at `_in_memory.py:251`) cannot use `extends:` and will get a clear error if they try.

## 4. Validation flow

**Post-merge validation only.** Each individual file is **not** required to be a standalone valid workflow — that is the entire point (a child providing only a delta cannot satisfy `required: [states, transitions, roles, work_item_types]`).

Pre-merge, we apply only **lightweight structural checks**: the file must parse as YAML; if it has `extends:`, that field must be a string; `__remove`/`__append` keys are stripped after their semantic action. The full JSON Schema (`_workflow_schema.json`) runs on the **composed** dict.

Schema change required: add optional `extends: { type: string }` to the schema's top-level properties (so a child file with `extends:` is parseable in isolation for tooling). The schema is otherwise unchanged. `additionalProperties: false` remains — that's a feature.

`compute_content_hash` (workflow.py:454) operates on the **composed** WorkflowDefinition, so the hash naturally reflects the effective workflow. The composed YAML is what we store in `raw_yaml` (the `WorkflowDefinition.raw_yaml` field at workflow.py:235) — registration is hermetic and does not depend on the parent file remaining on disk.

## 5. Error reporting

`SourceMap` (from §3) is consulted whenever validation fails. The error message becomes:

```
Schema validation error at transitions.2.allowed_roles: ['unknown_role']
  introduced by: phase4.yaml:24 (via extends chain phase4.yaml -> phase3.yaml -> phase2.yaml)
```

For YAML syntax errors in a parent file, the existing line-info path in `parse_workflow_yaml` (workflow.py:54–58) is wrapped to prepend the file path.

For semantic errors (`_validate_semantics`, workflow.py:75), each error already references a state/transition by name; we add a sidecar lookup against `SourceMap` to attribute it to the introducing file.

## 6. Backward compatibility

A file with no `extends:` field follows the existing code path bit-for-bit. The SourceMap for a single-file workflow trivially attributes everything to that one file. All existing tests (`tests/test_phase2.py`, `tests/test_e2e.py`, etc., which call `register_workflow_file` with existing single-file workflows) pass unchanged. The schema change (adding optional `extends`) is additive; `additionalProperties: false` previously rejected unknown top-level fields, but no existing file uses `extends:`.

`parse_workflow_yaml(raw_str)` and `parse_and_validate(raw_str)` retain single-document semantics. Callers that need composition must use `parse_file(path)` (the existing entry point at workflow.py:252).

## 7. Implementation steps

1. Add `extends: { type: string }` to `_workflow_schema.json`. Run existing tests — must stay green.
2. New module `_workflow_compose.py`: `deep_merge`, `resolve_includes`, `SourceMap`, cycle/depth/path-escape checks. Pure functions, no I/O dependencies beyond `Path.read_text()`.
3. Rewrite `parse_file(path)` (workflow.py:252) to call `resolve_includes` then `validate_and_build`. Keep `parse_and_validate(raw_yaml)` unchanged.
4. Wire `SourceMap` into `validate_json_schema` and `_validate_semantics` for attribution. Add a new `ErrorCode.WORKFLOW_COMPOSE_ERROR` (cycles, depth, path-escape, missing parent file) distinct from `WORKFLOW_VALIDATION_FAILED`.
5. Add `compose_workflow(path) -> str` helper that returns the merged YAML as text (useful for debugging and for the SF2 migration script).
6. Update `validate_yaml(source)` (workflow.py:464) — when given a Path with `extends:`, route through the composer.
7. Migration of sf2 workflows: write a one-shot script `scripts/migrate_workflows.py` in sf2 that takes each `phaseN.yaml`, computes its diff against `phase(N-1).yaml`, and emits a `phaseN.yaml` using `extends:`. Verify `compute_content_hash` matches before and after. **This is sf2 work, not regista work**, but the plan should land both together to prove the design.

## 8. Test approach

- Unit (`tests/test_workflow_compose.py`):
  - simple two-file extends, deep merge of maps
  - keyed list merge: child overrides a transition's `allowed_roles`
  - `__append` on a list field
  - `__remove: true` on a named entry
  - chain depth 3 (A → B → C)
  - diamond (caching correctness)
- Error paths:
  - cycle (A → B → A) raises `WORKFLOW_COMPOSE_ERROR` with cycle chain
  - depth > 8 raises
  - `extends: /absolute/path` raises path-escape
  - `extends: ../../../../etc/passwd` raises path-escape
  - missing parent file raises with parent path in message
  - post-merge schema failure attributes to introducing file (snapshot test on error message)
- Fixture port: copy sf2's `phase2.yaml`→`phase5.yaml` into `tests/fixtures/composition/`, write the `extends:`-based versions, assert `compute_content_hash` byte-equality before/after refactor. This is the load-bearing acceptance test.
- E2E: `tests/test_phase2.py` etc. unchanged. Add one new test that registers a 3-deep composed workflow against a real DB and runs an end-to-end transition.

## 9. Open questions / risks

- **Hash stability across phases:** if sf2 migrates `phase3.yaml` to `extends: ./phase2.yaml`, the *composed* dict must be bytewise identical to the old standalone file. Map key ordering during merge must be deterministic. Mitigation: merge preserves child-then-parent insertion order; verify with content-hash equivalence test.
- **`raw_yaml` semantics in DB:** registration stores the source YAML. Composed-then-stored means the DB record no longer matches the file the operator authored. Decision: store the **composed** YAML in `raw_yaml` and add a new event/column `compose_sources: list[str]` recording the chain. Replay reads composed YAML directly; no re-resolution on read.
- **Tooling impact:** YAML LSP and editors won't follow `extends:`. Acceptable in v1 — provide a `regista workflow show <file>` CLI subcommand that prints the composed form.
- **Override expressiveness:** `__remove` / `__append` are minimal. Risk that users want more (e.g., "remove allowed_role X from every transition"). Out of scope; revisit only if needed.
- **Diamond inheritance:** disallow in v1. If a file's transitive extends graph has the same ancestor reachable two ways, reject. Simpler than specifying merge order.

## 10. Out of scope

- Multi-base inheritance (`extends: [a, b]`)
- Parameterized templates (Jinja-style variable substitution)
- Conditional includes (`extends_if:`)
- Cross-project / URL-based includes (`extends: https://...`)
- `!include` as a YAML tag in any form
- Diamond inheritance with merge-order specification
- Runtime composition (composing at workflow-register time from operator-supplied fragments)
