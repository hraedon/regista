---
number: "002"
title: "Workflow composition — when phase2.yaml becomes unmaintainable"
author: opencode
date: "2026-05-09"
related: ["RFC-004", "BC-058"]
---

## Context

Substrate's workflow definitions are single YAML files per workflow version. v2 currently registers:
- `phase1.yaml` — single role (interface_architect)
- `phase2.yaml` — three roles + handoff transitions + gate_escalation

Phase 4 will add jury gates: `frontier_judge_1`, `frontier_judge_2`, `frontier_judge_3`, plus `cross_family_reviewer`, plus race patterns. Phase 5+ may add `coherence_reviewer`, `outcome_verifier`, and integration stages.

The substrate spec §3 explicitly defers workflow file composition (`!include`, anchors across files) as out of scope.

## Problem

`phase2.yaml` is already ~80 lines. By Phase 4, the equivalent YAML could be 200+ lines with:
- 10+ states
- 20+ transitions
- 8+ roles
- 5+ work_item_types
- Per-transition retry overrides
- Custom field declarations per type

A 200-line YAML file with deep nesting is hard for humans to review and impossible for agents to edit without introducing syntax errors. The principal cannot review a 200-line YAML for correctness.

## Position

**Re-evaluate the `!include` deferral before Phase 4. Implement a minimal composition primitive: `include:` list at the top level that merges fragments.**

### Proposed minimal composition

```yaml
name: software_factory
version: 4
substrate_version: "0.1.0"
include:
  - states.yaml          # shared states (new, in_progress, gating, locked, cannot_proceed)
  - roles.yaml           # shared roles (interface_architect, test_author, implementer, ...)
  - transitions_core.yaml # claim, submit, gate_pass, gate_fail, channel_fail
  - transitions_jury.yaml # jury_vote, jury_quorum, jury_disagree
  - work_item_types.yaml # interface_spec, test_suite, implementation, review
```

Rules:
- `include` is processed at load time; the in-memory representation is a single flat workflow
- Later fragments override earlier fragments for the same key (last-wins)
- Circular includes are rejected at parse time
- The composed workflow is validated as a single unit (same JSON Schema)

### Why minimal, not full YAML anchors

YAML anchors (`&states`, `*states`) are powerful but error-prone. Agents already struggle with YAML syntax (v1 BC-022). An explicit `include` list is simpler and reviewable.

### Alternative: keep single files, add linting

If composition is rejected, at minimum add:
- `validate_yaml` already exists (BC-061)
- Add a `workflow lint` mode that checks line count, nesting depth, and transition count against thresholds
- Warn when a workflow exceeds 150 lines or 15 transitions

This doesn't solve the problem but makes the pain visible.

## Risks

| Risk | Mitigation |
|---|---|
| Include resolution adds complexity to substrate | Keep it in `_workflow.py` only; no schema change; no migration |
| Principal cannot review composed workflow | The composed output is always a single YAML; review the composed result, not the fragments |
| Agents editing fragments introduce cross-file drift | CI validates composition; `make check-workflow` fails if fragments don't compose |

## Blocking

Phase 4 (jury and race). Phase 3 can stay with `phase2.yaml`. Phase 4 will likely need new transitions and roles.

## Next step

1. Measure `phase2.yaml` line count and nesting depth
2. Draft a `phase4.yaml` on paper (no code) with estimated states, transitions, roles
3. If the draft exceeds 150 lines, accept this debate and implement `include` primitive
4. If under 150 lines, defer and add linting thresholds instead
