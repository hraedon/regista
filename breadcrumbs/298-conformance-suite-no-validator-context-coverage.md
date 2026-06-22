---
number: "298"
title: "Property-based conformance suite does not exercise validator context (Plan 020/021 coverage gap)"
severity: low
status: accepted
kind: improvement
author: deepseek-v4-pro adversarial review
date: "2026-06-22"
tags: [testing, conformance, validators, plan-020, plan-021]
related: []
---

## Problem

Plan 020 §5 and Plan 021 §5 both claim that the hypothesis property-based
conformance suite (`tests/test_property_conformance.py`) is extended to assert
equality of validator-context fields (`actor_kind`, `prior_events`,
`on_behalf_of`) across the Postgres and InMemory backends for validator-bearing
transitions. **This extension never happened.**

- `tests/test_workflow.yaml` (the workflow used by the property suite) declares
  **zero validators** on any transition.
- `_exec_op` (`tests/test_property_conformance.py`) calls `backend.transition()`
  but never registers a recording validator.
- `_compare_state` compares work-item state fields but never compares
  `ValidatorContext` fields.

As a result, the only cross-backend conformance coverage for `ValidatorContext`
fields is the manual `TestConformanceAcrossBackends` class in
`tests/test_validator_context_enrichment.py`, which runs a single deterministic
scenario per field. That is adequate coverage for small additive fields, but it
is not what the plan docs claim.

## Impact

- Plan docs are inaccurate about coverage. This was corrected in Plan 021 §5 as
  part of the adversarial review response; Plan 020 §5 still overstates
  coverage and should be amended if revisited.
- The validator-context surface (which is now load-bearing for the dossier
  separation-of-duties gate and similar consumer policies) has thinner
  conformance coverage than the rest of the backend contract.

## Resolution

Accepted as a tracked improvement. Extending the property suite would require:
1. Adding a validator-bearing transition to `test_workflow.yaml`.
2. Threading a recording validator through `_exec_op` (registered on both
   backends before the transition).
3. Extending `_compare_state` to compare the captured `ValidatorContext` fields
   across backends.

Worth doing when the next validator-context field lands or when a consumer
reports a divergence. Until then, the manual `TestConformanceAcrossBackends`
class is the canonical coverage.
