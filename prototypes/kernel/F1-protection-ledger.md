# F1 Stage A — protection ledger

Stage B is **not yet authorized by this ledger**: the unresolved rows below
are protection gaps, not retirement decisions. No `src/regista/` or `tests/`
file was edited or deleted. The existing 69 checks remain passing.

Primary source: `plans/032-f0-inventory/regression-preservation-map.md`.
Rulings: `plans/032-open-decisions.md`; replay boundary: `7b3607a` and the
public `REPLAY_COVERS` / `REPLAY_DOES_NOT_COVER` constants.

Rechecked baseline `4d2dd48`: YAML/JSON loading, declared work-item types,
workflow version pinning, keyset queries, D6, D7, lease liveness/ownership,
reserved reducer keys, field drift, tail deletion and repeatable-read were
already implemented. Their map descriptions of missing code are stale.
Field-schema validation, typed field refs, link vocabulary/removal, optimistic
sequence checks and streamed replay were still missing. The suite adds those
protections with backward-compatible optional declarations/arguments.

Real defects exposed and repaired:

- All nine write entry points previously wrote through unsupported (999) or
  absent kernel_meta markers. All 18 paired tests failed before the guard.
  A shared admission check now refuses before effects; diagnostic reads remain
  available and initialize retains its explicit fresh-baseline path.
- Nonpositive/nonfinite TTLs either created expired leases reported as live or
  leaked database errors. All 10 paired tests failed before argument validation.
  Tests now manufacture expiry relative to the database clock, not via bad TTLs.
- Missing DSN exited 1 via SystemExit instead of the CLI refusal contract
  of 2. All 14 paired subprocess tests failed before routing it through the
  normal KernelError envelope.
- Connection setup ran outside the CLI error handler, so an unreachable DSN
  escaped as a traceback. Setup now shares the sanitized refusal path; both
  subprocess modes reject the original placement in a scratch copy.

- Request hashing omitted actor kind and role: conflicting reuse returned the
  prior result. Both assertions failed before the fix (not setup failures).
- DISCARD ALL invalidated server prepared statements without invalidating the
  driver cache. Sustained operations logged reset errors and exhausted the
  pool. Automatic preparation is disabled for this discard-on-return pool.
- Malformed YAML/JSON escaped as parser exceptions (CLI traceback). Public
  loading now raises InvalidWorkflowError with a sanitized exception type.
- Replay materialized one item's entire event log. A server-side cursor reduces
  it within one repeatable-read transaction, including projection comparison.
- Retained validation obligations had no implementation: optional per-type
  field_schemas enforce required/unknown/type/enum and typed UUID refs; optional
  link_type_names enforce a closed vocabulary, missing endpoints raise a typed
  refusal, remove_link refuses absent relationships, expected_seq checks the
  locked projection. These are completion of map gaps, not old trust setup.

The authoring format remains version 1. Existing definitions without these
optional declarations serialize/hash identically; old per-type object forms
and link_types remain explicitly refused. Field schemas use a bounded subset
of the existing JSON Schema library: object/properties/required/
additionalProperties; field type/enum/minLength plus work_item_ref target-type
list. No external schema references are accepted. Required transition fields
still mean present and non-null after merge and clear.

`conftest.py` creates unique disposable schemas, then uses only public
Kernel.connect/initialize for kernel bootstrap. Raw SQL is confined to schema
lifecycle, deliberate corruption, database failure/barrier fixtures and relative
lease expiry. Unset REGISTA_TEST_DSN skips with a clear explanation. No fixed
calendar dates determine expiry. All normal writes use the public API.

Stewardship: isolated branch feat/wi364-f1-protection, work item WI-364 as
assigned by the user; working set prototypes/kernel only. The live tracker was
not claimed/updated because the user explicitly excluded the live estate.
External evidence is the gates and scratch-mutation artifacts below; no suite
provenance reference is invented. Independent review by another model family
remains pending, as requested. This is a review handoff, not an acceptance claim.

Inventory corrections: the actual typed-reference module contains **20** tests
(the map says 18), TestCheckIdempotency has more than the map's six assertions,
and §B's 32 bodies cannot survive unchanged against a different public API.
§B below nevertheless accounts for all 35 source test functions exactly.

Rows name assertion replacements, not promises of source/API compatibility.
A class/file citation in the map is expanded to actual source test names below.
Parameterized nodes without a bracket suffix denote the entire test matrix.
Repeated source nodes in §B/§C are separate map obligations, counted as rows.


| Old assertion / map entry | Disposition | New pytest node or reference | Scope / reason | Mutation proof |
| --- | --- | --- | --- | --- |
| `tests/test_bc188_connect_search_path.py::TestConnectSetsSearchPath::test_drop_old_replay_tables_does_not_touch_sibling_schema` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_namespace_isolation` | Scoped operation replacement; rollback and sibling handles use independent namespaces. No legacy replay-table DROP exists. | 1/1 nodes; recipes below |
| `tests/test_bc188_connect_search_path.py::TestConnectSetsSearchPath::test_connect_sets_search_path_session` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_namespace_isolation` | Scoped operation replacement; rollback and sibling handles use independent namespaces. No legacy replay-table DROP exists. | 1/1 nodes; recipes below |
| `tests/test_provision.py::TestProvision::test_provision_creates_schema_and_role` | UNRESOLVED | `UNRESOLVED` | Kernel has no service-role provisioning/dry-run API. D1 alone does not retire these permission assertions. | No replacement claim |
| `tests/test_provision.py::TestProvision::test_provision_idempotent` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_catalog_roundtrip` |  | 1/1 nodes; recipes below |
| `tests/test_provision.py::TestProvision::test_provision_multiple_projects` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_namespace_isolation` |  | 1/1 nodes; recipes below |
| `tests/test_provision.py::TestProvision::test_provision_dry_run` | UNRESOLVED | `UNRESOLVED` | Kernel has no service-role provisioning/dry-run API. D1 alone does not retire these permission assertions. | No replacement claim |
| `tests/test_provision.py::TestProvision::test_provision_cross_schema_denied` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_database_role_is_scoped` | Disposable scoped DB role writes its namespace and is denied sibling reads through the public API. Role provisioning automation itself is not claimed. | 1/1 nodes; recipes below |
| `tests/test_wi246_concurrent_create.py::TestConcurrentCreateProject::test_concurrent_create_project_no_deadlock` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_concurrent_initialize` | Concurrent public initialization serializes per schema; old public.projects bootstrap is replaced by per-schema metadata. The mixed service-role provisioning half remains unresolved above. | 1/1 nodes; recipes below |
| `tests/test_wi246_concurrent_create.py::TestConcurrentCreateProject::test_concurrent_provision_plus_create_project_no_deadlock` | SPLIT | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_concurrent_initialize` | Concurrent kernel initialization is protected. Mixed role-provisioning/create concurrency is unresolved because no kernel provisioning API exists. | 1/1 nodes; recipes below |
| `tests/test_wi246_concurrent_create.py::TestCatalogBootstrapConcurrency::test_ensure_catalog_table_concurrent` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_concurrent_initialize` | Concurrent public initialization serializes per schema; old public.projects bootstrap is replaced by per-schema metadata. The mixed service-role provisioning half remains unresolved above. | 1/1 nodes; recipes below |
| `tests/test_wi243_schema_leak.py::TestDropProjectSchemaUnregistersCatalog::test_drop_removes_catalog_row` | UNRESOLVED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_catalog_roundtrip` | The kernel has no public drop/catalog-unregister operation. test_catalog_roundtrip protects initialization and checks disposable SQL cleanup only; it is not a replacement for the old library cleanup assertion. | No replacement claim |
| `tests/test_wi243_schema_leak.py::TestDropProjectSchemaUnregistersCatalog::test_drop_is_idempotent_and_safe_on_missing_schema` | UNRESOLVED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_catalog_roundtrip` | The kernel has no public drop/catalog-unregister operation. test_catalog_roundtrip protects initialization and checks disposable SQL cleanup only; it is not a replacement for the old library cleanup assertion. | No replacement claim |
| `tests/test_wi243_schema_leak.py::TestCreateProjectRegistersCatalog::test_create_registers_and_drop_cleans` | UNRESOLVED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_catalog_roundtrip` | The kernel has no public drop/catalog-unregister operation. test_catalog_roundtrip protects initialization and checks disposable SQL cleanup only; it is not a replacement for the old library cleanup assertion. | No replacement claim |
| `tests/test_wi243_schema_leak.py::TestCatalogRowCountStableAcrossCreateDrop::test_create_drop_roundtrip_leaves_no_net_growth` | UNRESOLVED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_catalog_roundtrip` | The kernel has no public drop/catalog-unregister operation. test_catalog_roundtrip protects initialization and checks disposable SQL cleanup only; it is not a replacement for the old library cleanup assertion. | No replacement claim |
| `tests/test_wi243_schema_leak.py::test_fixture_pattern_leaves_no_schema` | UNRESOLVED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_catalog_roundtrip` | The kernel has no public drop/catalog-unregister operation. test_catalog_roundtrip protects initialization and checks disposable SQL cleanup only; it is not a replacement for the old library cleanup assertion. | No replacement claim |
| `tests/test_validate_yaml.py::TestValidateYamlValid::test_valid_yaml_from_string` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_load_roundtrip[yaml]` | Public file/document front door; valid results are empty tuples of problems, not v6 ValidationResult serialization. | 0/1 nodes; recipes below |
| `tests/test_validate_yaml.py::TestValidateYamlValid::test_valid_yaml_from_path` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_load_roundtrip[yaml]` | Public file/document front door; valid results are empty tuples of problems, not v6 ValidationResult serialization. | 0/1 nodes; recipes below |
| `tests/test_validate_yaml.py::TestValidateYamlValid::test_valid_yaml_from_path_string_is_content` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_load_roundtrip[yaml]` | Public file/document front door; valid results are empty tuples of problems, not v6 ValidationResult serialization. | 0/1 nodes; recipes below |
| `tests/test_validate_yaml.py::TestValidateYamlInvalidYaml::test_invalid_yaml_syntax` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_load_refusals[syntax]` | Public file/document front door; valid results are empty tuples of problems, not v6 ValidationResult serialization. | 1/1 nodes; recipes below |
| `tests/test_validate_yaml.py::TestValidateYamlSchemaErrors::test_missing_name` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[name]` | Public file/document front door; valid results are empty tuples of problems, not v6 ValidationResult serialization. | 1/1 nodes; recipes below |
| `tests/test_validate_yaml.py::TestValidateYamlSchemaErrors::test_missing_states` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[states]` | Public file/document front door; valid results are empty tuples of problems, not v6 ValidationResult serialization. | 1/1 nodes; recipes below |
| `tests/test_validate_yaml.py::TestValidateYamlSemanticErrors::test_unreachable_state` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[unreachable]` | Public file/document front door; valid results are empty tuples of problems, not v6 ValidationResult serialization. | 1/1 nodes; recipes below |
| `tests/test_validate_yaml.py::TestValidateYamlSemanticErrors::test_undeclared_role_in_transition` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[undeclared_role]` | Public file/document front door; valid results are empty tuples of problems, not v6 ValidationResult serialization. | 1/1 nodes; recipes below |
| `tests/test_validate_yaml.py::TestValidateYamlResultShape::test_validation_result_to_dict` | UNRESOLVED | `UNRESOLVED` | No validation-result serializer exists. Document/workflow round trips and CLI validation are covered, but do not preserve the old serialized result shape. | No replacement claim |
| `tests/test_validate_yaml.py::TestValidateYamlResultShape::test_invalid_result_to_dict` | UNRESOLVED | `UNRESOLVED` | CLI malformed-document refusal is covered; its envelope does not preserve the old ValidationResult error list/omitted workflow assertion. | No replacement claim |
| `tests/test_validate_yaml.py::TestValidateYamlResultShape::test_roundtrip_from_dict` | UNRESOLVED | `UNRESOLVED` | Workflow round trips are covered, but the old validation-result deserializer has no counterpart or explicit retirement ruling. | No replacement claim |
| `tests/test_version_pinning.py::TestAC12PinnedVersionIsolation::test_v1_work_item_rejects_v2_only_transition` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_version_pinning` |  | 1/1 nodes; recipes below |
| `tests/test_version_pinning.py::TestAC12PinnedVersionIsolation::test_v2_work_item_accepts_shortcut` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_version_pinning` |  | 1/1 nodes; recipes below |
| `tests/test_version_pinning.py::TestAC12PinnedVersionIsolation::test_v1_work_item_uses_v1_transitions` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_version_pinning` |  | 1/1 nodes; recipes below |
| `tests/test_sf2_workflows.py::TestSF2WorkflowRoundtripV1::test_phase1_interface_spec_lifecycle` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_full_repair_handoff` | Same multi-actor lifecycle and repair/review intent; fixture is generic review, with public document loading independently covered. | 1/1 nodes; recipes below |
| `tests/test_sf2_workflows.py::TestSF2WorkflowRoundtripV1::test_phase1_create_missing_required_field_rejected` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[required-create]` |  | 1/1 nodes; recipes below |
| `tests/test_sf2_workflows.py::TestSF2WorkflowRoundtripV1::test_role_gating_rejects_unauthorized` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_transition_refusals[role]` |  | 1/1 nodes; recipes below |
| `tests/test_sf2_workflows.py::TestSF2WorkflowRoundtripV1::test_attempt_threshold_drives_escalation` | UNRESOLVED | `WORKFLOW_DOCUMENT_REMOVED_KEYS["document"]["attempt_threshold"]` | Automatic escalation is absent from the extracted API; application uses Claim.attempt. No maintainer retirement ruling is explicit in the map. | No replacement claim |
| `tests/test_sf2_workflows.py::TestSF2WorkflowRoundtripV2::test_both_yamls_register_without_error` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_full_repair_handoff` | Same multi-actor lifecycle and repair/review intent; fixture is generic review, with public document loading independently covered. | 1/1 nodes; recipes below |
| `tests/test_sf2_workflows.py::TestSF2WorkflowRoundtripV2::test_version_pinning_across_v1_v2` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_version_pinning` |  | 1/1 nodes; recipes below |
| `tests/test_sf2_workflows.py::TestSF2WorkflowRoundtripV2::test_full_pipeline_link_types` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_link_vocabulary_and_removal` |  | 1/1 nodes; recipes below |
| `tests/test_smoke.py::TestWorkItem::test_create_work_item` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_create_and_get` |  | 1/1 nodes; recipes below |
| `tests/test_smoke.py::TestWorkItem::test_create_with_invalid_type` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_create_refusals[type]` |  | 1/1 nodes; recipes below |
| `tests/test_smoke.py::TestWorkItem::test_create_with_invalid_field` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[type-create]` |  | 1/1 nodes; recipes below |
| `tests/test_smoke.py::TestTransition::test_valid_transition` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_full_repair_handoff` |  | 1/1 nodes; recipes below |
| `tests/test_smoke.py::TestTransition::test_invalid_transition` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_transition_refusals[wrong_state]` |  | 1/1 nodes; recipes below |
| `tests/test_smoke.py::TestTransition::test_role_not_permitted` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_transition_refusals[role]` |  | 1/1 nodes; recipes below |
| `tests/test_smoke.py::TestTransition::test_full_lifecycle` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_full_repair_handoff` |  | 1/1 nodes; recipes below |
| `tests/test_smoke.py::TestQuery::test_query_by_workflow` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_query_filters_and_liveness` |  | 1/1 nodes; recipes below |
| `tests/test_smoke.py::TestQuery::test_query_by_state` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_query_filters_and_liveness` |  | 1/1 nodes; recipes below |
| `tests/test_smoke.py::TestQuery::test_query_claimable_now` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_query_filters_and_liveness` |  | 1/1 nodes; recipes below |
| `tests/test_smoke.py::TestQuery::test_pagination_stable_no_duplicates` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_query_order_and_paging[all]` |  | 1/1 nodes; recipes below |
| `tests/test_remaining_errors.py::TestWorkItemTypeNotDeclared::test_create_rejects_undeclared_type` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_create_refusals[type]` |  | 1/1 nodes; recipes below |
| `tests/test_remaining_errors.py::TestWorkflowNotRegistered::test_create_rejects_unknown_workflow` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_create_refusals[workflow]` |  | 1/1 nodes; recipes below |
| `tests/test_remaining_errors.py::TestCustomFieldViolation::test_missing_required_field_on_create` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[required-create]` |  | 1/1 nodes; recipes below |
| `tests/test_remaining_errors.py::TestCustomFieldViolation::test_unknown_field_on_create` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[unknown-create]` |  | 1/1 nodes; recipes below |
| `tests/test_remaining_errors.py::TestCustomFieldViolation::test_wrong_type_on_create` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[type-create]` |  | 1/1 nodes; recipes below |
| `tests/test_remaining_errors.py::TestCustomFieldViolation::test_invalid_enum_on_create` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[enum-create]` |  | 1/1 nodes; recipes below |
| `tests/test_remaining_errors.py::TestCustomFieldViolation::test_custom_field_violation_on_transition` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[type-transition]` |  | 1/1 nodes; recipes below |
| `tests/test_remaining_errors.py::TestDbNotFound::test_connect_without_create_rejects` | UNRESOLVED | `UNRESOLVED` | connect() permits an empty destination so initialize() can run. No read-only/open-existing mode currently refuses a missing schema. | No replacement claim |
| `tests/test_stale_heartbeat.py::TestAC07StaleHeartbeat::test_heartbeat_rejects_different_actor` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_refusals[actor]` |  | 1/1 nodes; recipes below |
| `tests/test_stale_heartbeat.py::TestAC07StaleHeartbeat::test_heartbeat_rejects_after_auto_steal` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_refusals[takeover]` |  | 1/1 nodes; recipes below |
| `tests/test_stale_heartbeat.py::TestAC07StaleHeartbeat::test_valid_heartbeat_succeeds` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_extension` |  | 1/1 nodes; recipes below |
| `tests/test_coverage_gaps.py::TestExpectedAttemptNumber::test_heartbeat_rejects_stale_attempt_number` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_refusals[attempt]` |  | 1/1 nodes; recipes below |
| `tests/test_coverage_gaps.py::TestExpectedAttemptNumber::test_heartbeat_accepts_correct_attempt_number` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_extension` |  | 1/1 nodes; recipes below |
| `tests/test_heartbeat_coalesce.py::TestComputeCoalesceThreshold::test_default_returns_max_of_60_and_half_ttl` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Heartbeat emits no events; thresholds, event counts and event payloads retire with that explicit boundary. | Retirement reference |
| `tests/test_heartbeat_coalesce.py::TestComputeCoalesceThreshold::test_override_used_when_provided` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Heartbeat emits no events; thresholds, event counts and event payloads retire with that explicit boundary. | Retirement reference |
| `tests/test_heartbeat_coalesce.py::TestComputeCoalesceThreshold::test_negative_override_clamped_to_zero` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Heartbeat emits no events; thresholds, event counts and event payloads retire with that explicit boundary. | Retirement reference |
| `tests/test_heartbeat_coalesce.py::TestHeartbeatCoalescing::test_first_heartbeat_always_emits_event` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Heartbeat emits no events; thresholds, event counts and event payloads retire with that explicit boundary. | Retirement reference |
| `tests/test_heartbeat_coalesce.py::TestHeartbeatCoalescing::test_two_rapid_heartbeats_produce_one_event` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Heartbeat emits no events; thresholds, event counts and event payloads retire with that explicit boundary. | Retirement reference |
| `tests/test_heartbeat_coalesce.py::TestHeartbeatCoalescing::test_past_threshold_produces_second_event` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Heartbeat emits no events; thresholds, event counts and event payloads retire with that explicit boundary. | Retirement reference |
| `tests/test_heartbeat_coalesce.py::TestHeartbeatCoalescing::test_coalesce_threshold_zero_always_emits` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Heartbeat emits no events; thresholds, event counts and event payloads retire with that explicit boundary. | Retirement reference |
| `tests/test_heartbeat_coalesce.py::TestHeartbeatCoalescing::test_default_threshold_60_seconds_coalesces_rapid` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Heartbeat emits no events; thresholds, event counts and event payloads retire with that explicit boundary. | Retirement reference |
| `tests/test_heartbeat_coalesce.py::TestHeartbeatCoalescing::test_coalesced_heartbeat_still_extends_claim` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_extension` | Lease extension survives without any heartbeat event growth. | 1/1 nodes; recipes below |
| `tests/test_heartbeat_coalesce.py::TestHeartbeatEventPayload::test_event_contains_coalesce_threshold` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Heartbeat emits no events; thresholds, event counts and event payloads retire with that explicit boundary. | Retirement reference |
| `tests/test_production_readiness.py::TestClaimStolenMetric::test_stolen_claim_emits_event_and_metric` | SPLIT | `prototypes/kernel/tests/test_f1_core.py::test_attempt_monotonic` | SPLIT: takeover and monotonically increasing attempts preserved. Claim events retire by REPLAY_DOES_NOT_COVER; Prometheus stolen counter is UNRESOLVED (no kernel metrics or ruling). | 1/1 nodes; recipes below |
| `tests/test_production_readiness.py::TestClaimStolenMetric::test_same_actor_reacquire_does_not_count_as_stolen` | SPLIT | `prototypes/kernel/tests/test_f1_core.py::test_attempt_monotonic` | SPLIT: takeover and monotonically increasing attempts preserved. Claim events retire by REPLAY_DOES_NOT_COVER; Prometheus stolen counter is UNRESOLVED (no kernel metrics or ruling). | 1/1 nodes; recipes below |
| `tests/test_concurrency.py::TestAC28ConcurrentSeqGapFree::test_concurrent_appends_are_gap_free` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_concurrent_gap_free` | Serialized transition self-loops replace raw append writes; 20 writers and exact dense sequence are asserted. There is no public append_event in the kernel. | 1/1 nodes; recipes below |
| `tests/test_concurrency.py::TestAC28ConcurrentSeqGapFree::test_concurrent_transitions_gap_free` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_concurrent_gap_free` | Serialized transition self-loops replace raw append writes; 20 writers and exact dense sequence are asserted. There is no public append_event in the kernel. | 1/1 nodes; recipes below |
| `tests/test_bc310_replay_isolation.py::TestRepeatableReadTransactionManager::test_transaction_repeatable_read_sets_isolation` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_repeatable_snapshot` | Real database barrier lets a consistent edit commit during replay; old snapshot must remain visible. Public replay is also exercised under read-only settings. | 1/1 nodes; recipes below |
| `tests/test_bc310_replay_isolation.py::TestRepeatableReadTransactionManager::test_transaction_repeatable_read_sets_search_path` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_repeatable_snapshot` | Real database barrier lets a consistent edit commit during replay; old snapshot must remain visible. Public replay is also exercised under read-only settings. | 1/1 nodes; recipes below |
| `tests/test_bc310_replay_isolation.py::TestReplayUsesRepeatableRead::test_replay_succeeds_under_repeatable_read` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_repeatable_snapshot` | Real database barrier lets a consistent edit commit during replay; old snapshot must remain visible. Public replay is also exercised under read-only settings. | 1/1 nodes; recipes below |
| `tests/test_bc310_replay_isolation.py::TestReplayUsesRepeatableRead::test_scoped_replay_succeeds_under_repeatable_read` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_repeatable_snapshot` | Real database barrier lets a consistent edit commit during replay; old snapshot must remain visible. Public replay is also exercised under read-only settings. | 1/1 nodes; recipes below |
| `tests/test_bc310_replay_isolation.py::TestReplayUsesRepeatableRead::test_replay_does_not_see_concurrent_write` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_repeatable_snapshot` | Real database barrier lets a consistent edit commit during replay; old snapshot must remain visible. Public replay is also exercised under read-only settings. | 1/1 nodes; recipes below |
| `tests/test_replay.py::TestAC29OutOfBandEditDrift::test_direct_state_update_detected_as_drift` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[state]` |  | 1/1 nodes; recipes below |
| `tests/test_replay.py::TestAC29OutOfBandEditDrift::test_direct_custom_fields_update_detected_as_drift` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[fields]` |  | 1/1 nodes; recipes below |
| `tests/test_replay.py::TestAC29OutOfBandEditDrift::test_no_drift_after_normal_operations` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_clean_and_boundary` |  | 1/1 nodes; recipes below |
| `tests/test_wi266_fail_closed.py::TestChainBreaksFailClosed::test_per_work_item_hash_chain_break_counts_as_chain_breaks` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[chain]` |  | 1/1 nodes; recipes below |
| `tests/test_wi266_fail_closed.py::TestChainBreaksFailClosed::test_global_chain_orphan_counts_as_chain_breaks` | RETIRED-BY-DESIGN | `preservation map RETIRED-BY-DESIGN index: global signature-bound chain; D5` | No global signed head survives. Per-item chain and tail/sequence reconciliation are covered separately. | Retirement reference |
| `tests/test_wi266_fail_closed.py::TestChainBreaksFailClosed::test_global_chain_head_mismatch_counts_as_chain_breaks` | RETIRED-BY-DESIGN | `preservation map RETIRED-BY-DESIGN index: global signature-bound chain; D5` | No global signed head survives. Per-item chain and tail/sequence reconciliation are covered separately. | Retirement reference |
| `tests/test_wi266_fail_closed.py::TestChainBreaksFailClosed::test_clean_replay_reports_zero_chain_breaks` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[chain]` |  | 1/1 nodes; recipes below |
| `tests/test_wi266_fail_closed.py::TestChainBreaksFailClosed::test_cli_replay_exits_nonzero_and_prints_chain_breaks` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_drift_nonzero` | CLI exits 1 on reported damage in human and JSON modes. | 1/1 nodes; recipes below |
| `tests/test_wi266_fail_closed.py::TestChainBreaksFailClosed::test_cli_replay_json_serializes_chain_breaks` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_drift_nonzero` | CLI exits 1 on reported damage in human and JSON modes. | 1/1 nodes; recipes below |
| `tests/test_wi266_fail_closed.py::TestOrphanProjectionRowHaltsEverywhere::test_whole_store_orphan_with_created_event_halts` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[orphan_created]` | Missing projection is drift, never a clean result; kernel reports drift rather than old whole-store halt counters. | 1/1 nodes; recipes below |
| `tests/test_wi266_fail_closed.py::TestOrphanProjectionRowHaltsEverywhere::test_scoped_orphan_with_created_event_halts` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[orphan_created]` | Missing projection is drift, never a clean result; kernel reports drift rather than old whole-store halt counters. | 1/1 nodes; recipes below |
| `tests/test_wi266_fail_closed.py::TestOrphanProjectionRowHaltsEverywhere::test_in_memory_orphan_with_created_event_halts` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[orphan_created]` | Missing projection is drift, never a clean result; kernel reports drift rather than old whole-store halt counters. | 1/1 nodes; recipes below |
| `tests/test_wi266_fail_closed.py::TestUnvisitedProjectionRowsHalt::test_work_item_with_deleted_events_halts` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[all_deleted]` | Zero backing events produces explicit damage. | 1/1 nodes; recipes below |
| `tests/test_wi266_fail_closed.py::TestUnvisitedProjectionRowsHalt::test_scoped_replay_of_work_item_with_deleted_events_halts` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[all_deleted]` | Zero backing events produces explicit damage. | 1/1 nodes; recipes below |
| `tests/test_wi266_fail_closed.py::TestUnvisitedProjectionRowsHalt::test_fabricated_projection_row_halts` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[all_deleted]` | Zero backing events produces explicit damage. | 1/1 nodes; recipes below |
| `tests/test_wi266_fail_closed.py::TestUnvisitedProjectionRowsHalt::test_empty_log_with_head_set_is_a_hard_halt` | RETIRED-BY-DESIGN | `preservation map RETIRED-BY-DESIGN index: global signature-bound chain; D5` | No global signed head survives. Per-item chain and tail/sequence reconciliation are covered separately. | Retirement reference |
| `tests/test_wi266_fail_closed.py::TestUnvisitedProjectionRowsHalt::test_in_memory_work_item_with_deleted_events_halts` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[all_deleted]` | Zero backing events produces explicit damage. | 1/1 nodes; recipes below |
| `tests/test_wi266_fail_closed.py::TestUnvisitedProjectionRowsHalt::test_in_memory_empty_log_with_head_set_is_a_hard_halt` | RETIRED-BY-DESIGN | `preservation map RETIRED-BY-DESIGN index: global signature-bound chain; D5` | No global signed head survives. Per-item chain and tail/sequence reconciliation are covered separately. | Retirement reference |
| `tests/test_wi266_fail_closed.py::TestUnvisitedProjectionRowsHalt::test_in_memory_global_chain_head_mismatch_counts_as_chain_breaks` | RETIRED-BY-DESIGN | `preservation map RETIRED-BY-DESIGN index: global signature-bound chain; D5` | No global signed head survives. Per-item chain and tail/sequence reconciliation are covered separately. | Retirement reference |
| `tests/test_wi266_fail_closed.py::TestUnvisitedProjectionRowsHalt::test_in_memory_clean_replay_reports_zero_chain_breaks` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[chain]` |  | 1/1 nodes; recipes below |
| `tests/test_wi217_replay_memory.py::TestWI217ReplayMemory::test_replay_peak_does_not_track_log_size` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_memory_bound` | Client peak is bounded across 8x history growth; server DECLARE CURSOR plans as ordered Index Scan without Sort. | 1/1 nodes; recipes below |
| `tests/test_wi217_replay_memory.py::TestWI217ReplayMemory::test_stream_plan_has_no_sort` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_stream_plan_has_no_sort` | Client peak is bounded across 8x history growth; server DECLARE CURSOR plans as ordered Index Scan without Sort. | 0/1 nodes; recipes below |
| `tests/test_wi242_readonly.py::TestReplayNoResidue::test_replay_leaves_no_permanent_replay_tables` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_read_only_no_temp_residue` | Read-only public get/replay, repeated runs, no temporary-table catalog residue. Per-item result tuple replaces replay report entries/table_name. | 1/1 nodes; recipes below |
| `tests/test_wi242_readonly.py::TestReplayReadOnly::test_replay_works_under_read_only` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_read_only_no_temp_residue` | Read-only public get/replay, repeated runs, no temporary-table catalog residue. Per-item result tuple replaces replay report entries/table_name. | 1/1 nodes; recipes below |
| `tests/test_wi242_readonly.py::TestConnectReadOnly::test_read_only_connect_succeeds_on_migrated_schema` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_read_only_no_temp_residue` | Read-only public get/replay, repeated runs, no temporary-table catalog residue. Per-item result tuple replaces replay report entries/table_name. | 1/1 nodes; recipes below |
| `tests/test_wi242_readonly.py::TestConnectReadOnly::test_read_only_connect_fails_closed_on_missing_schema` | UNRESOLVED | `UNRESOLVED` | Kernel connect has no read-only/open-existing startup mode; initializer refusals are separate and do not carry this exact assertion. | No replacement claim |
| `tests/test_wi242_readonly.py::TestConnectReadOnly::test_read_only_connect_fails_closed_on_missing_migrations_table` | UNRESOLVED | `UNRESOLVED` | Kernel connect has no read-only/open-existing startup mode; initializer refusals are separate and do not carry this exact assertion. | No replacement claim |
| `tests/test_wi242_readonly.py::TestConnectReadOnly::test_normal_connect_creates_migrations_table` | UNRESOLVED | `UNRESOLVED` | Kernel connect has no read-only/open-existing startup mode; initializer refusals are separate and do not carry this exact assertion. | No replacement claim |
| `tests/test_wi242_readonly.py::TestReplayEntriesPortable::test_normal_mode_populates_entries` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_read_only_no_temp_residue` | Read-only public get/replay, repeated runs, no temporary-table catalog residue. Per-item result tuple replaces replay report entries/table_name. | 1/1 nodes; recipes below |
| `tests/test_wi242_readonly.py::TestReplayEntriesPortable::test_read_only_mode_populates_entries` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_read_only_no_temp_residue` | Read-only public get/replay, repeated runs, no temporary-table catalog residue. Per-item result tuple replaces replay report entries/table_name. | 1/1 nodes; recipes below |
| `tests/test_wi242_readonly.py::TestReplayEntriesPortable::test_entries_round_trip_with_warnings` | UNRESOLVED | `UNRESOLVED` | Kernel replay exposes per-item state/fields/drift, not report entries with numeric warnings. A clean read-only replay does not test that old report serialization assertion. | No replacement claim |
| `tests/test_wi242_readonly.py::TestReplayTempTablesDropped::test_no_temp_table_residue_after_success` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_read_only_no_temp_residue` | Read-only public get/replay, repeated runs, no temporary-table catalog residue. Per-item result tuple replaces replay report entries/table_name. | 1/1 nodes; recipes below |
| `tests/test_idempotency.py::TestAC24IdempotencyMismatch::test_same_event_id_different_transition_rejected` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[transition]` | Explicit event_id retries translate to public idempotency_key retries; the stable original result is retained. | 1/1 nodes; recipes below |
| `tests/test_idempotency.py::TestAC24IdempotencyMismatch::test_same_event_id_different_actor_rejected` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[actor]` | Explicit event_id retries translate to public idempotency_key retries; the stable original result is retained. | 1/1 nodes; recipes below |
| `tests/test_idempotency.py::TestAC24IdempotencyMismatch::test_idempotent_retry_returns_original` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_idempotency_original_result` | Explicit event_id retries translate to public idempotency_key retries; the stable original result is retained. | 1/1 nodes; recipes below |
| `tests/test_idempotency.py::TestAC25ExpectedEventSeq::test_expected_seq_mismatch_rejected` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_expected_sequence[1]` | Explicit event_id retries translate to public idempotency_key retries; the stable original result is retained. | 1/1 nodes; recipes below |
| `tests/test_idempotency.py::TestAC25ExpectedEventSeq::test_expected_seq_match_accepted` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_expected_sequence[0]` | Explicit event_id retries translate to public idempotency_key retries; the stable original result is retained. | 1/1 nodes; recipes below |
| `tests/test_idempotency.py::TestAC25ExpectedEventSeq::test_expected_seq_on_transition` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_expected_sequence[0]` | Explicit event_id retries translate to public idempotency_key retries; the stable original result is retained. | 1/1 nodes; recipes below |
| `tests/test_claim_link_idempotency.py::TestClaimIdempotency::test_acquire_claim_same_event_id_no_duplicate_events` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Claim/link operations do not emit events; event_id/event-count contracts retire. Duplicate typed-link creation is covered by test_links_lookup_and_idempotency. | Retirement reference |
| `tests/test_claim_link_idempotency.py::TestClaimIdempotency::test_release_claim_event_id_dedup` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Claim/link operations do not emit events; event_id/event-count contracts retire. Duplicate typed-link creation is covered by test_links_lookup_and_idempotency. | Retirement reference |
| `tests/test_claim_link_idempotency.py::TestLinkIdempotency::test_create_link_same_event_id_no_duplicate_events` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Claim/link operations do not emit events; event_id/event-count contracts retire. Duplicate typed-link creation is covered by test_links_lookup_and_idempotency. | Retirement reference |
| `tests/test_claim_link_idempotency.py::TestLinkIdempotency::test_remove_link_same_event_id_no_duplicate_events` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Claim/link operations do not emit events; event_id/event-count contracts retire. Duplicate typed-link creation is covered by test_links_lookup_and_idempotency. | Retirement reference |
| `tests/test_claim_link_idempotency.py::TestClaimActorMetadataWI224::test_claim_events_record_actor_metadata` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Claim/link operations do not emit events; event_id/event-count contracts retire. Duplicate typed-link creation is covered by test_links_lookup_and_idempotency. | Retirement reference |
| `tests/test_claim_link_idempotency.py::TestClaimActorMetadataWI224::test_claim_without_metadata_records_none` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | Claim/link operations do not emit events; event_id/event-count contracts retire. Duplicate typed-link creation is covered by test_links_lookup_and_idempotency. | Retirement reference |
| `tests/test_contract.py::TestCheckIdempotency::test_none_existing_returns_none` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_idempotency_original_result` | Behaviour tested through PostgreSQL/public operations, not private validation imports; None filters/old optional fields have no direct public equivalent. | 1/1 nodes; recipes below |
| `tests/test_contract.py::TestCheckIdempotency::test_matching_returns_existing` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_idempotency_original_result` | Behaviour tested through PostgreSQL/public operations, not private validation imports; None filters/old optional fields have no direct public equivalent. | 1/1 nodes; recipes below |
| `tests/test_contract.py::TestCheckIdempotency::test_actor_mismatch_raises` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[actor]` | Behaviour tested through PostgreSQL/public operations, not private validation imports; None filters/old optional fields have no direct public equivalent. | 1/1 nodes; recipes below |
| `tests/test_contract.py::TestCheckIdempotency::test_transition_mismatch_raises` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[transition]` | Behaviour tested through PostgreSQL/public operations, not private validation imports; None filters/old optional fields have no direct public equivalent. | 1/1 nodes; recipes below |
| `tests/test_contract.py::TestCheckIdempotency::test_matching_with_none_transition_and_none_actor` | UNRESOLVED | `UNRESOLVED` | Kernel transition retries require item, actor and transition; the old private wildcard lookup assertion has no public counterpart. | No replacement claim |
| `tests/test_contract.py::TestCheckIdempotency::test_work_item_id_mismatch_raises` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[item]` | Behaviour tested through PostgreSQL/public operations, not private validation imports; None filters/old optional fields have no direct public equivalent. | 1/1 nodes; recipes below |
| `tests/test_contract.py::TestCheckIdempotency::test_work_item_id_match_passes` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_idempotency_original_result` | Behaviour tested through PostgreSQL/public operations, not private validation imports; None filters/old optional fields have no direct public equivalent. | 1/1 nodes; recipes below |
| `tests/test_contract.py::TestCheckIdempotency::test_work_item_id_none_skips_check` | UNRESOLVED | `UNRESOLVED` | Kernel transition retries require an item id. The old wildcard item check has no public counterpart. | No replacement claim |
| `tests/test_contract.py::TestCheckExpectedSeq::test_none_expected_passes` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_idempotency_original_result` | Both first transitions omit expected_seq (default None) and remain valid as the current sequence advances. | 1/1 nodes; recipes below |
| `tests/test_contract.py::TestCheckExpectedSeq::test_matching_passes` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_expected_sequence[0]` | Behaviour tested through PostgreSQL/public operations, not private validation imports; None filters/old optional fields have no direct public equivalent. | 1/1 nodes; recipes below |
| `tests/test_contract.py::TestCheckExpectedSeq::test_mismatching_raises` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_expected_sequence[1]` | Behaviour tested through PostgreSQL/public operations, not private validation imports; None filters/old optional fields have no direct public equivalent. | 1/1 nodes; recipes below |
| `tests/test_link_errors.py::TestLinkErrorPaths::test_disallowed_link_type_rejected` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_link_vocabulary_and_removal` |  | 1/1 nodes; recipes below |
| `tests/test_link_errors.py::TestLinkErrorPaths::test_link_target_not_found_rejected` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_link_refusals[missing_target]` |  | 1/1 nodes; recipes below |
| `tests/test_link_errors.py::TestLinkErrorPaths::test_remove_nonexistent_link_rejected` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_remove_absent_link` |  | 1/1 nodes; recipes below |
| `tests/test_link_errors.py::TestLinkErrorPaths::test_link_removed_event_emitted` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_DOES_NOT_COVER` | No link events by explicit replay boundary. | Retirement reference |
| `tests/test_work_item_ref_validation.py::TestWorkItemRefCreateValidation::test_nonexistent_uuid_rejected` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[missing-create]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 1/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestWorkItemRefCreateValidation::test_wrong_type_rejected` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[wrong_type-create]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 1/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestWorkItemRefCreateValidation::test_correct_type_accepted` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[valid_source-create]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 0/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestWorkItemRefCreateValidation::test_invalid_uuid_format_rejected` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[invalid_uuid-create]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 1/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestWorkItemRefCreateValidation::test_optional_ref_with_none_accepted` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[null-create]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 0/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestWorkItemRefCreateValidation::test_untyped_ref_accepts_any_existing_uuid` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[untyped-create]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 0/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestWorkItemRefCreateValidation::test_untyped_ref_rejects_nonexistent` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[untyped_missing-create]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 1/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestWorkItemRefTransitionValidation::test_transition_rejects_nonexistent_ref` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[missing-transition]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 1/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestWorkItemRefTransitionValidation::test_transition_rejects_wrong_type_ref` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[wrong_type-transition]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 1/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestWorkItemRefTransitionValidation::test_transition_accepts_correct_type_ref` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[valid_source-transition]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 0/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestMultiTargetWorkItemRefCreateValidation::test_accepts_review_ref` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[valid_source-create]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 0/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestMultiTargetWorkItemRefCreateValidation::test_accepts_jury_ref` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[valid_review-create]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 0/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestMultiTargetWorkItemRefCreateValidation::test_rejects_wrong_type_ref` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[wrong_type-create]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 1/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestMultiTargetWorkItemRefCreateValidation::test_rejects_nonexistent_ref` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[missing-create]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 1/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestMultiTargetWorkItemRefCreateValidation::test_transition_accepts_matching_type` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[valid_source-transition]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 0/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestMultiTargetWorkItemRefCreateValidation::test_transition_rejects_non_matching_type` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[wrong_type-transition]` | UUID existence and single/union/any-target validation; null optional ref remains accepted. Two distinct allowed target types are tested. | 1/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestMultiTargetRegistrationValidation::test_both_singular_and_plural_rejected` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_field_declaration_refusals[both_ref_forms]` | One work_item_ref list replaces competing singular/plural declaration spellings. Both old spellings are unsupported field-rule keywords; union targets are validated at registration. | 1/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestMultiTargetRegistrationValidation::test_schema_rejects_both_singular_and_plural` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_field_declaration_refusals[both_ref_forms]` | One work_item_ref list replaces competing singular/plural declaration spellings. Both old spellings are unsupported field-rule keywords; union targets are validated at registration. | 1/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestMultiTargetRegistrationValidation::test_unknown_type_in_plural_rejected` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_field_declaration_refusals[unknown_ref_type]` | One work_item_ref list replaces competing singular/plural declaration spellings. Both old spellings are unsupported field-rule keywords; union targets are validated at registration. | 1/1 nodes; recipes below |
| `tests/test_work_item_ref_validation.py::TestMultiTargetRegistrationValidation::test_plural_form_round_trips_to_dict` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_field_schema_roundtrip` | One work_item_ref list replaces competing singular/plural declaration spellings. Both old spellings are unsupported field-rule keywords; union targets are validated at registration. | 0/1 nodes; recipes below |
| `tests/test_startup_integrity.py::TestMigrationRequired::test_refuses_start_with_pending_migrations` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_initialize_refuses_without_writes[version]` | Fresh schema baseline and explicit initialize path replace the old migration chain. Unsupported metadata also refuses every public write. | 1/1 nodes; recipes below |
| `tests/test_startup_integrity.py::TestMigrationRequired::test_refuses_start_with_multiple_pending_migrations` | PORTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_initialize_refuses_without_writes[version]` | Fresh schema baseline and explicit initialize path replace the old migration chain. Unsupported metadata also refuses every public write. | 1/1 nodes; recipes below |
| `tests/test_startup_integrity.py::TestMigrationRequired::test_starts_normally_with_all_migrations` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_fresh_init` | Fresh schema baseline and explicit initialize path replace the old migration chain. Unsupported metadata also refuses every public write. | 1/1 nodes; recipes below |
| `tests/test_startup_integrity.py::TestWorkflowVersionIncompatible::test_refuses_start_on_major_version_mismatch` | UNRESOLVED | `UNRESOLVED` | The authoring-format version is tested, but not the old stored workflow/library compatibility assertion. The kernel explicitly removes regista_version; no retirement ruling in this map makes that exact assertion safe to delete. | No replacement claim |
| `tests/test_startup_integrity.py::TestWorkflowVersionIncompatible::test_refuses_start_on_library_older_than_workflow` | UNRESOLVED | `UNRESOLVED` | The authoring-format version is tested, but not the old stored workflow/library compatibility assertion. The kernel explicitly removes regista_version; no retirement ruling in this map makes that exact assertion safe to delete. | No replacement claim |
| `tests/test_startup_integrity.py::TestWorkflowVersionIncompatible::test_starts_normally_with_compatible_workflow` | UNRESOLVED | `UNRESOLVED` | The authoring-format version is tested, but not the old stored workflow/library compatibility assertion. The kernel explicitly removes regista_version; no retirement ruling in this map makes that exact assertion safe to delete. | No replacement claim |
| `tests/test_startup_integrity.py::TestWorkflowVersionIncompatible::test_error_detail_contains_issue_list` | UNRESOLVED | `UNRESOLVED` | The authoring-format version is tested, but not the old stored workflow/library compatibility assertion. The kernel explicitly removes regista_version; no retirement ruling in this map makes that exact assertion safe to delete. | No replacement claim |
| `tests/test_cli_args.py::TestCLIExitCodes::test_no_args_exits_2` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 30/30 nodes; recipes below |
| `tests/test_cli_args.py::TestCLIExitCodes::test_workflow_validate_ok` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_each_command` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 36/36 nodes; recipes below |
| `tests/test_cli_args.py::TestCLIExitCodes::test_workflow_validate_json` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_each_command` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 36/36 nodes; recipes below |
| `tests/test_cli_args.py::TestCLIExitCodes::test_workflow_validate_bad` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 30/30 nodes; recipes below |
| `tests/test_cli_args.py::TestCLIExitCodes::test_work_item_show_missing_config` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 14/14 nodes; recipes below |
| `tests/test_cli_args.py::TestCLIExitCodes::test_schema_status_missing_config` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 14/14 nodes; recipes below |
| `tests/test_cli_args.py::TestCLIExitCodes::test_schema_init_missing_config` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 14/14 nodes; recipes below |
| `tests/test_cli_args.py::TestCLIExitCodes::test_replay_missing_config` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 14/14 nodes; recipes below |
| `tests/test_cli_args.py::TestCLIExitCodes::test_events_show_missing_config` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 14/14 nodes; recipes below |
| `tests/test_cli_args.py::TestCLIExitCodes::test_events_tail_missing_config` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 14/14 nodes; recipes below |
| `tests/test_cli_args.py::TestCLIExitCodes::test_hooks_dead_letter_list_missing_config` | RETIRED-BY-DESIGN | `D4` | Queued hooks/CLI are removed. | Retirement reference |
| `tests/test_cli_args.py::TestCLIExitCodes::test_hooks_dead_letter_requeue_missing_config` | RETIRED-BY-DESIGN | `D4` | Queued hooks/CLI are removed. | Retirement reference |
| `tests/test_cli_args.py::TestCLIExitCodes::test_actor_roles_list_missing_config` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 14/14 nodes; recipes below |
| `tests/test_cli_args.py::TestCLIExitCodes::test_unknown_command_prints_help` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 30/30 nodes; recipes below |
| `tests/test_stream_discipline.py::test_library_logging_defaults_to_stderr` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_each_command` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 36/36 nodes; recipes below |
| `tests/test_stream_discipline.py::test_app_structlog_configuration_wins` | UNRESOLVED | `UNRESOLVED` | CLI stream tests do not exercise embedding-app logging configuration. Kernel imports no structlog; the exact import-does-not-reconfigure assertion remains unported. | No replacement claim |
| `tests/test_stream_discipline.py::test_handle_error_human_mode` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 30/30 nodes; recipes below |
| `tests/test_stream_discipline.py::test_handle_error_json_mode_emits_envelope` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 30/30 nodes; recipes below |
| `tests/test_stream_discipline.py::test_handle_error_retryable_codes` | UNRESOLVED | `UNRESOLVED` | Kernel error envelopes do not expose retryable. Nonzero exits and JSON parseability do not preserve that assertion; no retirement ruling is explicit. | No replacement claim |
| `tests/test_wi229_cli_contract.py::TestJsonExitCodeAudit::test_exit_is_decided_outside_the_format_branch` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 30/30 nodes; recipes below |
| `tests/test_wi229_cli_contract.py::TestJsonExitCodeAudit::test_the_scan_detects_the_shape_it_claims_to` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 30/30 nodes; recipes below |
| `tests/test_wi229_cli_contract.py::TestJsonExitCodeAudit::test_the_audit_list_covers_every_such_handler` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit` | Subprocess test matrix asserts stdout discipline/JSON parseability and human/JSON exit parity. Old private CLI handlers and structlog config are removed. | 30/30 nodes; recipes below |
| `tests/test_doctor.py: reachability/schema checks` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_unreachable_database` | Health command is covered by test_each_command[True-health]. | 2/2 nodes; recipes below |
| `tests/test_doctor.py: CREATEROLE role attribute` | UNRESOLVED | `UNRESOLVED` | Kernel health does not report service-role privilege diagnostics; no retirement ruling. | No replacement claim |
| `tests/test_cli_conformance.py: generic conformance assertions` | PORTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit` | D20: port ordinary subprocess contract, drop dependency on suite conformance kit. | 30/30 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceWorkflow::test_register_and_idempotent` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_workflow_idempotent` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceWorkflow::test_register_version_conflict` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_workflow_version_conflict` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceWorkItem::test_create_and_get` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_create_and_get` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceWorkItem::test_create_missing_required_field` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[required-create]` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceWorkItem::test_create_unknown_type` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_create_refusals[type]` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceTransition::test_valid_transition` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_full_repair_handoff` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceTransition::test_invalid_transition` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_transition_refusals[wrong_state]` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceTransition::test_role_not_permitted` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_transition_refusals[role]` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceTransition::test_transition_via_append_blocked` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_transition_is_the_only_public_event_writer` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceTransition::test_custom_fields_update_on_transition` | PORTED | `prototypes/kernel/tests/test_f1_fields.py::test_shallow_merge_and_atomic_clear` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceEvents::test_read_events_by_work_item` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_create_and_get` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceEvents::test_read_events_by_actor` | UNRESOLVED | `UNRESOLVED` | No actor-filtered history API. | No replacement claim |
| `tests/test_in_memory_conformance.py::TestConformanceEvents::test_event_idempotency` | UNRESOLVED | `UNRESOLVED` | Creation accepts no caller event_id; this exact caller-chosen identity assertion is not the transition retry assertion. | No replacement claim |
| `tests/test_in_memory_conformance.py::TestConformanceEvents::test_read_events_composite_work_item_and_transition` | UNRESOLVED | `UNRESOLVED` | No transition filter on public history. | No replacement claim |
| `tests/test_in_memory_conformance.py::TestConformanceEvents::test_read_events_composite_actor_and_transition` | UNRESOLVED | `UNRESOLVED` | No composite actor/transition history filter. | No replacement claim |
| `tests/test_in_memory_conformance.py::TestConformanceClaims::test_acquire_and_release` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_claim_acquire_release` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceClaims::test_claim_contested` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_claim_contested[other]` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceClaims::test_heartbeat` | PORTED | `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_extension` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceClaims::test_claim_releases_on_transition` | UNRESOLVED | `UNRESOLVED` | Kernel retains the lease through transitions until explicit release. New test_lease_is_retained_until_explicit_release pins current behavior; no ruling explicitly retires auto-release. | No replacement claim |
| `tests/test_in_memory_conformance.py::TestConformanceLinks::test_create_and_query` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_links_lookup_and_idempotency` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceActorRoles::test_register_and_enforce` | UNRESOLVED | `UNRESOLVED` | No actor-role registry. Workflow roles remain caller-presented policy (Plan 032 §1); registry assertion itself is not ported. | No replacement claim |
| `tests/test_in_memory_conformance.py::TestConformanceActorRoles::test_role_rejects_unauthorized` | UNRESOLVED | `UNRESOLVED` | Caller-presented role checks do not implement registry-authorized actor roles. Not labelled retired without a ruling. | No replacement claim |
| `tests/test_in_memory_conformance.py::TestConformanceQuery::test_query_by_state` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_query_filters_and_liveness` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceQuery::test_query_by_workflow` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_query_filters_and_liveness` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceQuery::test_query_with_cursor` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_query_order_and_paging[all]` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceReplay::test_replay_no_drift` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_clean_and_boundary` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceReplay::test_replay_no_drift_with_active_claim` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_clean_and_boundary` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceUpdateNotBefore::test_set_and_clear` | UNRESOLVED | `UNRESOLVED` | No update_not_before; D4 retires recurrence, not explicitly this standalone deferral assertion. | No replacement claim |
| `tests/test_in_memory_conformance.py::TestConformanceCustomFieldFilter::test_custom_field_filter` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_query_filters_and_liveness` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceCustomFieldFilter::test_custom_field_filter_unknown_key` | PORTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_query_filters_and_liveness` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestConformanceCustomFieldFilter::test_custom_field_filter_nested_json_containment` | UNRESOLVED | `UNRESOLVED` | Kernel scalar-equality filter explicitly refuses objects; nested containment is a different contract and lacks a retirement ruling. | No replacement claim |
| `tests/test_in_memory_conformance.py::TestBC189OrphanEventDetection::test_orphan_with_created_event_counts_as_halted` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[orphan_created]` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestBC189OrphanEventDetection::test_orphan_without_created_event_counts_as_halted` | PORTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[orphan_noncreated]` | §B assertion adapted to kernel public results; real PostgreSQL only. The 32 unchanged-body claim is inaccurate. | 1/1 nodes; recipes below |
| `tests/test_in_memory_conformance.py::TestHeartbeatActorKindConformance::test_heartbeat_actor_kind_emitted_real` | RETIRED-BY-DESIGN | `7b3607a REPLAY_DOES_NOT_COVER` | Heartbeat events do not exist. Actor-kind on creation/transition is tested through CLI. | Retirement reference |
| `tests/test_in_memory_conformance.py::TestHeartbeatActorKindConformance::test_heartbeat_actor_kind_emitted_in_memory_with_keys` | RETIRED-BY-DESIGN | `D2 + 7b3607a REPLAY_DOES_NOT_COVER` | Backend parity target retired; heartbeat events outside boundary. | Retirement reference |
| `tests/test_replay_coverage.py::TestReplayClaimLifecycle::test_replay_derives_claim_acquired` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_COVERS / REPLAY_DOES_NOT_COVER` | Claims, links, fencing counters have no event trail; test_replay_clean_and_boundary proves replay leaves them alone and never resets/reissues persisted attempts. | Retirement reference |
| `tests/test_replay_coverage.py::TestReplayClaimLifecycle::test_replay_derives_claim_stolen` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_COVERS / REPLAY_DOES_NOT_COVER` | Claims, links, fencing counters have no event trail; test_replay_clean_and_boundary proves replay leaves them alone and never resets/reissues persisted attempts. | Retirement reference |
| `tests/test_replay_coverage.py::TestReplayClaimLifecycle::test_replay_derives_claim_released` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_COVERS / REPLAY_DOES_NOT_COVER` | Claims, links, fencing counters have no event trail; test_replay_clean_and_boundary proves replay leaves them alone and never resets/reissues persisted attempts. | Retirement reference |
| `tests/test_replay_coverage.py::TestReplayClaimLifecycle::test_replay_derives_claim_expired` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_COVERS / REPLAY_DOES_NOT_COVER` | Claims, links, fencing counters have no event trail; test_replay_clean_and_boundary proves replay leaves them alone and never resets/reissues persisted attempts. | Retirement reference |
| `tests/test_replay_coverage.py::TestReplayClaimLifecycle::test_replay_heartbeat_drift_within_threshold` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_COVERS / REPLAY_DOES_NOT_COVER` | Claims, links, fencing counters have no event trail; test_replay_clean_and_boundary proves replay leaves them alone and never resets/reissues persisted attempts. | Retirement reference |
| `tests/test_replay_coverage.py::TestReplayLinkLifecycle::test_replay_derives_link_created_and_removed` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_COVERS / REPLAY_DOES_NOT_COVER` | Claims, links, fencing counters have no event trail; test_replay_clean_and_boundary proves replay leaves them alone and never resets/reissues persisted attempts. | Retirement reference |
| `tests/test_replay_coverage.py::TestBC090ClaimStateDriftDetection::test_claimed_by_tampered_detected_as_drift` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_COVERS / REPLAY_DOES_NOT_COVER` | Claims, links, fencing counters have no event trail; test_replay_clean_and_boundary proves replay leaves them alone and never resets/reissues persisted attempts. | Retirement reference |
| `tests/test_replay_coverage.py::TestBC090ClaimStateDriftDetection::test_claim_expires_at_tampered_detected_as_drift` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_COVERS / REPLAY_DOES_NOT_COVER` | Claims, links, fencing counters have no event trail; test_replay_clean_and_boundary proves replay leaves them alone and never resets/reissues persisted attempts. | Retirement reference |
| `tests/test_replay_coverage.py::TestBC090ClaimStateDriftDetection::test_claim_state_cleared_after_workflow_transition` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_COVERS / REPLAY_DOES_NOT_COVER` | Claims, links, fencing counters have no event trail; test_replay_clean_and_boundary proves replay leaves them alone and never resets/reissues persisted attempts. | Retirement reference |
| `tests/test_replay_coverage.py::TestBC090ClaimStateDriftDetection::test_claim_state_correct_after_acquire_and_heartbeat` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_COVERS / REPLAY_DOES_NOT_COVER` | Claims, links, fencing counters have no event trail; test_replay_clean_and_boundary proves replay leaves them alone and never resets/reissues persisted attempts. | Retirement reference |
| `tests/test_replay_coverage.py::TestBC090ClaimStateDriftDetection::test_claim_attempt_number_reconstructed` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_COVERS / REPLAY_DOES_NOT_COVER` | Claims, links, fencing counters have no event trail; test_replay_clean_and_boundary proves replay leaves them alone and never resets/reissues persisted attempts. | Retirement reference |
| `tests/test_replay_coverage.py::TestBC090ClaimStateDriftDetection::test_claim_stolen_replay_drift_detection` | RETIRED-BY-DESIGN | `7b3607a: REPLAY_COVERS / REPLAY_DOES_NOT_COVER` | Claims, links, fencing counters have no event trail; test_replay_clean_and_boundary proves replay leaves them alone and never resets/reissues persisted attempts. | Retirement reference |
| `§1 supplied schema cannot redirect operations` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_supplied_schema_cannot_redirect` |  | 1/1 nodes; recipes below |
| `§1 supplied workflow name is data` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_supplied_workflow_name_is_data` |  | 1/1 nodes; recipes below |
| `§3 available/owned/in-states/blocked/review-ready order and pagination` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_query_order_and_paging` |  | 6/6 nodes; recipes below |
| `§4 expired-but-unswept transition refusal` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_core.py::test_transition_fencing[expired]` |  | 1/1 nodes; recipes below |
| `§4 expired heartbeat cannot revive lease` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_refusals[expired]` |  | 1/1 nodes; recipes below |
| `§4 actor must be the live holder` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_core.py::test_transition_fencing[actor]` |  | 1/1 nodes; recipes below |
| `§5 event/projection rollback between effects` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_core.py::test_event_projection_atomicity` |  | 2/2 nodes; recipes below |
| `§5 reducer-reserved caller payload refusal` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_core.py::test_reserved_payload_refusal` |  | 5/5 nodes; recipes below |
| `§5 deletion of field-changing final event` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[tail_deleted]` |  | 1/1 nodes; recipes below |
| `§6 actor-kind/role changes conflict on retry` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict` |  | 8/8 nodes; recipes below |
| `§7 D7 shallow merge and explicit atomic clearing` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_fields.py::test_shallow_merge_and_atomic_clear` |  | 1/1 nodes; recipes below |
| `§8 D6 bounded single-hop query: direction, satisfaction, no scheduler` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_queries_links.py::test_d6_single_hop_no_scheduler` |  | 1/1 nodes; recipes below |
| `§9 every actual CLI command, subprocess, both modes` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_cli.py::test_each_command` |  | 36/36 nodes; recipes below |
| `§C honest reconstruction boundary` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_replay.py::test_replay_clean_and_boundary` |  | 1/1 nodes; recipes below |
| `Pool cache reset remains healthy over sustained operations` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_core.py::test_sustained_pool_operations` |  | 1/1 nodes; recipes below |
| `Concurrent same-key and cross-item idempotency` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_core.py::test_concurrent_idempotency` |  | 2/2 nodes; recipes below |
| `Concurrent workflow registration` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_core.py::test_concurrent_workflow_registration` |  | 1/1 nodes; recipes below |
| `Unsupported/missing schema version refuses all nine mutation entry points` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write` |  | 18/18 nodes; recipes below |
| `Positive finite lease TTL and no effects on invalid input` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_core.py::test_invalid_lease_ttl` |  | 10/10 nodes; recipes below |
| `Missing DSN refuses with exit 2 in both CLI modes` | NEWLY PROTECTED | `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn` |  | 14/14 nodes; recipes below |


## §A fixture blast radius

The new public fixture replaces the v6 bootstrap for ported assertions. The
45-file importer inventory itself does **not** enumerate every retained
assertion in each file. These files are therefore explicitly audited below;
an inventory-only row is not evidence permitting whole-file deletion.

| Old caller | Retargeting evidence |
| --- | --- |
| `tests/test_bc184_bc185_metrics.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_bc215_219_220_221.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_bc278_279_280.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_bc306_entity_kind_validation.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_bc310_replay_isolation.py` | 5 individually mapped rows above |
| `tests/test_canonical_workflow.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_claim_link_idempotency.py` | 6 individually mapped rows above |
| `tests/test_cli_integration.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_concurrency.py` | 2 individually mapped rows above |
| `tests/test_coverage_gaps.py` | 2 individually mapped rows above |
| `tests/test_e2e.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_events_partition.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_heartbeat_coalesce.py` | 10 individually mapped rows above |
| `tests/test_hook_miss_recovery.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_idempotency.py` | 6 individually mapped rows above |
| `tests/test_in_memory_conformance.py` | 35 individually mapped rows above |
| `tests/test_link_errors.py` | 4 individually mapped rows above |
| `tests/test_phase2.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_phase3.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_plan007_facade.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_plan008_ws1.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_plan009.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_plan016.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_plan022.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_production_readiness.py` | 2 individually mapped rows above |
| `tests/test_property_conformance.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_read_events_conformance.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_remaining_errors.py` | 8 individually mapped rows above |
| `tests/test_replay_coverage.py` | 12 individually mapped rows above |
| `tests/test_replay.py` | 3 individually mapped rows above |
| `tests/test_replay_scoped.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_scale.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_session13_regression.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_sf2_workflows.py` | 7 individually mapped rows above |
| `tests/test_smoke.py` | 11 individually mapped rows above |
| `tests/test_stale_heartbeat.py` | 3 individually mapped rows above |
| `tests/test_validator_context_enrichment.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_validator_hardening.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_version_pinning.py` | 3 individually mapped rows above |
| `tests/test_wi217_replay_memory.py` | 2 individually mapped rows above |
| `tests/test_wi234_actor_metadata_limit.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_wi242_readonly.py` | 10 individually mapped rows above |
| `tests/test_wi266_fail_closed.py` | 17 individually mapped rows above |
| `tests/test_wi289_v6_counterparts.py` | UNRESOLVED: caller inventory only; unnamed PORT/SPLIT assertions not yet individually retargeted |
| `tests/test_work_item_ref_validation.py` | 20 individually mapped rows above |

## Mutation proof

Run `REGISTA_TEST_DSN=... .venv/bin/python prototypes/kernel/prove_f1.py`.
The runner copies only kernel assets to a temporary directory and redirects
the suite's public import/CLI paths there. A clean control run is mandatory.
Each selected node must report a test-body failure in JUnit; errors, skips,
or a surviving selected node reject the proof. JUnit test-body failures
include assertions and exceptions raised by the defective operation; fixture
setup/teardown errors never count. The clean control run excludes only the
large memory-bound case, which runs separately in the full suite and against
the materialization mutant.

Final proof: **71 mutants killed; 276 distinct test nodes proved**.
This comprises the complete 70-mutant run and a targeted, clean-control
restoration of CLI connection setup outside its error handler (both modes).
The runtime/tests under proof are committed at `ceecc38`; only proof and
ledger artifacts were edited afterwards.
[F1-mutation-evidence.json](F1-mutation-evidence.json) records each mutant,
source file, selector and every failing node. [prove_f1.py](prove_f1.py) holds
the exact executable recipe for each name below: removed/inverted admission
conditions, bypassed ownership/expiry/attempt checks, retry/sequence defects,
partial commits, redirected namespace, invalid declaration acceptance,
materialized/READ COMMITTED replay, broken pool reset, reversed query order,
changed CLI exits and replay writes/counter resets. Each run uses a fresh
scratch copy and requires every selected node to go red.

The database-failure atomicity tests reject commits between event/projection
effects; the namespace tests reject a shared/redirected namespace; the replay
boundary test rejects resetting the persisted fencing counter. These are
operation failures against PostgreSQL, not mocks or inverted test assertions.

| Mutation-proven new node | Defect recipes that made it fail |
| --- | --- |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_drift_nonzero` | `cli_failures_exit_zero`, `replay_always_clean` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_fresh_init` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_listing_modes_and_pages` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[False-claim]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[False-health]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[False-history]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[False-init]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[False-replay]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[False-show]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[False-workflow_list]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[True-claim]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[True-health]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[True-history]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[True-init]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[True-replay]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[True-show]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_missing_dsn[True-workflow_list]` | `missing_dsn_exit_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_new_workflow` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-blocked]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-claim]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-create]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-cursor]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-heartbeat]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-invalid_workflow]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-legacy_verb]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-limit]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-link]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-malformed_yaml]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-missing_argument]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-show]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-transition]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-unknown_command]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[False-workflow_show]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-blocked]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-claim]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-create]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-cursor]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-heartbeat]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-invalid_workflow]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-legacy_verb]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-limit]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-link]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-malformed_yaml]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-missing_argument]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-show]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-transition]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-unknown_command]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_refusal_audit[True-workflow_show]` | `cli_failures_exit_zero` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_unlink[False]` | `cli_bad_exits_zero`, `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_unlink[True]` | `cli_bad_exits_zero`, `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_unreachable_database[False]` | `cli_bad_exits_zero`, `cli_connect_outside_error_handler` |
| `prototypes/kernel/tests/test_f1_cli.py::test_cli_unreachable_database[True]` | `cli_bad_exits_zero`, `cli_connect_outside_error_handler` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-claim]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-create]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-expire_leases]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-health]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-heartbeat]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-history]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-init]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-lease]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-link]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-list]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-release]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-replay]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-show]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-transition]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-workflow_list]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-workflow_register]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-workflow_show]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[False-workflow_validate]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-claim]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-create]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-expire_leases]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-health]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-heartbeat]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-history]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-init]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-lease]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-link]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-list]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-release]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-replay]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-show]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-transition]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-workflow_list]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-workflow_register]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-workflow_show]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_cli.py::test_each_command[True-workflow_validate]` | `cli_success_exits_one` |
| `prototypes/kernel/tests/test_f1_core.py::test_attempt_monotonic` | `attempt_reissued`, `release_fence_removed` |
| `prototypes/kernel/tests/test_f1_core.py::test_claim_acquire_release` | `release_ignored` |
| `prototypes/kernel/tests/test_f1_core.py::test_claim_contested[other]` | `claim_contention` |
| `prototypes/kernel/tests/test_f1_core.py::test_claim_contested[w]` | `claim_contention` |
| `prototypes/kernel/tests/test_f1_core.py::test_concurrent_claim_one_winner` | `claim_contention` |
| `prototypes/kernel/tests/test_f1_core.py::test_concurrent_gap_free` | `sequence_gaps` |
| `prototypes/kernel/tests/test_f1_core.py::test_concurrent_idempotency[False]` | `retry_lookup_removed` |
| `prototypes/kernel/tests/test_f1_core.py::test_concurrent_idempotency[True]` | `retry_lookup_removed` |
| `prototypes/kernel/tests/test_f1_core.py::test_concurrent_workflow_registration` | `workflow_lock_missing` |
| `prototypes/kernel/tests/test_f1_core.py::test_create_and_get` | `history_missing` |
| `prototypes/kernel/tests/test_f1_core.py::test_create_refusals[type]` | `type_unchecked` |
| `prototypes/kernel/tests/test_f1_core.py::test_create_refusals[workflow]` | `workflow_ignored` |
| `prototypes/kernel/tests/test_f1_core.py::test_event_projection_atomicity[create]` | `partial_commit` |
| `prototypes/kernel/tests/test_f1_core.py::test_event_projection_atomicity[transition]` | `partial_commit` |
| `prototypes/kernel/tests/test_f1_core.py::test_expected_sequence[0]` | `expected_sequence_always_refused` |
| `prototypes/kernel/tests/test_f1_core.py::test_expected_sequence[1]` | `expected_sequence_ignored` |
| `prototypes/kernel/tests/test_f1_core.py::test_expected_sequence[99]` | `expected_sequence_ignored` |
| `prototypes/kernel/tests/test_f1_core.py::test_full_repair_handoff` | `replay_ignores_handoff_fields` |
| `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_extension` | `heartbeat_no_extension` |
| `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_refusals[actor]` | `heartbeat_owner_attempt_expiry` |
| `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_refusals[attempt]` | `heartbeat_owner_attempt_expiry` |
| `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_refusals[expired]` | `heartbeat_owner_attempt_expiry` |
| `prototypes/kernel/tests/test_f1_core.py::test_heartbeat_refusals[takeover]` | `heartbeat_owner_attempt_expiry` |
| `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[actor]` | `retry_conflict_accepted` |
| `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[actor_kind]` | `retry_conflict_accepted` |
| `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[fields]` | `retry_conflict_accepted` |
| `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[item]` | `retry_conflict_accepted` |
| `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[payload]` | `retry_conflict_accepted` |
| `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[role]` | `retry_conflict_accepted` |
| `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[transition]` | `retry_conflict_accepted` |
| `prototypes/kernel/tests/test_f1_core.py::test_idempotency_conflict[unset]` | `retry_conflict_accepted` |
| `prototypes/kernel/tests/test_f1_core.py::test_idempotency_original_result` | `retry_returns_latest`, `retry_lookup_removed` |
| `prototypes/kernel/tests/test_f1_core.py::test_invalid_lease_ttl[-1.0-claim]` | `invalid_ttl_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_invalid_lease_ttl[-1.0-heartbeat]` | `invalid_ttl_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_invalid_lease_ttl[-inf-claim]` | `invalid_ttl_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_invalid_lease_ttl[-inf-heartbeat]` | `invalid_ttl_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_invalid_lease_ttl[0.0-claim]` | `invalid_ttl_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_invalid_lease_ttl[0.0-heartbeat]` | `invalid_ttl_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_invalid_lease_ttl[inf-claim]` | `invalid_ttl_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_invalid_lease_ttl[inf-heartbeat]` | `invalid_ttl_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_invalid_lease_ttl[nan-claim]` | `invalid_ttl_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_invalid_lease_ttl[nan-heartbeat]` | `invalid_ttl_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_lease_is_retained_until_explicit_release` | `transition_releases_lease` |
| `prototypes/kernel/tests/test_f1_core.py::test_reserved_payload_refusal[created]` | `reserved_payload_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_reserved_payload_refusal[fields]` | `reserved_payload_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_reserved_payload_refusal[from]` | `reserved_payload_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_reserved_payload_refusal[to]` | `reserved_payload_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_reserved_payload_refusal[unset]` | `reserved_payload_allowed` |
| `prototypes/kernel/tests/test_f1_core.py::test_sustained_pool_operations` | `prepared_cache_restored` |
| `prototypes/kernel/tests/test_f1_core.py::test_sweep_scoped_and_live_safe` | `sweep_live_leases` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_fencing[actor]` | `lease_fencing` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_fencing[expired]` | `lease_fencing` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_fencing[missing]` | `lease_fencing` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_fencing[released]` | `lease_fencing` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_fencing[swept]` | `lease_fencing` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_fencing[takeover]` | `lease_fencing` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_fencing[wrong]` | `lease_fencing` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_is_the_only_public_event_writer` | `append_writer_reintroduced` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_refusals[null]` | `required_gate_removed` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_refusals[required]` | `required_gate_removed` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_refusals[role]` | `role_gate_removed` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_refusals[terminal]` | `terminal_gate_removed` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_refusals[unknown]` | `unknown_transition_accepted` |
| `prototypes/kernel/tests/test_f1_core.py::test_transition_refusals[wrong_state]` | `from_state_gate_removed` |
| `prototypes/kernel/tests/test_f1_core.py::test_version_pinning` | `workflow_pinning_removed` |
| `prototypes/kernel/tests/test_f1_core.py::test_workflow_idempotent` | `workflow_duplicate_version` |
| `prototypes/kernel/tests/test_f1_core.py::test_workflow_version_conflict` | `workflow_version_assertion_ignored` |
| `prototypes/kernel/tests/test_f1_fields.py::test_clear_refusals[required_clear]` | `required_gate_removed` |
| `prototypes/kernel/tests/test_f1_fields.py::test_clear_refusals[same_key]` | `clear_collision_allowed` |
| `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[enum-create]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[enum-transition]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[required-create]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[required-transition]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[type-create]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[type-transition]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[unknown-create]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_declared_field_refusals[unknown-transition]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_field_declaration_refusals[boolean_rule]` | `workflow_semantics_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_field_declaration_refusals[both_ref_forms]` | `workflow_semantics_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_field_declaration_refusals[invalid_schema]` | `workflow_semantics_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_field_declaration_refusals[malformed_ref]` | `workflow_semantics_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_field_declaration_refusals[null_ref_rule]` | `workflow_semantics_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_field_declaration_refusals[schema_reference]` | `workflow_semantics_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_field_declaration_refusals[unknown_ref_type]` | `workflow_semantics_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_field_declaration_refusals[unknown_type]` | `workflow_semantics_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[create-inf]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[create-nan]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[create-value2]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[create-value3]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[create-value4]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[payload-inf]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[payload-nan]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[payload-value2]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[payload-value3]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[payload-value4]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[transition-inf]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[transition-nan]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[transition-value2]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[transition-value3]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_json_type_refusal[transition-value4]` | `json_types_unchecked` |
| `prototypes/kernel/tests/test_f1_fields.py::test_shallow_merge_and_atomic_clear` | `clear_not_recorded` |
| `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[invalid_uuid-create]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[invalid_uuid-transition]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[missing-create]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[missing-transition]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[untyped_missing-create]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[untyped_missing-transition]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[wrong_type-create]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_fields.py::test_work_item_refs[wrong_type-transition]` | `field_schema_unenforced` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_catalog_roundtrip` | `initializer_missing_catalog` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_concurrent_initialize` | `initializer_missing` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_database_role_is_scoped` | `namespace_shared_role` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[duplicate_state]` | `document_rules_ignored` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[duplicate_transition]` | `document_rules_ignored` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[format_version]` | `document_rules_ignored` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[initial]` | `document_rules_ignored` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[name]` | `document_rules_ignored` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[states]` | `document_rules_ignored` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[undeclared_role]` | `workflow_semantics_unchecked`, `document_rules_ignored` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[unknown_from]` | `workflow_semantics_unchecked`, `document_rules_ignored` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[unknown_to]` | `workflow_semantics_unchecked`, `document_rules_ignored` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[unreachable]` | `workflow_semantics_unchecked`, `document_rules_ignored` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_document_semantic_refusals[unused_role]` | `workflow_semantics_unchecked`, `document_rules_ignored` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_initialize_refuses_without_writes[empty_meta]` | `schema_refusal_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_initialize_refuses_without_writes[legacy]` | `schema_refusal_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_initialize_refuses_without_writes[unknown]` | `schema_refusal_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_initialize_refuses_without_writes[version]` | `schema_refusal_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_load_refusals[duplicate]` | `invalid_files_accepted` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_load_refusals[empty]` | `invalid_files_accepted` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_load_refusals[extension]` | `invalid_files_accepted` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_load_refusals[syntax]` | `invalid_files_accepted` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_namespace_isolation` | `namespace_shared` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_supplied_schema_cannot_redirect` | `search_path_injection` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_supplied_workflow_name_is_data` | `workflow_name_ignored` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[claim-missing]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[claim-unsupported]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[create-missing]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[create-unsupported]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[heartbeat-missing]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[heartbeat-unsupported]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[link-missing]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[link-unsupported]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[release-missing]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[release-unsupported]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[remove_link-missing]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[remove_link-unsupported]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[sweep-missing]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[sweep-unsupported]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[transition-missing]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[transition-unsupported]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[workflow-missing]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_namespace_workflows.py::test_unsupported_schema_cannot_write[workflow-unsupported]` | `write_schema_gate_removed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_d6_single_hop_no_scheduler` | `query_order_reversed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_link_refusals[missing_source]` | `link_endpoints_unchecked` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_link_refusals[missing_target]` | `missing_target_silent` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_link_refusals[self]` | `link_self_allowed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_link_vocabulary_and_removal` | `link_type_unchecked` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_links_lookup_and_idempotency` | `duplicate_link_refused` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_filters_and_liveness` | `query_order_reversed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_order_and_paging[all]` | `query_order_reversed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_order_and_paging[available]` | `query_order_reversed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_order_and_paging[blocked]` | `query_order_reversed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_order_and_paging[in_states]` | `query_order_reversed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_order_and_paging[owned]` | `query_order_reversed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_order_and_paging[review_ready]` | `query_order_reversed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_refusals[dead_cursor]` | `dead_cursor_restarts` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_refusals[direction]` | `bad_direction_allowed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_refusals[empty_states]` | `empty_states_allowed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_refusals[nested_filter]` | `nested_filter_allowed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_refusals[satisfied]` | `unknown_satisfaction_allowed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_refusals[too_large]` | `query_limits_ignored` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_refusals[too_many_filters]` | `nested_filter_allowed` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_query_refusals[zero]` | `query_limits_ignored` |
| `prototypes/kernel/tests/test_f1_queries_links.py::test_remove_absent_link` | `absent_link_removal_silent` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_clean_and_boundary` | `replay_resets_fencing` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[all_deleted]` | `replay_always_clean` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[chain]` | `replay_always_clean` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[fields]` | `replay_always_clean` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[middle_deleted]` | `replay_always_clean` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[orphan_created]` | `replay_always_clean` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[orphan_noncreated]` | `replay_always_clean` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[payload]` | `replay_always_clean` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[sequence]` | `replay_always_clean` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[state]` | `replay_always_clean` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_detects_damage[tail_deleted]` | `replay_always_clean` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_memory_bound` | `replay_materialized` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_read_only_no_temp_residue` | `replay_writes` |
| `prototypes/kernel/tests/test_f1_replay.py::test_replay_repeatable_snapshot` | `snapshot_read_committed` |

The remaining **12 nodes** are successful typed-reference cases (8), field-
schema round trip (1), YAML/JSON document round trips (2) and PostgreSQL
EXPLAIN-plan inspection (1). They are tested in both interpreter runs but
are **not claimed mutation-proven**.

## Outstanding obligations

- §B: **24 ported, 2 retired by reference, 9 unresolved** out of 35. The
  unresolved assertions are actor/composite history filters, creation event
  identity retries, automatic lease release, actor-role registry enforcement,
  not_before deferral and nested JSON containment. Implementing these would
  add/change the current kernel public contract; no retirement is inferred.
- Main ledger: **34 unresolved rows**, plus unresolved portions of all **3
  SPLIT rows**. Other gaps include role provisioning/dry-run/mixed concurrency,
  library catalog-unregister cleanup, startup modes/library compatibility,
  automatic escalation, metrics, validation-result/warnings serialization,
  wildcard idempotency helper semantics and logging/retryability assertions.
- §A inventories **45 caller files**. **25** have no individually mapped
  assertion in the main table. A file with mapped rows is not thereby fully
  qualified: unnamed assertions in those files still need disposition. This
  ledger does not authorize deleting any whole caller file on that basis.

## Gate results

Checked against disposable PostgreSQL 15, CPython 3.14.8 and 3.11.15.
The commands below are repeated after the final artifact edit.

| Command (DSN supplied through REGISTA_TEST_DSN / positional argument) | Result |
| --- | --- |
| `.venv/bin/ruff check src/ tests/ tools/ prototypes/` | All checks passed |
| `.venv/bin/mypy` | No issues in 126 source files |
| `.venv/bin/pytest prototypes/kernel/tests -q` | 288 passed |
| `.venv/bin/python prototypes/kernel/test_mutations.py "$DSN"` | 69 passed, 0 failed |
| `.venv/bin/python prototypes/kernel/example_handoff.py "$DSN"` | Scenario passed |
| `.venv/bin/python prototypes/kernel/example_documents.py "$DSN"` | Scenario passed |
| `.venv/bin/pytest prototypes/kernel/test_scenarios.py -q` | 3 passed |
| `/tmp/regista-f1-python311/bin/python -m pytest prototypes/kernel/tests -q` | 288 passed |
| `env -u REGISTA_TEST_DSN .venv/bin/pytest prototypes/kernel/tests -q` | 288 skipped; explicit unset-DSN reason |

## Counts (row counts; distinct collected test nodes reported separately)

NEWLY PROTECTED: **20**, PORTED: **163**, RETIRED-BY-DESIGN: **37**, SPLIT: **3**, UNRESOLVED: **34**. Total main ledger rows: **257**; §A inventory rows: **45**.

Collected suite: **68 test functions, 288 parametrized nodes**.
Mutation proof: **71 killed mutants, 276 distinct nodes**.
These counts measure delivered protection; they do not erase unresolved rows.
