from __future__ import annotations

from regista._errors import ErrorCode

_STATUS_MAP: dict[str, int] = {
    ErrorCode.WORK_ITEM_NOT_FOUND: 404,
    ErrorCode.WORKFLOW_NOT_REGISTERED: 404,
    ErrorCode.CLAIM_NOT_FOUND: 404,
    ErrorCode.HOOK_NOT_FOUND: 404,
    ErrorCode.LINK_NOT_FOUND: 404,
    ErrorCode.LINK_TARGET_NOT_FOUND: 404,
    ErrorCode.ACTOR_ROLE_NOT_REGISTERED: 404,
    ErrorCode.RECURRENCE_RULE_NOT_FOUND: 404,
    ErrorCode.INVALID_TRANSITION: 400,
    ErrorCode.INVALID_FILTER: 400,
    ErrorCode.INVALID_ARGUMENT: 400,
    # The export would exceed the offline verifier's size cap (WI-240): the
    # remedy is client-side (chunk the range with since/until), so 400.
    ErrorCode.BUNDLE_UNVERIFIABLE: 400,
    # The written artifact failed its own hash — a server-side integrity
    # failure, not a client error (WI-240 review F6).
    ErrorCode.BUNDLE_WRITE_CORRUPT: 500,
    ErrorCode.INVALID_ACTOR_KIND: 400,
    ErrorCode.INVALID_PRINCIPAL_KIND: 400,
    ErrorCode.INVALID_MODEL_LINEAGE: 400,
    ErrorCode.WORK_ITEM_TYPE_NOT_DECLARED: 400,
    ErrorCode.CUSTOM_FIELD_VIOLATION: 400,
    ErrorCode.TRANSITION_VIA_APPEND_BLOCKED: 400,
    ErrorCode.WORKFLOW_VALIDATION_FAILED: 400,
    ErrorCode.WORKFLOW_SEMANTIC_ERROR: 400,
    ErrorCode.LINK_TYPE_NOT_ALLOWED: 400,
    ErrorCode.LINK_CROSS_PROJECT: 400,
    ErrorCode.NOT_BEFORE_FUTURE: 400,
    ErrorCode.WORKFLOW_COMPOSE_ERROR: 400,
    ErrorCode.RECURRENCE_SCHEDULE_INVALID: 400,
    ErrorCode.RECURRENCE_TEMPLATE_INVALID: 400,
    ErrorCode.RECURRENCE_RULE_EXHAUSTED: 400,
    ErrorCode.LIBRARY_IS_SOLE_SIGNER: 400,
    ErrorCode.WITNESS_NOT_FOUND: 404,
    ErrorCode.WITNESS_DELIVERY_FAILED: 500,
    ErrorCode.WITNESS_PAUSED: 409,
    ErrorCode.EVENT_ID_GLOBAL_COLLISION: 409,
    ErrorCode.MIGRATION_DRIFT: 500,
    ErrorCode.KEY_LOAD_ERROR: 500,
    ErrorCode.INVALID_KEY_ROLE: 400,
    ErrorCode.KEY_ROLE_NOT_PERMITTED: 403,
    ErrorCode.SIGNING_SCHEME_NOT_FOUND: 400,
    ErrorCode.DELEGATION_CHAIN_EXPIRED: 400,
    ErrorCode.RESERVED_TRANSITION_NAME: 400,
    ErrorCode.PRIVILEGED_TRANSITION_REQUIRED: 403,
    ErrorCode.ROLE_NOT_PERMITTED: 403,
    ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED: 403,
    ErrorCode.CLAIM_CONTESTED: 409,
    ErrorCode.CLAIM_LOST: 409,
    ErrorCode.CONCURRENT_MODIFICATION: 409,
    ErrorCode.WORKFLOW_VERSION_CONFLICT: 409,
    ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD: 409,
    ErrorCode.UNKNOWN_KEY_ID: 500,
    ErrorCode.REVOKED_KEY_ID: 500,
    ErrorCode.MIGRATION_REQUIRED: 500,
    ErrorCode.WORKFLOW_VERSION_INCOMPATIBLE: 500,
    ErrorCode.REPLAY_HALTED: 500,
    ErrorCode.DB_NOT_FOUND: 500,
    ErrorCode.VALIDATOR_FAILED: 500,
    ErrorCode.VALIDATOR_NOT_REGISTERED: 500,
    ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER: 409,
    ErrorCode.SECRET_RESOLVE_FAILED: 500,
    ErrorCode.SECRET_WRITE_UNSUPPORTED: 400,
    ErrorCode.SECRET_WRITE_EXTERNAL: 409,
    ErrorCode.SECRET_ALREADY_EXISTS: 409,
    ErrorCode.PRINCIPAL_KEY_NOT_FOUND: 404,
    ErrorCode.PRINCIPAL_KEY_ALREADY_EXISTS: 409,
    ErrorCode.ACTOR_SIGNER_MISMATCH: 403,
    ErrorCode.UNREGISTERED_SIGNER: 403,
    ErrorCode.SPEC_SCHEMA_VERSION_UNKNOWN: 400,
    ErrorCode.ENCRYPTION_SCHEME_NOT_FOUND: 400,
    ErrorCode.DECRYPTION_FAILED: 400,
    ErrorCode.ENCRYPTION_KEY_NOT_RESOLVED: 500,
    ErrorCode.LOAD_BEARING_FIELD_MISSING: 400,
    ErrorCode.GENESIS_GATE_NOT_PASSED: 409,
    ErrorCode.GENESIS_REQUIRED: 409,
    ErrorCode.GENESIS_ALREADY_WRITTEN: 409,
    ErrorCode.GENESIS_SENTINEL_MISSING: 500,
    ErrorCode.GENESIS_INVALID: 400,
    ErrorCode.GENESIS_RECOVERY_FAILED: 500,
    ErrorCode.V6_EPOCH_OPEN: 409,
    # Trust-domain genesis (P2.1). These verbs are offline-only (the CLI never
    # contacts a database and the sidecar exposes no trust endpoint), so the
    # mappings exist to satisfy total coverage: every rejection is a defect in
    # the submitted document/transition, hence 400.
    ErrorCode.TRUST_GENESIS_SCHEMA_INVALID: 400,
    ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID: 400,
    ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH: 400,
    ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID: 400,
    ErrorCode.TRUST_GOVERNANCE_TRANSITION_INVALID: 400,
    # Canonical principal identity (P2.3, TRUST-DOMAIN.md §2). Every one of these is a
    # defect in the *submitted* identifier or payload, never a server fault, hence 400.
    ErrorCode.PRINCIPAL_ID_UNGRAMMATICAL: 400,
    ErrorCode.PRINCIPAL_ID_NOT_CANONICAL: 400,
    ErrorCode.PRINCIPAL_ALIAS_INVALID: 400,
    ErrorCode.PRINCIPAL_MAPPING_INVALID: 400,
    # Trust-domain log and the principal_keys projection (P2.2, TRUST-DOMAIN.md §5).
    # A malformed payload or a failed authority check is a defect in what was
    # submitted, hence 400.
    ErrorCode.TRUST_LOG_PAYLOAD_INVALID: 400,
    ErrorCode.TRUST_LOG_AUTHORITY_INVALID: 403,
    ErrorCode.TRUST_LOG_BOOTSTRAP_NOT_PERMITTED: 400,
    # 503: the trust-log store is unreachable or the target schema is not a trust
    # log — an infrastructure/config condition the caller cannot fix by reformatting.
    ErrorCode.TRUST_LOG_STORE_UNAVAILABLE: 503,
    # 409: the caller asked for a write that this deployment structurally does not
    # perform any more (§5.9 rule 2). Not 400 — the request is well-formed; not 500
    # — nothing is broken. The state of the system conflicts with the request.
    ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED: 409,
    # 500: the store disagrees with its own event log. That is a server-side
    # integrity fault, not a client error.
    ErrorCode.PRINCIPAL_KEYS_PROJECTION_DIVERGED: 500,
    # 409, matching the projection-write refusal above and for the same reason:
    # the request is well-formed and nothing is broken, but this deployment
    # structurally does not perform the operation. 501 would read better as
    # "not implemented", but the sidecar's status map is deliberately restricted
    # to a small sanctioned set (tests/sidecar/test_sidecar.py
    # ::test_status_map_values_are_valid_http_codes) and 501 is not in it.
    ErrorCode.WITNESS_LIFECYCLE_CUT: 409,
    # The post-genesis v6 writer (P1.7). The split here is deliberate: an
    # unresolvable *referent* is a conflict with the store's state, while a
    # contradiction inside what the caller submitted is a client defect.
    #
    # 409: the request is well-formed, but the project chain does not (yet) contain
    # the acceptance or the workflow registration it names. The caller's fix is to
    # append the missing anchor/registration, not to reformat the request.
    ErrorCode.KEY_BINDING_UNRESOLVED: 409,
    ErrorCode.WORKFLOW_REGISTRATION_UNRESOLVED: 409,
    # 403: an authorization decision. The producer block contradicts the scopes the
    # accepted key holds, the closed lineage registry, or a pinned producer policy.
    # Not 400 — nothing is malformed; the caller is not permitted.
    ErrorCode.PRODUCER_NOT_AUTHORIZED: 403,
    # 400: the submitted envelope does not satisfy the v6 contract.
    ErrorCode.V6_ENVELOPE_INVALID: 400,
    # 500: the store's own entity chain is missing a link the writer must build on.
    # That is a server-side integrity fault, not something the caller can fix.
    ErrorCode.V6_CHAIN_LINK_MISSING: 500,
    # 500: the material stopped presenting an event it had already presented, part-way
    # through one verification pass. Server-side, and deliberately not 409: a conflict
    # invites a retry, and a store that changes under the pass reading it is a fault to
    # investigate rather than a race to re-run.
    ErrorCode.MATERIAL_CHANGED_UNDER_VERIFICATION: 500,
    # 400: a malformed project-local acceptance payload is a defect in what was
    # submitted, matching TRUST_LOG_PAYLOAD_INVALID's reasoning for the trust log.
    ErrorCode.KEY_ACCEPTANCE_PAYLOAD_INVALID: 400,
    # 403: the key's acceptance was revoked. An authorization decision, not a
    # missing referent — which is why it is not 409 like KEY_BINDING_UNRESOLVED.
    ErrorCode.KEY_ACCEPTANCE_REVOKED: 403,
    ErrorCode.ACTION_DELEGATION_INVALID: 403,
    ErrorCode.ACTION_DELEGATION_CREDENTIAL_CONFLICT: 409,
    # 500: the in-memory v6 parity boundary (WI-287). A sidecar never runs on the
    # in-memory backend, so reaching this through HTTP means the deployment is
    # misconfigured — a server fault the caller cannot fix by reformatting, and
    # emphatically not a 409 the caller might retry into existence.
    ErrorCode.PARITY_BOUNDARY_POSTGRES_ONLY: 500,
}


def error_to_status(code: ErrorCode) -> int:
    return _STATUS_MAP.get(code, 500)
