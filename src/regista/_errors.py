from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    WORKFLOW_NOT_REGISTERED = "WORKFLOW_NOT_REGISTERED"
    WORK_ITEM_TYPE_NOT_DECLARED = "WORK_ITEM_TYPE_NOT_DECLARED"
    CUSTOM_FIELD_VIOLATION = "CUSTOM_FIELD_VIOLATION"
    INVALID_TRANSITION = "INVALID_TRANSITION"
    ROLE_NOT_PERMITTED = "ROLE_NOT_PERMITTED"
    CLAIM_CONTESTED = "CLAIM_CONTESTED"
    CLAIM_LOST = "CLAIM_LOST"
    CLAIM_NOT_FOUND = "CLAIM_NOT_FOUND"
    NOT_BEFORE_FUTURE = "NOT_BEFORE_FUTURE"
    CONCURRENT_MODIFICATION = "CONCURRENT_MODIFICATION"
    IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD = "IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD"
    EVENT_ID_GLOBAL_COLLISION = "EVENT_ID_GLOBAL_COLLISION"
    UNKNOWN_KEY_ID = "UNKNOWN_KEY_ID"
    REVOKED_KEY_ID = "REVOKED_KEY_ID"
    WORKFLOW_VERSION_CONFLICT = "WORKFLOW_VERSION_CONFLICT"
    WORKFLOW_VALIDATION_FAILED = "WORKFLOW_VALIDATION_FAILED"
    WORKFLOW_SEMANTIC_ERROR = "WORKFLOW_SEMANTIC_ERROR"
    MIGRATION_REQUIRED = "MIGRATION_REQUIRED"
    MIGRATION_DRIFT = "MIGRATION_DRIFT"
    WORKFLOW_VERSION_INCOMPATIBLE = "WORKFLOW_VERSION_INCOMPATIBLE"
    DB_NOT_FOUND = "DB_NOT_FOUND"
    LINK_TYPE_NOT_ALLOWED = "LINK_TYPE_NOT_ALLOWED"
    LINK_TARGET_NOT_FOUND = "LINK_TARGET_NOT_FOUND"
    LINK_CROSS_PROJECT = "LINK_CROSS_PROJECT"
    LINK_NOT_FOUND = "LINK_NOT_FOUND"
    WORK_ITEM_NOT_FOUND = "WORK_ITEM_NOT_FOUND"
    TRANSITION_VIA_APPEND_BLOCKED = "TRANSITION_VIA_APPEND_BLOCKED"
    REPLAY_HALTED = "REPLAY_HALTED"
    VALIDATOR_FAILED = "VALIDATOR_FAILED"
    VALIDATOR_NOT_REGISTERED = "VALIDATOR_NOT_REGISTERED"
    HOOK_NOT_FOUND = "HOOK_NOT_FOUND"
    INVALID_FILTER = "INVALID_FILTER"
    INVALID_ACTOR_KIND = "INVALID_ACTOR_KIND"
    INVALID_PRINCIPAL_KIND = "INVALID_PRINCIPAL_KIND"
    INVALID_MODEL_LINEAGE = "INVALID_MODEL_LINEAGE"
    ACTOR_ROLE_NOT_AUTHORIZED = "ACTOR_ROLE_NOT_AUTHORIZED"
    ACTOR_ROLE_NOT_REGISTERED = "ACTOR_ROLE_NOT_REGISTERED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    BUNDLE_UNVERIFIABLE = "BUNDLE_UNVERIFIABLE"
    BUNDLE_WRITE_CORRUPT = "BUNDLE_WRITE_CORRUPT"
    WORKFLOW_COMPOSE_ERROR = "WORKFLOW_COMPOSE_ERROR"
    RECURRENCE_RULE_NOT_FOUND = "RECURRENCE_RULE_NOT_FOUND"
    RECURRENCE_RULE_EXHAUSTED = "RECURRENCE_RULE_EXHAUSTED"
    RECURRENCE_SCHEDULE_INVALID = "RECURRENCE_SCHEDULE_INVALID"
    RECURRENCE_TEMPLATE_INVALID = "RECURRENCE_TEMPLATE_INVALID"
    LIBRARY_IS_SOLE_SIGNER = "LIBRARY_IS_SOLE_SIGNER"
    KEY_LOAD_ERROR = "KEY_LOAD_ERROR"
    INVALID_KEY_ROLE = "INVALID_KEY_ROLE"
    KEY_ROLE_NOT_PERMITTED = "KEY_ROLE_NOT_PERMITTED"
    SIGNING_SCHEME_NOT_FOUND = "SIGNING_SCHEME_NOT_FOUND"
    DELEGATION_CHAIN_EXPIRED = "DELEGATION_CHAIN_EXPIRED"
    RESERVED_TRANSITION_NAME = "RESERVED_TRANSITION_NAME"
    WITNESS_NOT_FOUND = "WITNESS_NOT_FOUND"
    WITNESS_DELIVERY_FAILED = "WITNESS_DELIVERY_FAILED"
    WITNESS_PAUSED = "WITNESS_PAUSED"
    PRIVILEGED_TRANSITION_REQUIRED = "PRIVILEGED_TRANSITION_REQUIRED"
    HOOK_NOT_CLAIMED_BY_CALLER = "HOOK_NOT_CLAIMED_BY_CALLER"
    SECRET_RESOLVE_FAILED = "SECRET_RESOLVE_FAILED"
    SECRET_WRITE_UNSUPPORTED = "SECRET_WRITE_UNSUPPORTED"
    SECRET_WRITE_EXTERNAL = "SECRET_WRITE_EXTERNAL"
    SECRET_ALREADY_EXISTS = "SECRET_ALREADY_EXISTS"
    PRINCIPAL_KEY_NOT_FOUND = "PRINCIPAL_KEY_NOT_FOUND"
    PRINCIPAL_KEY_ALREADY_EXISTS = "PRINCIPAL_KEY_ALREADY_EXISTS"
    ACTOR_SIGNER_MISMATCH = "ACTOR_SIGNER_MISMATCH"
    UNREGISTERED_SIGNER = "UNREGISTERED_SIGNER"
    SPEC_SCHEMA_VERSION_UNKNOWN = "SPEC_SCHEMA_VERSION_UNKNOWN"
    ENCRYPTION_SCHEME_NOT_FOUND = "ENCRYPTION_SCHEME_NOT_FOUND"
    DECRYPTION_FAILED = "DECRYPTION_FAILED"
    ENCRYPTION_KEY_NOT_RESOLVED = "ENCRYPTION_KEY_NOT_RESOLVED"
    LOAD_BEARING_FIELD_MISSING = "LOAD_BEARING_FIELD_MISSING"
    GENESIS_GATE_NOT_PASSED = "GENESIS_GATE_NOT_PASSED"
    GENESIS_REQUIRED = "GENESIS_REQUIRED"
    GENESIS_ALREADY_WRITTEN = "GENESIS_ALREADY_WRITTEN"
    GENESIS_SENTINEL_MISSING = "GENESIS_SENTINEL_MISSING"
    GENESIS_INVALID = "GENESIS_INVALID"
    GENESIS_RECOVERY_FAILED = "GENESIS_RECOVERY_FAILED"
    V6_EPOCH_OPEN = "V6_EPOCH_OPEN"
    # Trust-domain genesis (P2.1, TRUST-DOMAIN.md §3). Each error carries a
    # machine-readable `reason` in detail naming the exact rule violated.
    TRUST_GENESIS_SCHEMA_INVALID = "TRUST_GENESIS_SCHEMA_INVALID"
    TRUST_GENESIS_GOVERNANCE_INVALID = "TRUST_GENESIS_GOVERNANCE_INVALID"
    TRUST_GENESIS_DERIVATION_MISMATCH = "TRUST_GENESIS_DERIVATION_MISMATCH"
    TRUST_GENESIS_SIGNATURE_INVALID = "TRUST_GENESIS_SIGNATURE_INVALID"
    TRUST_GOVERNANCE_TRANSITION_INVALID = "TRUST_GOVERNANCE_TRANSITION_INVALID"
    # Canonical principal identity (P2.3, TRUST-DOMAIN.md §2). Each error carries a
    # machine-readable `reason` in detail naming the exact rule violated.
    # NOT_CANONICAL is kept distinct from UNGRAMMATICAL so a legacy bare name (§2.4
    # convention 2) gets a refusal that points at the §2.5 alias path, while junk does not.
    PRINCIPAL_ID_UNGRAMMATICAL = "PRINCIPAL_ID_UNGRAMMATICAL"
    PRINCIPAL_ID_NOT_CANONICAL = "PRINCIPAL_ID_NOT_CANONICAL"
    PRINCIPAL_ALIAS_INVALID = "PRINCIPAL_ALIAS_INVALID"
    PRINCIPAL_MAPPING_INVALID = "PRINCIPAL_MAPPING_INVALID"
    # Trust-domain log and the principal_keys projection (P2.2, TRUST-DOMAIN.md §5).
    # Each error carries a machine-readable `reason` in detail naming the exact
    # rule violated, so a caller asserts the named failure rather than a message.
    TRUST_LOG_PAYLOAD_INVALID = "TRUST_LOG_PAYLOAD_INVALID"
    TRUST_LOG_AUTHORITY_INVALID = "TRUST_LOG_AUTHORITY_INVALID"
    TRUST_LOG_BOOTSTRAP_NOT_PERMITTED = "TRUST_LOG_BOOTSTRAP_NOT_PERMITTED"
    # §5.9 rule 2: principal_keys is a projection. A write that is not driven by a
    # signed trust-log event is refused by name, not by review.
    PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED = "PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED"
    # §5.9 rule 3: a rebuild-into-temp diff that finds any divergence.
    PRINCIPAL_KEYS_PROJECTION_DIVERGED = "PRINCIPAL_KEYS_PROJECTION_DIVERGED"
    # D-7 / §7 CUT marker: witness lifecycle is not a 0.6.0 trust mechanism, so the
    # witness key-lifecycle write paths refuse instead of silently bypassing §5.9.
    WITNESS_LIFECYCLE_CUT = "WITNESS_LIFECYCLE_CUT"
    # The post-genesis v6 ordinary-event writer (P1.7). Each error carries a
    # machine-readable `reason` or the referent it could not resolve, so a caller
    # asserts the named refusal rather than message text.
    #
    # KEY_BINDING_UNRESOLVED: no PRECEDING project key-binding anchor accepts this
    # key for this principal (TRUST-DOMAIN.md §5.8/§5.11). Deliberately not a
    # fallback to the principal_keys projection — that is the S6 defect.
    KEY_BINDING_UNRESOLVED = "KEY_BINDING_UNRESOLVED"
    # Admission gate 1 (P1.7 owns it): the event names a workflow whose signed
    # workflow_registered event cannot be resolved on this project's chain, or was
    # retired before this position. A workflow_registry ROW is not a registration.
    WORKFLOW_REGISTRATION_UNRESOLVED = "WORKFLOW_REGISTRATION_UNRESOLVED"
    # Admission gate 2 (P1.7 owns it): the producer block contradicts the accepted
    # key's scopes (§5.8), the closed lineage registry, or a supplied producer
    # policy (V6-ENVELOPE.md §1.8). An UNSUPPLIED policy is never this error — it
    # is reported `policy_not_supplied`, which is an explicit state, not a skip.
    PRODUCER_NOT_AUTHORIZED = "PRODUCER_NOT_AUTHORIZED"
    # The writer refused to sign, or signed bytes that did not verify under their
    # own key. Distinct from GENESIS_INVALID so a genesis defect and an ordinary
    # append defect are never confused in a report.
    V6_ENVELOPE_INVALID = "V6_ENVELOPE_INVALID"
    # A v6 entity chain may not skip a link: the predecessor at entity_seq - 1 must
    # exist and be signed, or the append is refused rather than writing a fork.
    V6_CHAIN_LINK_MISSING = "V6_CHAIN_LINK_MISSING"
    # The presented material stopped presenting an event it had already presented,
    # part-way through one verification pass (`_v6_referents.StoreReferents` indexes
    # the store, then re-reads an envelope when a verdict needs its payload). Raised
    # rather than answered with an empty payload: material that changes under the
    # pass reading it cannot be reported as evidence, and an absence dressed as a
    # fact is the one outcome §5.11 exists to keep out of verdicts.
    MATERIAL_CHANGED_UNDER_VERIFICATION = "MATERIAL_CHANGED_UNDER_VERIFICATION"
    # The two project-local acceptance transitions _trust_log.DEFERRED_TRANSITIONS
    # assigns to P1.7 (TRUST-DOMAIN.md §5.8). Both carry a machine-readable `reason`.
    #
    # A malformed regista.key-acceptance/v1 or key-acceptance-revocation/v1 payload.
    # Kept distinct from TRUST_LOG_PAYLOAD_INVALID because these are *project-local*
    # events, not trust-log ones, and conflating them would hide which chain is at
    # fault.
    KEY_ACCEPTANCE_PAYLOAD_INVALID = "KEY_ACCEPTANCE_PAYLOAD_INVALID"
    # Every project-local acceptance of this key has been revoked. §5.10 step 4's
    # reason code, spelled exactly as the spec spells it, and deliberately NOT
    # KEY_BINDING_UNRESOLVED: "revoked" and "never accepted" are different facts and
    # an operator's response to each is different.
    KEY_ACCEPTANCE_REVOKED = "KEY_ACCEPTANCE_REVOKED"

    # The in-memory v6 parity boundary (WI-287, SUITE-RECONCILIATION.md §2.3(a)).
    # Locking, rollback, persistence and concurrency remain Postgres-only, and the
    # in-memory backend's statement grammar is closed. Reaching for any of those
    # through the in-memory backend is this refusal, never a fake that would let an
    # in-memory pass satisfy a Postgres-gated acceptance criterion.
    PARITY_BOUNDARY_POSTGRES_ONLY = "PARITY_BOUNDARY_POSTGRES_ONLY"


class RegistaError(Exception):
    def __init__(self, code: ErrorCode, message: str, detail: dict[str, Any] | None = None) -> None:
        self.code = code
        self.message = message
        self.detail = detail
        super().__init__(str(self))

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"
