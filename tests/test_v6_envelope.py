"""P1.1 strict v6 schema, byte and signature conformance tests.

These cases are intentionally written as fail-then-pass guards: the pre-v6
classifier either had no v6 path or could fall through to a legacy schema.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from regista._jcs import canonicalize
from regista._signing import (
    build_signing_envelope_v6,
    canonicalize_v6_envelope,
    sign_v6_envelope,
)
from regista._verification import (
    Backend,
    EnvelopeVersion,
    EventRow,
    FailureReason,
    StaticKeyResolver,
    TrustedKeySource,
    V6EnvelopeError,
    classify_envelope_bytes,
    parse_v6_envelope_strict,
    verify_event_strict,
    verify_v6_signature,
)

VECTOR = Path(__file__).parent / "vectors" / "v6" / "v6-envelope-basic.json"
CASE = json.loads(VECTOR.read_text(encoding="utf-8"))
BASE = CASE["input"]["envelope_declaration_order"]
SEED = bytes.fromhex(CASE["input"]["signing_seed_hex"])
PUBLIC_KEY = bytes.fromhex(
    json.loads(
        (Path(__file__).parent / "vectors" / "v6" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )["test_public_key_hex"]
)


def _event_row(envelope: dict[str, Any] = BASE) -> EventRow:
    signed = sign_v6_envelope(envelope, SEED)
    workflow = envelope["workflow"]
    return EventRow.from_mapping(
        {
            "event_id": envelope["event_id"],
            "work_item_id": envelope["entity"]["id"],
            "entity_kind": envelope["entity"]["kind"],
            "entity_id": envelope["entity"]["id"],
            "actor_id": envelope["actor"]["principal_id"],
            "actor_kind": envelope["actor"]["kind"],
            "actor_metadata": envelope["actor"]["metadata"],
            "key_id": envelope["signing"]["key_id"],
            "event_seq": envelope["entity_seq"],
            "workflow_name": workflow["name"] if workflow is not None else None,
            "workflow_version": workflow["version"] if workflow is not None else None,
            "timestamp": envelope["occurred_at"].replace("Z", "+00:00"),
            "hash_alg": envelope["chain"]["hash_algorithm"],
            "on_behalf_of": None,
            "transition": envelope["transition"],
            "payload": envelope["payload"],
            "prev_event_hash": _digest_bytes(
                envelope["chain"]["previous_entity_event_hash"]
            ),
            "prev_global_event_hash": _digest_bytes(
                envelope["chain"]["previous_project_event_hash"]
            ),
            "global_seq": 11,
            "canonical_envelope": signed.canonical_envelope,
            "signature": signed.signature,
            "payload_canonical_hash": signed.payload_canonical_hash,
            "scheme_id": "ed25519",
        },
        backend=Backend.POSTGRES,
    )


def _digest_bytes(value: str | None) -> bytes | None:
    return bytes.fromhex(value.removeprefix("sha256:")) if value is not None else None


def _resolver(*, scheme_id: str | None = "ed25519") -> StaticKeyResolver:
    return StaticKeyResolver(
        material=PUBLIC_KEY,
        scheme_id=scheme_id,
        key_id=BASE["signing"]["key_id"],
        source=TrustedKeySource.PRINCIPAL_REGISTRY,
    )


def _raw(envelope: dict[str, Any]) -> bytes:
    return canonicalize(envelope)


def _assert_unknown(envelope: dict[str, Any]) -> None:
    raw = _raw(envelope)
    assert classify_envelope_bytes(raw) is EnvelopeVersion.UNKNOWN_SCHEMA
    with pytest.raises(V6EnvelopeError):
        parse_v6_envelope_strict(raw)


def _replace(path: tuple[str, ...], value: Any) -> dict[str, Any]:
    result = copy.deepcopy(BASE)
    target: dict[str, Any] = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return result


def test_valid_v6_is_classified_as_v6_and_round_trips_exact_bytes() -> None:
    raw = canonicalize_v6_envelope(BASE)
    assert classify_envelope_bytes(raw) is EnvelopeVersion.V6
    assert parse_v6_envelope_strict(raw) == json.loads(raw)


def test_v6_builder_rejects_mixed_or_partial_workflow_inputs() -> None:
    with pytest.raises(TypeError, match="cannot be combined"):
        build_signing_envelope_v6(**BASE, workflow_name="contradictory")

    partial = dict(BASE)
    del partial["workflow"]
    partial["workflow_name"] = "agent-notes"
    with pytest.raises(TypeError, match="requires all four"):
        build_signing_envelope_v6(**partial)


@pytest.mark.parametrize("field", sorted(BASE))
def test_missing_any_top_level_member_is_unknown_schema(field: str) -> None:
    mutated = copy.deepcopy(BASE)
    del mutated[field]
    _assert_unknown(mutated)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("entity", "extra"), True),
        (("actor", "extra"), True),
        (("signing", "extra"), True),
        (("authorization", "extra"), True),
        (("chain", "extra"), True),
        (("producer", "extra"), True),
        (("workflow", "extra"), True),
        (("authorization", "credentials"), [{"credential_id": BASE["event_id"]}]),
    ],
)
def test_unknown_nested_members_fail_closed(path: tuple[str, ...], value: Any) -> None:
    mutated = copy.deepcopy(BASE)
    if path[-1] == "extra":
        target = mutated
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    else:
        target = mutated
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    _assert_unknown(mutated)


def test_producer_is_required_and_its_keys_cannot_return_to_actor_metadata() -> None:
    missing = copy.deepcopy(BASE)
    del missing["producer"]
    _assert_unknown(missing)
    for key in ("harness", "harness_version", "model", "model_lineage"):
        _assert_unknown(_replace(("actor", "metadata"), {key: "duplicated"}))


def test_duplicate_keys_and_noncanonical_bytes_fail_before_signature_verification() -> None:
    raw = canonicalize_v6_envelope(BASE)
    duplicate = raw.replace(
        b'"type":"regista.event"',
        b'"type":"regista.event","type":"regista.event"',
        1,
    )
    with pytest.raises(V6EnvelopeError):
        parse_v6_envelope_strict(duplicate)
    assert classify_envelope_bytes(duplicate) is EnvelopeVersion.UNPARSEABLE

    noncanonical = b" " + raw
    assert classify_envelope_bytes(noncanonical) is EnvelopeVersion.UNCANONICAL
    with pytest.raises(V6EnvelopeError, match="fixed point"):
        parse_v6_envelope_strict(noncanonical)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("type",), "regista.event.v7"),
        (("version",), 7),
        (("version",), 6.0),
        (("project_instance_id",), "9F1C6A2E-3D5B-4C8A-9E07-1B2D3F4A5C6D"),
        (("entity_seq",), 1.0),
        (("entity", "kind"), []),
        (("actor", "kind"), "prompt"),
        (("actor", "kind"), []),
        (("actor", "principal_id"), "key:operator"),
        (("signing", "scheme_id"), "hmac-sha256"),
        (("signing", "key_binding_event_hash"), "aa"),
        (("authorization", "mode"), "delegated"),
        (("authorization", "mode"), []),
        (("workflow", "version"), True),
        (("occurred_at",), "2026-08-08T12:34:56.123456+00:00"),
        (("transition",), ""),
        (("chain", "hash_algorithm"), "sha-512"),
        (("chain", "hash_algorithm"), []),
        (("producer", "model"), None),
    ],
)
def test_degenerate_values_are_unknown_schema(path: tuple[str, ...], value: Any) -> None:
    if path == ("version",) and value == 6.0:
        raw = canonicalize_v6_envelope(BASE).replace(b'"version":6', b'"version":6.0', 1)
        assert classify_envelope_bytes(raw) is EnvelopeVersion.UNKNOWN_SCHEMA
        with pytest.raises(V6EnvelopeError):
            parse_v6_envelope_strict(raw)
        return
    _assert_unknown(_replace(path, value))


def test_authorization_mode_and_credential_consistency_is_structural() -> None:
    _assert_unknown(_replace(("authorization", "credentials"), [BASE["event_id"]]))
    delegated = _replace(
        ("authorization", "mode"),
        "delegated",
    )
    delegated["authorization"]["credentials"] = [
        {
            "credential_id": BASE["event_id"],
            "credential_hash": "sha256:" + "ab" * 32,
        }
    ]
    assert classify_envelope_bytes(_raw(delegated)) is EnvelopeVersion.V6
    too_many = copy.deepcopy(delegated)
    too_many["authorization"]["credentials"] *= 9
    _assert_unknown(too_many)


def test_numeric_depth_and_size_bounds_fail_closed() -> None:
    for value in (1e16, 1e21, 2**53, -(2**53)):
        unsafe_number = copy.deepcopy(BASE)
        unsafe_number["payload"] = {"unsafe": value}
        with pytest.raises((V6EnvelopeError, ValueError)):
            canonicalize_v6_envelope(unsafe_number)
        try:
            raw = _raw(unsafe_number)
        except ValueError:
            continue
        assert classify_envelope_bytes(raw) is EnvelopeVersion.UNKNOWN_SCHEMA
        with pytest.raises(V6EnvelopeError):
            parse_v6_envelope_strict(raw)

    nested: dict[str, Any] = {"leaf": True}
    for _ in range(40):
        nested = {"nested": nested}
    too_deep = copy.deepcopy(BASE)
    too_deep["payload"] = nested
    _assert_unknown(too_deep)

    oversized_payload = copy.deepcopy(BASE)
    oversized_payload["payload"] = {"blob": "x" * 1_050_000}
    _assert_unknown(oversized_payload)

    oversized_metadata = copy.deepcopy(BASE)
    oversized_metadata["actor"]["metadata"] = {"blob": "x" * 70_000}
    _assert_unknown(oversized_metadata)


def test_workflow_null_lifecycle_and_transition_rules_are_not_the_obsolete_rule() -> None:
    no_workflow = json.loads(
        (Path(__file__).parent / "vectors" / "v6" / "v6-envelope-no-model.json").read_text(
            encoding="utf-8"
        )
    )["input"]["envelope_declaration_order"]
    assert classify_envelope_bytes(canonicalize_v6_envelope(no_workflow)) is EnvelopeVersion.V6

    lifecycle_with_workflow = copy.deepcopy(BASE)
    lifecycle_with_workflow["entity"]["kind"] = "project"
    _assert_unknown(lifecycle_with_workflow)

    registration = copy.deepcopy(BASE)
    registration["transition"] = "workflow_registered"
    _assert_unknown(registration)


def test_bootstrap_null_key_binding_is_position_limited_without_external_state() -> None:
    for name in (
        "bootstrap-trust-genesis",
        "bootstrap-cutover-checkpoint",
        "bootstrap-project-initialized",
    ):
        case = json.loads(
            (Path(__file__).parent / "vectors" / "v6" / f"{name}.json").read_text(
                encoding="utf-8"
            )
        )
        env = case["input"]["envelope_declaration_order"]
        assert classify_envelope_bytes(canonicalize_v6_envelope(env)) is EnvelopeVersion.V6

    invalid = copy.deepcopy(BASE)
    invalid["signing"]["key_binding_event_hash"] = None
    _assert_unknown(invalid)


@pytest.mark.parametrize(
    "path",
    [
        ("type",),
        ("version",),
        ("project_instance_id",),
        ("trust_domain_id",),
        ("event_id",),
        ("entity", "kind"),
        ("entity", "id"),
        ("entity_seq",),
        ("actor", "principal_id"),
        ("actor", "kind"),
        ("actor", "metadata"),
        ("signing", "key_id"),
        ("signing", "scheme_id"),
        ("signing", "key_binding_event_hash"),
        ("authorization", "mode"),
        ("authorization", "credentials"),
        ("workflow", "name"),
        ("workflow", "version"),
        ("workflow", "definition_hash"),
        ("workflow", "registration_event_hash"),
        ("occurred_at",),
        ("transition",),
        ("payload",),
        ("chain", "hash_algorithm"),
        ("chain", "previous_entity_event_hash"),
        ("chain", "previous_project_event_hash"),
        ("producer", "harness"),
        ("producer", "harness_version"),
        ("producer", "model"),
        ("producer", "model_lineage"),
    ],
)
def test_every_signed_leaf_changes_production_signature_or_is_rejected(
    path: tuple[str, ...],
) -> None:
    mutated = copy.deepcopy(BASE)
    target: dict[str, Any] = mutated
    for key in path[:-1]:
        target = target[key]
    leaf = target[path[-1]]
    if path == ("authorization", "credentials"):
        target[path[-1]] = [
            {"credential_id": BASE["event_id"], "credential_hash": "sha256:" + "ab" * 32}
        ]
        mutated["authorization"]["mode"] = "delegated"
    elif path == ("workflow", "version"):
        target[path[-1]] = leaf + 1
    elif isinstance(leaf, int) and not isinstance(leaf, bool):
        target[path[-1]] = leaf + 1
    elif isinstance(leaf, str):
        target[path[-1]] = leaf + "-changed"
    elif leaf is None:
        target[path[-1]] = "sha256:" + "ab" * 32
    else:
        target[path[-1]] = {"changed": True}

    try:
        original = sign_v6_envelope(BASE, SEED)
        changed = sign_v6_envelope(mutated, SEED)
    except V6EnvelopeError:
        _assert_unknown(mutated)
        return
    assert changed.signature != original.signature
    assert changed.event_hash != original.event_hash
    assert changed.payload_canonical_hash != original.payload_canonical_hash
    assert not verify_v6_signature(
        changed.canonical_envelope,
        original.signature,
        PUBLIC_KEY,
    ).signature_valid


def test_v6_signature_verification_checks_the_signed_domain_and_external_pins() -> None:
    signed = sign_v6_envelope(BASE, SEED)
    result = verify_v6_signature(
        signed.canonical_envelope,
        signed.signature,
        PUBLIC_KEY,
        payload_canonical_hash=signed.payload_canonical_hash,
        expected_event_hash=signed.event_hash,
        expected_project_instance_id=BASE["project_instance_id"],
        expected_trust_domain_id=BASE["trust_domain_id"],
    )
    assert result.signature_and_hashes_valid
    assert result.unchecked == ()
    assert result.project_binding_valid is True
    assert result.trust_domain_binding_valid is True

    tampered = bytearray(signed.signature)
    tampered[0] ^= 1
    assert not verify_v6_signature(
        signed.canonical_envelope,
        bytes(tampered),
        PUBLIC_KEY,
        payload_canonical_hash=signed.payload_canonical_hash,
    ).signature_and_hashes_valid
    project_mismatch = verify_v6_signature(
        signed.canonical_envelope,
        signed.signature,
        PUBLIC_KEY,
        expected_project_instance_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    assert project_mismatch.signature_and_hashes_valid
    assert project_mismatch.project_binding_valid is False
    assert project_mismatch.unchecked == (
        "payload_canonical_hash",
        "event_hash",
        "trust_domain_binding",
    )
    project_mismatch_dict = project_mismatch.to_dict()
    assert project_mismatch_dict["signature_and_hashes_valid"] is True
    assert project_mismatch_dict["unchecked"] == list(project_mismatch.unchecked)
    assert "cryptographically_valid" not in project_mismatch_dict

    trust_mismatch = verify_v6_signature(
        signed.canonical_envelope,
        signed.signature,
        PUBLIC_KEY,
        expected_trust_domain_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    assert trust_mismatch.signature_and_hashes_valid
    assert trust_mismatch.trust_domain_binding_valid is False

    hash_mismatch = verify_v6_signature(
        signed.canonical_envelope,
        signed.signature,
        PUBLIC_KEY,
        payload_canonical_hash=b"\x00" * 32,
        expected_event_hash=b"\x00" * 32,
    )
    assert not hash_mismatch.signature_and_hashes_valid
    assert hash_mismatch.payload_canonical_hash_valid is False
    assert hash_mismatch.event_hash_valid is False


def test_legacy_result_surface_reconciles_v6_row_fields_without_claiming_external_bindings(
) -> None:
    row = _event_row()
    resolver = _resolver()
    result = verify_event_strict(row, keys=resolver)
    assert result.envelope_version is EnvelopeVersion.V6
    assert result.signature_valid
    assert result.row_reconciled
    assert result.mismatched_fields == ()
    assert "scheme_id" in result.authenticated_fields
    assert result.unsigned_fields == frozenset(
        {"global_seq", "on_behalf_of", "work_item_id"}
    )
    assert not result.ok

    tampered = dataclasses.replace(row, payload={"changed": True})
    changed = verify_event_strict(tampered, keys=resolver)
    assert changed.applicability.value == "invalid"
    assert "payload" in changed.mismatched_field_names

    tampered_hash = dataclasses.replace(row, payload_canonical_hash=b"\x00" * 32)
    hash_result = verify_event_strict(tampered_hash, keys=resolver)
    assert hash_result.reasons[0].value == "canonical_hash_mismatch"
    assert hash_result.authenticated_fields == frozenset()


def test_v6_raw_public_key_uses_the_signed_scheme_not_the_row_as_fallback() -> None:
    result = verify_event_strict(_event_row(), keys=_resolver(scheme_id=None))
    assert result.signature_valid
    assert result.row_reconciled
    assert result.scheme_id == "ed25519"


def test_v6_null_workflow_reconciles_against_null_projection_columns() -> None:
    envelope = json.loads(
        (Path(__file__).parent / "vectors" / "v6" / "v6-envelope-no-model.json").read_text(
            encoding="utf-8"
        )
    )["input"]["envelope_declaration_order"]
    result = verify_event_strict(_event_row(envelope), keys=_resolver())
    assert result.signature_valid
    assert result.row_reconciled
    assert "workflow_name" in result.authenticated_fields
    assert "workflow_version" in result.authenticated_fields


def test_v6_uncanonical_row_has_a_distinct_failure_reason() -> None:
    row = _event_row()
    result = verify_event_strict(
        dataclasses.replace(row, canonical_envelope=b" " + (row.canonical_envelope or b"")),
        keys=_resolver(),
    )
    assert result.envelope_version is EnvelopeVersion.UNCANONICAL
    assert result.reasons == (FailureReason.ENVELOPE_UNCANONICAL,)
    assert not result.signature_valid


def test_v6_missing_payload_hash_fails_closed() -> None:
    result = verify_event_strict(
        dataclasses.replace(_event_row(), payload_canonical_hash=None),
        keys=_resolver(),
    )
    assert result.signature_valid
    assert result.applicability.value == "invalid"
    assert result.reasons[0].value == "canonical_hash_mismatch"
    assert result.authenticated_fields == frozenset()


@pytest.mark.parametrize(
    ("changes", "mismatch"),
    [
        ({"event_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}, "event_id"),
        ({"entity_kind": "project"}, "entity_kind"),
        (
            {
                "entity_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "work_item_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            },
            "entity_id",
        ),
        ({"event_seq": BASE["entity_seq"] + 1}, "entity_seq"),
        ({"actor_id": "agent:changed"}, "actor_id"),
        ({"actor_kind": "human"}, "actor_kind"),
        ({"actor_metadata": {"changed": True}}, "actor_metadata"),
        ({"key_id": "pk_changed"}, "key_id"),
        ({"row_scheme_id": "hmac-sha256"}, "scheme_id"),
        ({"workflow_name": "changed"}, "workflow_name"),
        ({"workflow_version": BASE["workflow"]["version"] + 1}, "workflow_version"),
        ({"timestamp": "2026-08-09T12:34:56.123456+00:00"}, "timestamp"),
        ({"transition": "changed"}, "transition"),
        ({"payload": {"changed": True}}, "payload"),
        ({"hash_alg": "sha-512"}, "hash_alg"),
        ({"prev_event_hash": b"\x00" * 32}, "prev_event_hash"),
        ({"prev_global_event_hash": b"\x00" * 32}, "prev_global_event_hash"),
        ({"work_item_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}, "work_item_id!=entity_id"),
    ],
)
def test_each_v6_row_projection_rewrite_is_named(
    changes: dict[str, Any], mismatch: str,
) -> None:
    row = dataclasses.replace(_event_row(), **changes)
    result = verify_event_strict(row, keys=_resolver())
    assert result.signature_valid
    assert result.applicability.value == "invalid"
    assert mismatch in result.mismatched_field_names


def test_invalid_v6_signature_authenticates_no_row_columns() -> None:
    row = _event_row()
    invalid = dataclasses.replace(row, signature=b"\x00" * 64)
    result = verify_event_strict(invalid, keys=_resolver())
    assert not result.signature_valid
    assert result.authenticated_fields == frozenset()
    assert result.unsigned_fields == frozenset(
        {
            "actor_id",
            "actor_kind",
            "actor_metadata",
            "entity_id",
            "entity_kind",
            "event_id",
            "event_seq",
            "global_seq",
            "hash_alg",
            "key_id",
            "on_behalf_of",
            "payload",
            "prev_event_hash",
            "prev_global_event_hash",
            "scheme_id",
            "timestamp",
            "transition",
            "work_item_id",
            "workflow_name",
            "workflow_version",
        }
    )


def test_v6_row_only_fields_remain_explicitly_unsigned() -> None:
    row = dataclasses.replace(
        _event_row(),
        global_seq=999_999,
        on_behalf_of={"principal_id": "human:untrusted-assertion"},
    )
    result = verify_event_strict(row, keys=_resolver())
    assert result.signature_valid
    assert result.row_reconciled
    assert {"global_seq", "on_behalf_of", "work_item_id"} <= result.unsigned_fields
