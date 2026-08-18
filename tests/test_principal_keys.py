"""``principal_keys`` applier tests.

Rewritten for P2.2. These used to call ``register_principal_key`` /
``rotate_principal_key`` / ``revoke_principal_key``, which no longer exist:
``TRUST-DOMAIN.md`` §5.9 rule 2 made the mutators private, event-driven appliers
requiring a ``source_event_hash``. Every assertion from the pre-P2.2 version is
retained; the calls now go through the appliers, and the projection-provenance
columns are asserted on top.

``tests/test_trust_projection.py`` holds the §9 criteria (12, 13, 16, 17, 18);
this module is the unit-level behaviour of the appliers themselves.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._principal_keys import (
    _apply_enrollment_projection,
    _apply_revocation_projection,
    _apply_rotation_projection,
    get_active_key,
    list_principal_keys,
    verify_principal_binding,
)

_T0 = datetime(2026, 8, 20, 0, 0, 0, tzinfo=UTC)


def _hash(tag: str) -> str:
    """A distinct, well-formed source_event_hash per call site."""
    return "sha256:" + hashlib.sha256(tag.encode()).hexdigest()


#: Sentinel so `source=""` reaches the applier instead of being treated as "unset".
#: `source or _hash(...)` silently swallowed the empty string and made the
#: refusal tests pass vacuously.
_UNSET = object()


def _generate_ed25519_keypair():
    try:
        import nacl.signing
        sk = nacl.signing.SigningKey.generate()
        return sk, sk.verify_key
    except ImportError:
        import os
        fake_priv = os.urandom(32)
        fake_pub = os.urandom(32)
        return fake_priv, fake_pub


@pytest.fixture
def principal_keys(regista_instance):
    return regista_instance


def _enroll(sub, principal_id, public_key, scheme="ed25519", *, key_id=None,
            registered_by="system", source=_UNSET, valid_from=_T0, valid_to=None,
            trust_domain_id=None):
    with sub._mgr.transaction() as conn:
        return _apply_enrollment_projection(
            conn,
            principal_id,
            public_key,
            scheme,
            source_event_hash=(
                _hash(f"enrol:{principal_id}:{key_id}")
                if source is _UNSET else source
            ),
            valid_from=valid_from,
            valid_to=valid_to,
            registered_at=valid_from,
            key_id=key_id,
            registered_by=registered_by,
            trust_domain_id=trust_domain_id,
        )


def _rotate(sub, principal_id, public_key, scheme="ed25519", *, key_id=None,
            registered_by="system", source=_UNSET, valid_from=_T0):
    with sub._mgr.transaction() as conn:
        return _apply_rotation_projection(
            conn,
            principal_id,
            public_key,
            scheme,
            source_event_hash=(
                _hash(f"rotate:{principal_id}:{key_id}")
                if source is _UNSET else source
            ),
            valid_from=valid_from,
            registered_at=valid_from,
            key_id=key_id,
            registered_by=registered_by,
        )


def _revoke(sub, principal_id, key_id, *, reason="unspecified", source=_UNSET,
            revoked_at=_T0):
    with sub._mgr.transaction() as conn:
        return _apply_revocation_projection(
            conn,
            principal_id,
            key_id,
            source_event_hash=(
                _hash(f"revoke:{principal_id}:{key_id}")
                if source is _UNSET else source
            ),
            revoked_at=revoked_at,
            reason=reason,
        )


class TestAppliersRequireASourceEvent:
    """§5.9 rule 2: there is no write path that is not driven by a signed event."""

    def test_enrollment_without_source_event_hash_is_refused(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        with pytest.raises(RegistaError) as exc_info:
            _enroll(principal_keys, "agent:no-source", bytes(vk), source="")
        assert exc_info.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
        assert exc_info.value.detail["reason"] == "source_event_hash_required"

    def test_rotation_without_source_event_hash_is_refused(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        with pytest.raises(RegistaError) as exc_info:
            _rotate(principal_keys, "agent:no-source-rot", bytes(vk), source="   ")
        assert exc_info.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED

    def test_revocation_without_source_event_hash_is_refused(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry = _enroll(principal_keys, "agent:no-source-rev", bytes(vk))
        with pytest.raises(RegistaError) as exc_info:
            _revoke(principal_keys, "agent:no-source-rev", entry.key_id, source="")
        assert exc_info.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED

    def test_applier_refuses_an_arbitrary_table(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        with pytest.raises(RegistaError) as exc_info:
            with principal_keys._mgr.transaction() as conn:
                _apply_enrollment_projection(
                    conn,
                    "agent:table-injection",
                    bytes(vk),
                    "ed25519",
                    source_event_hash=_hash("t"),
                    valid_from=_T0,
                    registered_at=_T0,
                    _table="events",
                )
        assert exc_info.value.code is ErrorCode.INVALID_ARGUMENT
        assert exc_info.value.detail["reason"] == "unknown_applier_table"


class TestRegisterPrincipalKey:
    def test_register_returns_entry(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry = _enroll(
            principal_keys, "human:alice", bytes(vk), registered_by="admin",
        )
        assert entry.principal_id == "human:alice"
        assert entry.scheme == "ed25519"
        assert entry.status == "active"
        assert entry.registered_by == "admin"
        assert entry.public_key == bytes(vk)
        assert entry.fingerprint.startswith("ed25519:sha256:")

    def test_enrolled_row_records_its_provenance(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        source = _hash("provenance")
        entry = _enroll(
            principal_keys,
            "agent:provenance",
            bytes(vk),
            source=source,
            trust_domain_id="6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        )
        assert entry.source_event_hash == source
        assert entry.trust_domain_id == "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        assert entry.projection_version == 1
        # A row that names its source event is v6-sourced, not legacy.
        assert entry.provenance == "v6_sourced"
        assert entry.to_dict()["provenance"] == "v6_sourced"

    def test_timestamps_come_from_the_event_not_the_clock(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        not_before = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
        not_after = datetime(2027, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
        entry = _enroll(
            principal_keys,
            "agent:clockless",
            bytes(vk),
            valid_from=not_before,
            valid_to=not_after,
        )
        # Not "close to now" — exactly the event's values. This is what makes a
        # byte-for-byte rebuild possible at all (§9 criterion 12).
        assert entry.valid_from == not_before
        assert entry.valid_to == not_after
        assert entry.registered_at == not_before

    def test_register_idempotent_same_key_id(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry1 = _enroll(
            principal_keys, "human:bob", bytes(vk), key_id="key-001",
        )
        entry2 = _enroll(
            principal_keys, "human:bob", bytes(vk), key_id="key-001",
        )
        assert entry1.key_id == entry2.key_id
        assert entry2.status == "active"

    def test_register_new_key_supersedes_old(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        entry1 = _enroll(principal_keys, "human:carol", bytes(vk1))
        assert entry1.status == "active"

        _sk2, vk2 = _generate_ed25519_keypair()
        later = datetime(2026, 9, 1, tzinfo=UTC)
        entry2 = _enroll(
            principal_keys, "human:carol", bytes(vk2), key_id="carol-2",
            valid_from=later,
        )
        assert entry2.status == "active"

        old = get_active_key(principal_keys._mgr, "human:carol")
        assert old.key_id == entry2.key_id

        all_keys = list_principal_keys(principal_keys._mgr, "human:carol")
        statuses = {k.key_id: k.status for k in all_keys}
        assert statuses[entry1.key_id] == "superseded"
        assert statuses[entry2.key_id] == "active"

        valid_tos = {k.key_id: k.valid_to for k in all_keys}
        assert valid_tos[entry1.key_id] is not None
        # §5.6: the superseded key's valid_to is the successor's valid_from,
        # derived from the event rather than from whoever remembered the UPDATE.
        assert valid_tos[entry1.key_id] == later

    def test_register_empty_principal_raises(self, principal_keys):
        """Now refused by the §2.1 grammar (P2.3), which subsumes the old emptiness
        check — the applier validates the id before it validates anything else."""
        _sk, vk = _generate_ed25519_keypair()
        with pytest.raises(RegistaError) as exc_info:
            _enroll(principal_keys, "", bytes(vk))
        assert exc_info.value.code is ErrorCode.PRINCIPAL_ID_UNGRAMMATICAL

    def test_register_empty_pubkey_raises(self, principal_keys):
        with pytest.raises(RegistaError) as exc_info:
            _enroll(principal_keys, "human:dave", b"")
        assert exc_info.value.code is ErrorCode.INVALID_ARGUMENT


class TestListPrincipalKeys:
    def test_list_all(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        _sk2, vk2 = _generate_ed25519_keypair()
        _enroll(principal_keys, "agent:p1", bytes(vk1))
        _enroll(principal_keys, "agent:p2", bytes(vk2))
        all_keys = list_principal_keys(principal_keys._mgr)
        principals = {k.principal_id for k in all_keys}
        assert "agent:p1" in principals
        assert "agent:p2" in principals

    def test_list_by_principal(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        _sk2, vk2 = _generate_ed25519_keypair()
        _enroll(principal_keys, "agent:p3", bytes(vk1))
        _enroll(principal_keys, "agent:p4", bytes(vk2))
        keys = list_principal_keys(principal_keys._mgr, "agent:p3")
        assert all(k.principal_id == "agent:p3" for k in keys)

    def test_list_by_status(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        _sk2, vk2 = _generate_ed25519_keypair()
        entry1 = _enroll(principal_keys, "agent:p5", bytes(vk1), key_id="p5-a")
        entry2 = _enroll(principal_keys, "agent:p5", bytes(vk2), key_id="p5-b")
        active = list_principal_keys(principal_keys._mgr, "agent:p5", status="active")
        superseded = list_principal_keys(principal_keys._mgr, "agent:p5", status="superseded")
        assert len(active) == 1
        assert active[0].key_id == entry2.key_id
        assert len(superseded) == 1
        assert superseded[0].key_id == entry1.key_id


class TestGetActiveKey:
    def test_returns_active_key(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        _enroll(principal_keys, "agent:p6", bytes(vk))
        active = get_active_key(principal_keys._mgr, "agent:p6")
        assert active.principal_id == "agent:p6"
        assert active.status == "active"

    def test_raises_when_no_active_key(self, principal_keys):
        with pytest.raises(RegistaError) as exc_info:
            get_active_key(principal_keys._mgr, "agent:nonexistent")
        assert exc_info.value.code == ErrorCode.UNREGISTERED_SIGNER


class TestRotatePrincipalKey:
    def test_rotation_supersedes_old(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        entry1 = _enroll(principal_keys, "agent:p7", bytes(vk1), key_id="p7-a")
        _sk2, vk2 = _generate_ed25519_keypair()
        entry2 = _rotate(principal_keys, "agent:p7", bytes(vk2), key_id="p7-b")
        assert entry2.status == "active"
        assert entry2.key_id != entry1.key_id

        all_keys = list_principal_keys(principal_keys._mgr, "agent:p7")
        old = next(k for k in all_keys if k.key_id == entry1.key_id)
        assert old.status == "superseded"
        assert old.valid_to is not None

    def test_rotation_keeps_old_key_for_history(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        _enroll(principal_keys, "agent:p8", bytes(vk1), key_id="p8-a")
        _sk2, vk2 = _generate_ed25519_keypair()
        _rotate(principal_keys, "agent:p8", bytes(vk2), key_id="p8-b")
        all_keys = list_principal_keys(principal_keys._mgr, "agent:p8")
        assert len(all_keys) == 2

    def test_rotation_row_names_the_rotation_event(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        _enroll(principal_keys, "agent:p8b", bytes(vk1), key_id="p8b-a")
        _sk2, vk2 = _generate_ed25519_keypair()
        source = _hash("agent:p8b-rotation")
        rotated = _rotate(
            principal_keys, "agent:p8b", bytes(vk2), key_id="p8b-b", source=source,
        )
        assert rotated.source_event_hash == source


class TestRevokePrincipalKey:
    def test_revoke_sets_status(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry = _enroll(principal_keys, "agent:p9", bytes(vk))
        revoked = _revoke(
            principal_keys, "agent:p9", entry.key_id, reason="compromised",
        )
        assert revoked.status == "revoked"
        assert revoked.revoked_reason == "compromised"
        assert revoked.revoked_at is not None

    def test_revocation_does_not_overwrite_the_enrolment_provenance(
        self, principal_keys,
    ):
        """§5.9: source_event_hash names the enrolment/rotation event.

        A revocation flips ``status``; it does not change which event introduced the
        key. Overwriting it would make the row unreproducible by a rebuild.
        """
        _sk, vk = _generate_ed25519_keypair()
        enrol_source = _hash("agent:p9b-enrol")
        entry = _enroll(principal_keys, "agent:p9b", bytes(vk), source=enrol_source)
        revoked = _revoke(
            principal_keys, "agent:p9b", entry.key_id, source=_hash("agent:p9b-revoke"),
        )
        assert revoked.source_event_hash == enrol_source

    def test_revoked_at_comes_from_the_event(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry = _enroll(principal_keys, "agent:p9c", bytes(vk))
        claimed = datetime(2026, 11, 5, 6, 7, 8, 90123, tzinfo=UTC)
        revoked = _revoke(principal_keys, "agent:p9c", entry.key_id, revoked_at=claimed)
        assert revoked.revoked_at == claimed

    def test_revoke_idempotent(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry = _enroll(principal_keys, "agent:p10", bytes(vk))
        _revoke(principal_keys, "agent:p10", entry.key_id)
        revoked2 = _revoke(principal_keys, "agent:p10", entry.key_id)
        assert revoked2.status == "revoked"

    def test_revoke_nonexistent_raises(self, principal_keys):
        with pytest.raises(RegistaError) as exc_info:
            _revoke(principal_keys, "agent:nonexistent", "fake-key-id")
        assert exc_info.value.code == ErrorCode.PRINCIPAL_KEY_NOT_FOUND


class TestVerifyPrincipalBinding:
    def test_matching_principal_succeeds(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        _enroll(principal_keys, "agent:p11", bytes(vk))
        entry = verify_principal_binding(principal_keys._mgr, "agent:p11", "agent:p11")
        assert entry.status == "active"

    def test_mismatch_raises(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        _enroll(principal_keys, "agent:p12", bytes(vk))
        with pytest.raises(RegistaError) as exc_info:
            verify_principal_binding(principal_keys._mgr, "agent:p12", "agent:impostor")
        assert exc_info.value.code == ErrorCode.ACTOR_SIGNER_MISMATCH


class TestFingerprint:
    def test_fingerprint_matches_sha256(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        pub = bytes(vk)
        entry = _enroll(principal_keys, "agent:p13", pub)
        expected = f"ed25519:sha256:{hashlib.sha256(pub).hexdigest()}"
        assert entry.fingerprint == expected


class TestToDict:
    def test_to_dict_shape(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry = _enroll(principal_keys, "agent:p14", bytes(vk))
        d = entry.to_dict()
        assert d["principal_id"] == "agent:p14"
        assert d["scheme"] == "ed25519"
        assert d["status"] == "active"
        assert "public_key" in d
        assert "fingerprint" in d
        assert "valid_from" in d
        assert "registered_by" in d
        assert "registered_at" in d
        # §5.9 provenance columns are part of the reported shape.
        assert "source_event_hash" in d
        assert "acceptance_event_hash" in d
        assert "trust_domain_id" in d
        assert d["projection_version"] == 1
        assert d["provenance"] == "v6_sourced"


class TestLegacyUnsourcedRows:
    """Legacy rows are a labelled compatibility input, never lifecycle evidence."""

    def test_seeded_legacy_row_is_reported_legacy_unsourced(self, principal_keys):
        from regista.testing import seed_legacy_principal_key

        _sk, vk = _generate_ed25519_keypair()
        entry = seed_legacy_principal_key(principal_keys._mgr, "agent:legacy-1", bytes(vk))
        assert entry.source_event_hash is None
        assert entry.provenance == "legacy_unsourced"
        assert entry.to_dict()["provenance"] == "legacy_unsourced"

    def test_legacy_seeder_refuses_to_revoke_a_v6_sourced_row(self, principal_keys):
        from regista.testing import seed_legacy_principal_key_revocation

        _sk, vk = _generate_ed25519_keypair()
        entry = _enroll(principal_keys, "agent:legacy-2", bytes(vk))
        with pytest.raises(RegistaError) as exc_info:
            seed_legacy_principal_key_revocation(
                principal_keys._mgr, "agent:legacy-2", entry.key_id,
            )
        assert exc_info.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
        assert exc_info.value.detail["reason"] == "row_is_v6_sourced"


class TestFacadeAPI:
    """``Regista.principals`` — read paths intact, write paths refused.

    The five pre-P2.2 nodes in this class drove the facade's register/rotate/revoke,
    which wrote the projection with no event (§5.9 rule 2). Those three now refuse;
    the read paths they used for setup are exercised here against legacy-seeded rows,
    so the facade's query surface keeps its coverage.
    """

    def test_list_via_facade(self, principal_keys):
        from regista.testing import seed_legacy_principal_key

        _sk, vk = _generate_ed25519_keypair()
        seed_legacy_principal_key(principal_keys._mgr, "agent:p16", bytes(vk), "ed25519")
        result = principal_keys.principals.list()
        assert any(r["principal_id"] == "agent:p16" for r in result)

    def test_get_active_via_facade(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry = _enroll(principal_keys, "agent:p16b", bytes(vk))
        result = principal_keys.principals.get_active("agent:p16b")
        assert result["key_id"] == entry.key_id
        assert result["status"] == "active"
        assert result["provenance"] == "v6_sourced"

    def test_verify_binding_via_facade(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        _enroll(principal_keys, "agent:p19", bytes(vk))
        result = principal_keys.principals.verify_binding("agent:p19", "agent:p19")
        assert result["status"] == "active"

    def test_register_via_facade_is_refused(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        with pytest.raises(RegistaError) as exc_info:
            principal_keys.principals.register("agent:p15", bytes(vk), "ed25519")
        assert exc_info.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
        assert exc_info.value.detail["operation"] == "register"

    def test_rotate_via_facade_is_refused(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        with pytest.raises(RegistaError) as exc_info:
            principal_keys.principals.rotate("agent:p17", bytes(vk), "ed25519")
        assert exc_info.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
        assert exc_info.value.detail["operation"] == "rotate"

    def test_revoke_via_facade_is_refused(self, principal_keys):
        with pytest.raises(RegistaError) as exc_info:
            principal_keys.principals.revoke("agent:p18", "pk_whatever")
        assert exc_info.value.code is ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
        assert exc_info.value.detail["operation"] == "revoke"

    def test_rebuild_projection_via_facade(self, principal_keys):
        report = principal_keys.principals.rebuild_projection(dry_run=True)
        assert report["dry_run"] is True
        assert report["consistent"] is True
        assert principal_keys.principals.projection_summary() == {
            "legacy_unsourced": 0,
            "v6_sourced": 0,
        }
