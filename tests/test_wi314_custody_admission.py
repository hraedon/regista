"""WI-314: write-time admission for ``trust_domain_custody_declared``.

A custody correction was validated at *replay* time but not at *write* time, so a
malformed correction (a ``declaration_seq`` gap, or a ``supersedes_declaration_digest``
naming the wrong predecessor) could be durably appended fail-open and then permanently
wedge the trust log: every subsequent replay — and therefore every subsequent append,
which replays first — raised ``custody_seq_not_contiguous`` /
``custody_supersedes_wrong_predecessor``, and events are immutable so there is no repair
path.

These tests prove the symmetric write-time guard: a malformed correction is refused *at
append* with the same named error replay would raise, the log stays appendable, and a
valid correction still appends, replays, and surfaces on ``TrustState.current_custody``.
"""

from __future__ import annotations

import uuid

import pytest
from _helpers import DSN

# Reuse the WI-301 writer harness (genesis mint, key file, project lifecycle).
from test_wi301_trust_log_writer import (
    ROOT,
    _close,
    _make_environment,
    _root_keys,
    _signed_genesis_payload,
)

from regista._errors import ErrorCode, RegistaError
from regista._trust_log import (
    TrustDomainCustodyDeclared,
    admit_custody_declaration,
    replay_custody_declarations,
)
from regista._trust_log_writer import (
    _row_event_hash,
    append_trust_log_event,
    chain_order,
    read_trust_log_rows,
    replay_trust_state,
    write_trust_genesis,
)
from tests._trust_log_fixtures import make_custody_declaration_payload

pytestmark = pytest.mark.skipif(not DSN, reason="REGISTA_TEST_DSN is not set")


@pytest.fixture(autouse=True)
def _producer_env(monkeypatch):
    monkeypatch.setenv("REGISTA_PRODUCER_HARNESS", "pytest")
    monkeypatch.setenv("REGISTA_PRODUCER_HARNESS_VERSION", "0")
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL", "test-fixture")
    monkeypatch.setenv("REGISTA_PRODUCER_MODEL_LINEAGE", "fable")


# ---------------------------------------------------------------------------
# Writer harness helpers
# ---------------------------------------------------------------------------


def _bootstrap(tmp_path):
    fixture, handle, _key_file, project = _make_environment(tmp_path)
    write_trust_genesis(
        handle._mgr,
        keys=handle._keys,
        genesis_document=fixture.document,
        payload=_signed_genesis_payload(fixture),
        root_principal_id=ROOT,
    )
    return fixture, handle, project


def _custody_fingerprints(fixture):
    return list(fixture.fingerprints.values())


def _append_custody(handle, fixture, *, declaration_seq, supersedes):
    payload = make_custody_declaration_payload(
        trust_domain_id=fixture.trust_domain_id,
        fingerprints=_custody_fingerprints(fixture),
        declaration_seq=declaration_seq,
        supersedes_declaration_digest=supersedes,
        reason=f"custody correction seq {declaration_seq}",
        root_keys=_root_keys(fixture),
    )
    return append_trust_log_event(
        handle._mgr,
        keys=handle._keys,
        genesis_document=fixture.document,
        transition="trust_domain_custody_declared",
        payload=payload,
        entity_kind="trust_domain",
        entity_id=uuid.UUID(fixture.trust_domain_id),
        principal_id=ROOT,
        authority="root",
    )


def _custody_digests(handle):
    with handle._mgr.transaction() as conn:
        order = chain_order(read_trust_log_rows(conn))
    return [
        _row_event_hash(r)
        for r in order
        if str(r["transition"]) == "trust_domain_custody_declared"
    ]


def _replay(handle, fixture):
    with handle._mgr.transaction() as conn:
        return replay_trust_state(conn, fixture.document)


# ---------------------------------------------------------------------------
# Direct coverage for the replay primitive (previously untested)
# ---------------------------------------------------------------------------


def _decl(seq, supersedes):
    return TrustDomainCustodyDeclared(
        trust_domain_id="td",
        declaration_seq=seq,
        supersedes_declaration_digest=supersedes,
        custody=(),
        reason="r",
        root_signatures=(),
    )


class TestReplayCustodyDeclarationsDirect:
    def test_empty_sequence_returns_none(self):
        assert replay_custody_declarations([]) is None

    def test_contiguous_sequence_returns_head(self):
        d1, d2, d3 = _decl(1, None), _decl(2, "sha256:a"), _decl(3, "sha256:b")
        head = replay_custody_declarations(
            [(d1, "sha256:a"), (d2, "sha256:b"), (d3, "sha256:c")]
        )
        assert head is d3

    def test_seq_gap_raises_not_contiguous(self):
        d1, d3 = _decl(1, None), _decl(3, "sha256:a")
        with pytest.raises(RegistaError) as exc:
            replay_custody_declarations([(d1, "sha256:a"), (d3, "sha256:b")])
        assert exc.value.code is ErrorCode.TRUST_LOG_PAYLOAD_INVALID
        assert exc.value.detail["reason"] == "custody_seq_not_contiguous"

    def test_wrong_supersedes_raises(self):
        d1, d2 = _decl(1, None), _decl(2, "sha256:wrong")
        with pytest.raises(RegistaError) as exc:
            replay_custody_declarations([(d1, "sha256:a"), (d2, "sha256:b")])
        assert exc.value.code is ErrorCode.TRUST_LOG_PAYLOAD_INVALID
        assert exc.value.detail["reason"] == "custody_supersedes_wrong_predecessor"


class TestAdmitCustodyDeclarationDirect:
    def test_first_declaration_admitted_against_no_head(self):
        admit_custody_declaration(None, _decl(1, None))

    def test_first_declaration_seq_jump_refused(self):
        with pytest.raises(RegistaError) as exc:
            admit_custody_declaration(None, _decl(3, None))
        assert exc.value.detail["reason"] == "custody_seq_not_contiguous"

    def test_correction_admitted_against_head(self):
        admit_custody_declaration((_decl(1, None), "sha256:a"), _decl(2, "sha256:a"))

    def test_correction_wrong_supersedes_refused(self):
        with pytest.raises(RegistaError) as exc:
            admit_custody_declaration(
                (_decl(1, None), "sha256:a"), _decl(2, "sha256:nope")
            )
        assert exc.value.detail["reason"] == "custody_supersedes_wrong_predecessor"


# ---------------------------------------------------------------------------
# End-to-end writer admission (the WI-314 fix)
# ---------------------------------------------------------------------------


class TestCustodyWriteTimeAdmission:
    def test_valid_correction_appends_replays_and_surfaces(self, tmp_path):
        """A valid seq-1 then seq-2 correction append, replay, and read back;
        the replayed current custody is observable on TrustState (§9 iv)."""
        fixture, handle, project = _bootstrap(tmp_path)
        try:
            _append_custody(handle, fixture, declaration_seq=1, supersedes=None)
            seq1_digest = _custody_digests(handle)[0]
            _append_custody(
                handle, fixture, declaration_seq=2, supersedes=seq1_digest
            )

            state = _replay(handle, fixture)
            assert state.current_custody is not None
            assert state.current_custody.declaration_seq == 2
            assert state.current_custody.reason == "custody correction seq 2"
            assert state.current_custody_digest == _custody_digests(handle)[1]
        finally:
            _close(handle, project)

    def test_seq_gap_correction_refused_at_write(self, tmp_path):
        """The wedge, closed: a seq-3 jump after seq-1 is refused AT APPEND with the
        same error replay would raise, and the log stays appendable afterward."""
        fixture, handle, project = _bootstrap(tmp_path)
        try:
            _append_custody(handle, fixture, declaration_seq=1, supersedes=None)
            seq1_digest = _custody_digests(handle)[0]

            with pytest.raises(RegistaError) as exc:
                _append_custody(
                    handle, fixture, declaration_seq=3, supersedes=seq1_digest
                )
            assert exc.value.code is ErrorCode.TRUST_LOG_PAYLOAD_INVALID
            assert exc.value.detail["reason"] == "custody_seq_not_contiguous"

            # Fail-closed: nothing malformed was durably appended, so the log is not
            # wedged. Replay succeeds and a valid seq-2 still appends.
            assert _replay(handle, fixture).current_custody.declaration_seq == 1
            _append_custody(
                handle, fixture, declaration_seq=2, supersedes=seq1_digest
            )
            assert _replay(handle, fixture).current_custody.declaration_seq == 2
        finally:
            _close(handle, project)

    def test_wrong_supersedes_correction_refused_at_write(self, tmp_path):
        """A seq-2 naming the wrong predecessor digest is refused at append."""
        fixture, handle, project = _bootstrap(tmp_path)
        try:
            _append_custody(handle, fixture, declaration_seq=1, supersedes=None)

            with pytest.raises(RegistaError) as exc:
                _append_custody(
                    handle,
                    fixture,
                    declaration_seq=2,
                    supersedes="sha256:" + "00" * 32,
                )
            assert exc.value.code is ErrorCode.TRUST_LOG_PAYLOAD_INVALID
            assert exc.value.detail["reason"] == "custody_supersedes_wrong_predecessor"

            # Still appendable with the correct predecessor.
            seq1_digest = _custody_digests(handle)[0]
            _append_custody(
                handle, fixture, declaration_seq=2, supersedes=seq1_digest
            )
            assert _replay(handle, fixture).current_custody.declaration_seq == 2
        finally:
            _close(handle, project)

    def test_first_declaration_seq_jump_refused_at_write(self, tmp_path):
        """A first custody event with seq != 1 is refused at append."""
        fixture, handle, project = _bootstrap(tmp_path)
        try:
            with pytest.raises(RegistaError) as exc:
                _append_custody(handle, fixture, declaration_seq=2, supersedes=None)
            # seq 2 with supersedes=None fails the payload's own supersession rule
            # before the seq check; a seq 3 with a non-null digest reaches the
            # contiguity gate. Either way the append is refused fail-closed.
            assert exc.value.code is ErrorCode.TRUST_LOG_PAYLOAD_INVALID
        finally:
            _close(handle, project)
