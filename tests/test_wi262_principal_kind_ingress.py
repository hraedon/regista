"""WI-262: on_behalf_of.principal_kind is validated and canonicalised at ingress.

``validate_delegation_chain`` used to check ``principal_id`` and nothing else,
so ``principal_kind`` reached the cross-lineage gate as unvalidated,
attacker-controlled metadata. Sol's round-2 release review probed it end to end:
an author-side delegated principal with ``principal_kind="ai-agent"`` and no
lineage was ignored as an undeclared agent, and a lineage-B review was accepted
with NO acknowledgment, reporting ``independently_reviewed``,
``lineage_relation="distinct"``, ``agent_author_undeclared=False``.

Two legs close it, and they solve different halves:

1. this file — reject unknown kinds at write time against a closed set, and
   store the canonical spelling;
2. ``tests/test_lineage.py::TestDegenerateDelegationValues`` — the gate treats
   any declared kind that is not "human" as unable to vouch that the principal
   is not a model, so events written BEFORE this validation existed still fail
   closed rather than crash.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from regista._contract import _VALID_PRINCIPAL_KINDS, validate_delegation_chain
from regista._errors import ErrorCode, RegistaError
from regista._review_validators import derive_authors
from regista.principal_lifecycle import PrincipalKind
from regista.testing import InMemoryRegista

TESTS_DIR = Path(__file__).parent
KEY_PATH = str(TESTS_DIR / "test_keys.json")

REVIEW_NOTE = {"review_note": "looks good"}

_WORKFLOW = """\
name: wi262_review
version: 1
regista_version: "0.4.0"

states:
  - name: open
    initial: true
  - name: in_progress
  - name: in_review
  - name: done
    terminal: true

transitions:
  - name: start
    from: open
    to: in_progress
  - name: submit_for_review
    from: in_progress
    to: in_review
  - name: adversarial_pass
    from: in_review
    to: done
    validator: adversarial_review

roles: []

work_item_types:
  - name: issue
    custom_fields: []
"""


def _sub(project: str) -> InMemoryRegista:
    sub = InMemoryRegista(project=project, hmac_key_path=KEY_PATH)
    sub.register_workflow(_WORKFLOW)
    return sub


class TestClosedKindSet:
    def test_matches_the_estates_principal_kind_vocabulary(self):
        # The closed set is not invented here: PrincipalKind is the estate's
        # existing vocabulary for what a principal is. Pinning them together
        # means a new kind cannot be added to one and silently rejected by the
        # other.
        assert _VALID_PRINCIPAL_KINDS == {k.value for k in PrincipalKind}

    @pytest.mark.parametrize("kind", sorted(_VALID_PRINCIPAL_KINDS))
    def test_every_valid_kind_is_accepted(self, kind):
        validate_delegation_chain({"principal_id": "p", "principal_kind": kind})

    def test_absent_kind_is_still_legal(self):
        # The bare separation-of-duties shape claims nothing about the
        # principal and must keep working.
        validate_delegation_chain({"principal_id": "p"})

    def test_explicit_null_kind_is_still_legal(self):
        validate_delegation_chain({"principal_id": "p", "principal_kind": None})


class TestRejectsUnknownKinds:
    @pytest.mark.parametrize(
        "kind", ["ai-agent", "robot", "system", "", "   ", 42, True, ["agent"]]
    )
    def test_unknown_kind_rejected(self, kind):
        with pytest.raises(RegistaError) as exc_info:
            validate_delegation_chain({"principal_id": "p", "principal_kind": kind})
        assert exc_info.value.code == ErrorCode.INVALID_PRINCIPAL_KIND

    def test_error_names_the_allowed_set(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_delegation_chain(
                {"principal_id": "p", "principal_kind": "ai-agent"}
            )
        assert "ai-agent" in exc_info.value.message
        for kind in _VALID_PRINCIPAL_KINDS:
            assert kind in exc_info.value.message

    def test_actor_kind_system_is_not_a_principal_kind(self):
        # "system" is a valid actor_kind but has never been a principal_kind —
        # the confusion between the two fields is what justified the author-side
        # exemption this work item removes.
        with pytest.raises(RegistaError):
            validate_delegation_chain(
                {"principal_id": "p", "principal_kind": "system"}
            )


class TestCanonicalisation:
    @pytest.mark.parametrize(
        ("given", "canonical"),
        [
            ("Agent", "agent"),
            ("AGENT", "agent"),
            (" agent ", "agent"),
            ("\tHuman\n", "human"),
            ("Break_Glass", "break_glass"),
        ],
    )
    def test_kind_is_canonicalised_in_place(self, given, canonical):
        # Validation rewrites the value so what lands in the signed event is
        # the canonical spelling, rather than leaving every reader to normalise.
        delegation = {"principal_id": "p", "principal_kind": given}
        validate_delegation_chain(delegation)
        assert delegation["principal_kind"] == canonical

    def test_canonical_value_reaches_the_stored_event(self):
        sub = _sub("wi262_canonical")
        try:
            wi, _ = sub.create_work_item(
                workflow_name="wi262_review", work_item_type="issue",
                actor_id="proxy-agent", actor_kind="agent",
                actor_metadata={"model_lineage": "lineage-A"},
            )
            sub.transition(
                wi.work_item_id, "start", "proxy-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "lineage-A"},
                on_behalf_of={"principal_id": "boss", "principal_kind": " Human "},
            )
            events = sub.read_events(work_item_id=wi.work_item_id, limit=100)
            start = next(e for e in events if e.transition == "start")
            assert start.on_behalf_of["principal_kind"] == "human"
        finally:
            sub.close()


class TestIngressEndToEnd:
    def test_transition_rejects_unknown_principal_kind(self):
        sub = _sub("wi262_ingress_reject")
        try:
            wi, _ = sub.create_work_item(
                workflow_name="wi262_review", work_item_type="issue",
                actor_id="proxy-agent", actor_kind="agent",
                actor_metadata={"model_lineage": "lineage-A"},
            )
            with pytest.raises(RegistaError) as exc_info:
                sub.transition(
                    wi.work_item_id, "start", "proxy-agent",
                    actor_kind="agent",
                    actor_metadata={"model_lineage": "lineage-A"},
                    on_behalf_of={
                        "principal_id": "hidden",
                        "principal_kind": "ai-agent",
                    },
                )
            assert exc_info.value.code == ErrorCode.INVALID_PRINCIPAL_KIND
            # The write never happened.
            assert sub.get_work_item(wi.work_item_id).current_state == "open"
        finally:
            sub.close()

    def test_legacy_stored_kind_still_fails_closed_at_the_gate(self):
        # Validation applies to NEW writes. An event written before it existed
        # can still carry "ai-agent", so the gate must fail closed on it rather
        # than crash — this is Sol's probe, replayed against a history the
        # ingress can no longer produce.
        from types import SimpleNamespace

        legacy = SimpleNamespace(
            transition="created",
            actor_id="proxy-agent",
            actor_kind="agent",
            actor_metadata={"model_lineage": "lineage-A"},
            on_behalf_of={"principal_id": "hidden", "principal_kind": "ai-agent"},
        )
        _ids, kinds, lineages, undeclared = derive_authors([legacy])
        assert "hidden" in _ids
        assert "ai-agent" in kinds
        assert lineages == {"lineage-A"}
        assert undeclared is True

    def test_recognised_kind_still_writes(self):
        sub = _sub("wi262_ingress_accept")
        try:
            wi, _ = sub.create_work_item(
                workflow_name="wi262_review", work_item_type="issue",
                actor_id="proxy-agent", actor_kind="agent",
                actor_metadata={"model_lineage": "lineage-A"},
            )
            sub.transition(
                wi.work_item_id, "start", "proxy-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "lineage-A"},
                on_behalf_of={
                    "principal_id": "delegated-agent",
                    "principal_kind": "agent",
                    "principal_lineage": "lineage-D",
                },
            )
            sub.transition(
                wi.work_item_id, "submit_for_review", "proxy-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "lineage-A"},
            )
            # Every identity declared a lineage and the reviewer differs from
            # all of them: still no acknowledgment required.
            sub.transition(
                wi.work_item_id, "adversarial_pass", "kimi-agent",
                actor_kind="agent",
                actor_metadata={"model_lineage": "lineage-B"},
                payload=REVIEW_NOTE,
            )
            assert sub.get_work_item(wi.work_item_id).current_state == "done"
        finally:
            sub.close()
