from __future__ import annotations

import os
import uuid

import pytest

from regista import Regista
from regista._contract import check_privileged_transition
from regista._errors import ErrorCode, RegistaError
from regista._in_memory import InMemoryRegista
from regista._types import TransitionDef
from regista.testing import drop_project_schema, validate_yaml

DSN = os.environ.get(
    "TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)
KEY_PATH = os.environ.get("TEST_KEYS", "tests/test_keys.json")

#: Canonical per TRUST-DOMAIN.md §2.1 — the v6 ingress refuses a bare legacy name.
#: A privileged transition's actor is infrastructure, so it gets a `service:` id.
SYSTEM_ACTOR = "service:hooks"
WORKER = "agent:worker"

PRIVILEGED_WORKFLOW = """\
name: privileged_test
version: 1
regista_version: "0.3.0"

states:
  - name: new
    initial: true
  - name: attested
    terminal: true

transitions:
  - name: scope_attestation
    from: new
    to: attested
    privileged: true
  - name: start
    from: new
    to: attested
    allowed_roles: [agent]

roles:
  - name: agent

work_item_types:
  - name: task
    custom_fields:
      - name: title
        type: string
        required: true
"""


class TestContractPrivilegedTransition:
    def test_system_actor_passes(self):
        t = {"name": "scope_attestation", "from_state": "new", "privileged": True}
        check_privileged_transition(t, "system", "scope_attestation")

    def test_agent_actor_rejected(self):
        t = {"name": "scope_attestation", "from_state": "new", "privileged": True}
        with pytest.raises(RegistaError) as exc_info:
            check_privileged_transition(t, "agent", "scope_attestation")
        assert exc_info.value.code == ErrorCode.PRIVILEGED_TRANSITION_REQUIRED
        assert "agent" in exc_info.value.message
        assert "system" in exc_info.value.message

    def test_human_actor_rejected(self):
        t = {"name": "scope_attestation", "from_state": "new", "privileged": True}
        with pytest.raises(RegistaError):
            check_privileged_transition(t, "human", "scope_attestation")

    def test_non_privileged_transition_allows_any_actor(self):
        t = {"name": "start", "from_state": "new", "privileged": False}
        check_privileged_transition(t, "agent", "start")
        check_privileged_transition(t, "human", "start")
        check_privileged_transition(t, "system", "start")

    def test_missing_privileged_key_defaults_false(self):
        t = {"name": "start", "from_state": "new"}
        check_privileged_transition(t, "agent", "start")


class TestTransitionDefPrivileged:
    def test_default_privileged_false(self):
        td = TransitionDef(
            name="start", from_state="new", to_state="done",
            allowed_roles=[], validator=None, hooks=[],
        )
        assert td.privileged is False

    def test_privileged_true(self):
        td = TransitionDef(
            name="attest", from_state="new", to_state="done",
            allowed_roles=[], validator=None, hooks=[], privileged=True,
        )
        assert td.privileged is True

    def test_to_dict_includes_privileged_when_true(self):
        td = TransitionDef(
            name="attest", from_state="new", to_state="done",
            allowed_roles=[], validator=None, hooks=[], privileged=True,
        )
        d = td.to_dict()
        assert d["privileged"] is True

    def test_to_dict_omits_privileged_when_false(self):
        td = TransitionDef(
            name="start", from_state="new", to_state="done",
            allowed_roles=[], validator=None, hooks=[], privileged=False,
        )
        d = td.to_dict()
        assert "privileged" not in d

    def test_from_dict_with_privileged(self):
        d = {
            "name": "attest", "from_state": "new", "to_state": "done",
            "allowed_roles": [], "validator": None, "hooks": [], "privileged": True,
        }
        td = TransitionDef.from_dict(d)
        assert td.privileged is True

    def test_from_dict_without_privileged(self):
        d = {
            "name": "start", "from_state": "new", "to_state": "done",
            "allowed_roles": [], "validator": None, "hooks": [],
        }
        td = TransitionDef.from_dict(d)
        assert td.privileged is False


class TestWorkflowSchemaPrivileged:
    def test_privileged_workflow_validates(self):
        result = validate_yaml(PRIVILEGED_WORKFLOW)
        assert result.valid, result.errors

    def test_privileged_rejects_non_boolean(self):
        bad = PRIVILEGED_WORKFLOW.replace("privileged: true", "privileged: yes_not_bool")
        result = validate_yaml(bad)
        assert not result.valid


class TestPostgresPrivilegedTransition:
    @pytest.fixture()
    def sub(self, tmp_path):
        from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

        proj = f"test_priv_{uuid.uuid4().hex[:8]}"
        keyset = make_v6_keyset(tmp_path)
        s = Regista.create_project(DSN, proj, hmac_key_path=keyset.path)
        # The epoch first: `register_workflow` emits the signed
        # `workflow_registered` event admission gate 1 requires, and there is no
        # epoch to append it to before `open_v6_epoch` returns.
        open_v6_epoch(s, keyset)
        s.register_workflow(PRIVILEGED_WORKFLOW)
        yield s
        s.close()
        drop_project_schema(DSN, proj)

    def test_system_actor_can_transition(self, sub):
        wi, _ = sub.create_work_item(
            "privileged_test", "task", SYSTEM_ACTOR,
            actor_kind="system",
            custom_fields={"title": "test"},
        )
        evt = sub.transition(
            wi.work_item_id, "scope_attestation", SYSTEM_ACTOR,
            actor_kind="system",
        )
        assert evt.transition == "scope_attestation"

    def test_agent_actor_rejected(self, sub):
        wi, _ = sub.create_work_item(
            "privileged_test", "task", WORKER,
            actor_kind="agent",
            custom_fields={"title": "test"},
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.transition(
                wi.work_item_id, "scope_attestation", WORKER,
                actor_kind="agent",
            )
        assert exc_info.value.code == ErrorCode.PRIVILEGED_TRANSITION_REQUIRED

    def test_non_privileged_transition_works_normally(self, sub):
        wi, _ = sub.create_work_item(
            "privileged_test", "task", WORKER,
            actor_kind="agent",
            custom_fields={"title": "test"},
        )
        evt = sub.transition(
            wi.work_item_id, "start", WORKER,
            actor_kind="agent",
            actor_metadata={"role": "agent"},
        )
        assert evt.transition == "start"


class TestInMemoryPrivilegedTransition:
    @pytest.fixture()
    def sub(self, tmp_path):
        from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

        keyset = make_v6_keyset(tmp_path)
        s = InMemoryRegista(
            project="test_priv_mem",
            hmac_key_path=keyset.path,
        )
        # Before the tests' own `register_workflow`, which appends a signed event.
        open_v6_epoch(s, keyset)
        return s

    def test_system_actor_can_transition(self, sub):
        sub.register_workflow(PRIVILEGED_WORKFLOW)
        wi, _ = sub.create_work_item(
            "privileged_test", "task", SYSTEM_ACTOR,
            actor_kind="system",
            custom_fields={"title": "test"},
        )
        evt = sub.transition(
            wi.work_item_id, "scope_attestation", SYSTEM_ACTOR,
            actor_kind="system",
        )
        assert evt.transition == "scope_attestation"

    def test_agent_actor_rejected(self, sub):
        sub.register_workflow(PRIVILEGED_WORKFLOW)
        wi, _ = sub.create_work_item(
            "privileged_test", "task", WORKER,
            actor_kind="agent",
            custom_fields={"title": "test"},
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.transition(
                wi.work_item_id, "scope_attestation", WORKER,
                actor_kind="agent",
            )
        assert exc_info.value.code == ErrorCode.PRIVILEGED_TRANSITION_REQUIRED
