from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid

import pytest
from _helpers import DSN as _HELPER_DSN

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

from _v6_fixtures import make_v6_keyset, open_v6_epoch
from fastapi.testclient import TestClient

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from regista.testing import InMemoryRegista, drop_project_schema

#: ``_helpers.DSN`` rather than a local ``TEST_DSN`` read: every other file in the suite
#: honours ``REGISTA_TEST_DSN``, and the WI-243 schema-leak guard snapshots *that* DSN —
#: a project created against a different default was invisible to it.
DSN = _HELPER_DSN
TEST_WORKFLOW = os.environ.get("TEST_WORKFLOW", "tests/test_workflow.yaml")

#: Canonical per ``TRUST-DOMAIN.md`` §2.1. The sidecar resolves the *event* actor from
#: the bearer token, so the token's ``actor_id`` has to be canonical too — the bare
#: spelling it replaces is refused at the v6 ingress.
ACTOR = "agent:worker"


def _make_token_file():
    raw_token = "test-secret-token-12345"
    token_sha256 = hashlib.sha256(raw_token.encode()).hexdigest()
    data = {
        "tokens": [
            {
                "token_sha256": token_sha256,
                "actor_id": ACTOR,
                "actor_kind": "agent",
                "allowed_roles": ["agent", "coder", "reviewer", "admin"],
            },
        ]
    }
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False,
    )
    json.dump(data, f)
    f.close()
    return f.name, raw_token


@pytest.fixture(scope="module")
def token_file():
    path, raw = _make_token_file()
    yield path, raw
    os.unlink(path)


@pytest.fixture(scope="module")
def regista_instance(tmp_path_factory):
    project = f"bc306_test_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path_factory.mktemp("bc306_keys"))
    sub = Regista.create_project(DSN, project, keyset.path)
    # The clean v6 epoch before the registration: `register_workflow` emits the signed
    # `workflow_registered` event admission gate 1 requires, and there is no epoch to
    # append it to until `open_v6_epoch` returns.
    open_v6_epoch(sub, keyset)
    yaml_content = open(TEST_WORKFLOW).read()
    sub.register_workflow(yaml_content)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


@pytest.fixture(scope="module")
def client(regista_instance, token_file):
    token_path, _ = token_file
    from regista.sidecar.app import create_app
    from regista.sidecar.auth import TokenRegistry

    tokens = TokenRegistry.from_file(token_path)
    app = create_app(regista_instance, tokens)
    return TestClient(app)


@pytest.fixture(scope="module")
def auth_headers(token_file):
    _, raw = token_file
    return {"Authorization": f"Bearer {raw}"}


@pytest.fixture(scope="module")
def work_item_id(regista_instance, client, auth_headers):
    resp = client.post(
        "/v1/create_work_item",
        json={
            "workflow_name": "test_workflow",
            "work_item_type": "feature",
            "custom_fields": {"title": "bc306 test"},
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    return resp.json()["work_item"]["work_item_id"]


class TestSidecarEntityKindValidation:
    def test_sidecar_rejects_unknown_entity_kind(self, client, auth_headers, work_item_id):
        resp = client.post(
            "/v1/append_event",
            json={
                "work_item_id": work_item_id,
                "transition": "note",
                "entity_kind": "bogus_kind",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_sidecar_accepts_work_item_entity_kind(self, client, auth_headers, work_item_id):
        resp = client.post(
            "/v1/append_event",
            json={
                "work_item_id": work_item_id,
                "transition": "note",
                "entity_kind": "work_item",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200

    def test_sidecar_accepts_default_entity_kind(self, client, auth_headers, work_item_id):
        resp = client.post(
            "/v1/append_event",
            json={
                "work_item_id": work_item_id,
                "transition": "note",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200


class TestCoreApiEntityKindValidation:
    def test_core_api_rejects_unknown_entity_kind(self, regista_instance, work_item_id):
        with pytest.raises(RegistaError) as exc_info:
            regista_instance.append_event(
                work_item_id=uuid.UUID(work_item_id),
                actor_id=ACTOR,
                transition="note",
                entity_kind="bogus_kind",
            )
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_core_api_accepts_work_item_entity_kind(self, regista_instance, work_item_id):
        evt = regista_instance.append_event(
            work_item_id=uuid.UUID(work_item_id),
            actor_id=ACTOR,
            transition="note",
            entity_kind="work_item",
        )
        assert evt is not None


class TestInMemoryEntityKindValidation:
    def test_in_memory_rejects_unknown_entity_kind(self, tmp_path):
        keyset = make_v6_keyset(tmp_path)
        sub = InMemoryRegista(project="test_bc306", hmac_key_path=keyset.path)
        open_v6_epoch(sub, keyset)
        yaml_content = open(TEST_WORKFLOW).read()
        sub.register_workflow(yaml_content)
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", ACTOR,
            custom_fields={"title": "bc306 mem test"},
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.append_event(
                work_item_id=wi.work_item_id,
                actor_id=ACTOR,
                transition="note",
                entity_kind="bogus_kind",
            )
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_in_memory_accepts_work_item_entity_kind(self, tmp_path):
        keyset = make_v6_keyset(tmp_path)
        sub = InMemoryRegista(project="test_bc306_ok", hmac_key_path=keyset.path)
        open_v6_epoch(sub, keyset)
        yaml_content = open(TEST_WORKFLOW).read()
        sub.register_workflow(yaml_content)
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", ACTOR,
            custom_fields={"title": "bc306 mem ok"},
        )
        evt = sub.append_event(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR,
            transition="note",
            entity_kind="work_item",
        )
        assert evt is not None
