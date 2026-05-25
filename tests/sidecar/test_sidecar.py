from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

from fastapi.testclient import TestClient

from substrate import Substrate

DSN = os.environ.get(
    "TEST_DSN",
    "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test",
)
TEST_KEYS = os.environ.get("TEST_KEYS", "tests/test_keys.json")
TEST_WORKFLOW = os.environ.get("TEST_WORKFLOW", "tests/test_workflow.yaml")


def _make_token_file():
    raw_token = "test-secret-token-12345"
    token_sha256 = hashlib.sha256(raw_token.encode()).hexdigest()
    nonadmin_raw = "test-nonadmin-token-67890"
    nonadmin_sha256 = hashlib.sha256(nonadmin_raw.encode()).hexdigest()
    data = {
        "tokens": [
            {
                "token_sha256": token_sha256,
                "actor_id": "test-agent",
                "actor_kind": "agent",
                "allowed_roles": ["agent", "coder", "reviewer", "admin"],
            },
            {
                "token_sha256": nonadmin_sha256,
                "actor_id": "test-nonadmin",
                "actor_kind": "agent",
                "allowed_roles": ["agent"],
            },
        ]
    }
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False,
    )
    json.dump(data, f)
    f.close()
    return f.name, raw_token, nonadmin_raw


@pytest.fixture(scope="module")
def token_file():
    path, raw, nonadmin_raw = _make_token_file()
    yield path, raw, nonadmin_raw
    os.unlink(path)


@pytest.fixture(scope="module")
def substrate_instance():
    project = f"sidecar_test_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, TEST_KEYS)
    yield sub
    sub.close()
    from substrate._testing import drop_project_schema
    drop_project_schema(DSN, project)


@pytest.fixture(scope="module")
def client(substrate_instance, token_file):
    token_path, _, _ = token_file
    from substrate.sidecar.app import create_app
    from substrate.sidecar.auth import TokenRegistry

    tokens = TokenRegistry.from_file(token_path)
    app = create_app(substrate_instance, tokens)
    return TestClient(app)


@pytest.fixture(scope="module")
def auth_headers(token_file):
    _, raw, _ = token_file
    return {"Authorization": f"Bearer {raw}"}


@pytest.fixture(scope="module")
def nonadmin_headers(token_file):
    _, _, nonadmin_raw = token_file
    return {"Authorization": f"Bearer {nonadmin_raw}"}


@pytest.fixture(scope="module")
def workflow_id(substrate_instance):
    yaml_content = open(TEST_WORKFLOW).read()
    substrate_instance.register_workflow(yaml_content)
    return yaml_content


HOOK_TEST_WORKFLOW_YAML = """\
name: hook_test_workflow
version: 1
substrate_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: done
    terminal: true

transitions:
  - name: complete
    from: new
    to: done
    hooks:
      - on_complete

roles:
  - name: agent

work_item_types:
  - name: task
    custom_fields:
      - name: title
        type: string
        required: true

link_types: []
attempt_threshold: 3
"""


class TestAuth:
    def test_auth_required(self, client):
        resp = client.post("/v1/create_work_item", json={
            "workflow_name": "nonexistent",
            "work_item_type": "task",
        })
        assert resp.status_code == 401

    def test_invalid_token(self, client):
        resp = client.post(
            "/v1/create_work_item",
            json={"workflow_name": "nonexistent", "work_item_type": "task"},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401

    def test_missing_bearer_prefix(self, client):
        resp = client.get(
            "/v1/actor_roles",
            headers={"Authorization": "test-secret-token-12345"},
        )
        assert resp.status_code == 401

    def test_admin_required_for_sweep(self, client, nonadmin_headers):
        resp = client.post(
            "/v1/sweep_expired_claims", headers=nonadmin_headers,
        )
        assert resp.status_code == 403

    def test_admin_required_for_replay(self, client, nonadmin_headers):
        resp = client.post(
            "/v1/replay",
            json={"continue_on_revoked": False},
            headers=nonadmin_headers,
        )
        assert resp.status_code == 403

    def test_admin_required_for_dead_lettered_hooks(self, client, nonadmin_headers):
        resp = client.get("/v1/dead_lettered_hooks", headers=nonadmin_headers)
        assert resp.status_code == 403

    def test_non_admin_can_use_regular_endpoints(self, client, nonadmin_headers):
        # A non-admin token should still be able to authenticate; the
        # endpoint may 404 on missing workflow but must not 401/403.
        resp = client.post(
            "/v1/query_work_items",
            json={"workflow_name": "test_workflow"},
            headers=nonadmin_headers,
        )
        assert resp.status_code not in (401, 403)


class TestSoleSigner:
    def test_signature_rejected(self, client, auth_headers, workflow_id):
        resp = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "test_workflow",
                "work_item_type": "feature",
                "signature": "deadbeef",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "LIBRARY_IS_SOLE_SIGNER"

    def test_payload_canonical_hash_rejected(self, client, auth_headers, workflow_id):
        resp = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "test_workflow",
                "work_item_type": "feature",
                "payload_canonical_hash": "abc",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "LIBRARY_IS_SOLE_SIGNER"


class TestRoundTrip:
    def test_create_transition_read(self, client, auth_headers, workflow_id):
        resp = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "test_workflow",
                "work_item_type": "feature",
                "custom_fields": {"title": "test feature"},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        wi_id = data["work_item"]["work_item_id"]
        assert data["event"]["signature"] is not None

        client.post(
            "/v1/register_actor_role",
            json={"role": "agent"},
            headers=auth_headers,
        )

        resp = client.post(
            "/v1/transition",
            json={
                "work_item_id": wi_id,
                "transition_name": "start",
                "actor_metadata": {"role": "agent"},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200

        resp = client.post(
            "/v1/read_events",
            json={"work_item_id": wi_id},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        events = resp.json()
        assert len(events) >= 2
        assert events[0]["event_seq"] == 1
        assert events[1]["event_seq"] == 2

    def test_get_work_item(self, client, auth_headers, workflow_id):
        resp = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "test_workflow",
                "work_item_type": "feature",
                "custom_fields": {"title": "test feature"},
            },
            headers=auth_headers,
        )
        wi_id = resp.json()["work_item"]["work_item_id"]

        resp = client.get(f"/v1/work_items/{wi_id}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["work_item_id"] == wi_id

    def test_query_work_items(self, client, auth_headers, workflow_id):
        resp = client.post(
            "/v1/query_work_items",
            json={"workflow_name": "test_workflow"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert "items" in resp.json()


class TestClaims:
    def test_acquire_release_claim(self, client, auth_headers, workflow_id):
        resp = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "test_workflow",
                "work_item_type": "feature",
                "custom_fields": {"title": "test feature"},
            },
            headers=auth_headers,
        )
        wi_id = resp.json()["work_item"]["work_item_id"]

        resp = client.post(
            "/v1/acquire_claim",
            json={"work_item_id": wi_id, "ttl_seconds": 300},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["actor_id"] == "test-agent"

        resp = client.post(
            "/v1/release_claim",
            json={"work_item_id": wi_id},
            headers=auth_headers,
        )
        assert resp.status_code == 200


class TestErrorMapping:
    def test_work_item_not_found(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/v1/work_items/{fake_id}", headers=auth_headers)
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "WORK_ITEM_NOT_FOUND"

    def test_workflow_not_registered(self, client, auth_headers):
        resp = client.get("/v1/workflows/nonexistent/1", headers=auth_headers)
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "WORKFLOW_NOT_REGISTERED"


class TestIdempotency:
    def test_idempotent_append_event(self, client, auth_headers, workflow_id):
        resp = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "test_workflow",
                "work_item_type": "feature",
                "custom_fields": {"title": "test feature"},
            },
            headers=auth_headers,
        )
        wi_id = resp.json()["work_item"]["work_item_id"]
        event_id = str(uuid.uuid4())

        resp1 = client.post(
            "/v1/append_event",
            json={
                "work_item_id": wi_id,
                "transition": "note",
                "event_id": event_id,
            },
            headers=auth_headers,
        )
        assert resp1.status_code == 200

        resp2 = client.post(
            "/v1/append_event",
            json={
                "work_item_id": wi_id,
                "transition": "note",
                "event_id": event_id,
            },
            headers=auth_headers,
        )
        assert resp2.status_code == 200
        assert resp1.json()["event_id"] == resp2.json()["event_id"]


class TestActorRoles:
    def test_register_role(self, client, auth_headers):
        resp = client.post(
            "/v1/register_actor_role",
            json={"role": "coder"},
            headers=auth_headers,
        )
        assert resp.status_code == 200

    def test_unauthorized_role(self, client, auth_headers):
        resp = client.post(
            "/v1/register_actor_role",
            json={"role": "auditor"},
            headers=auth_headers,
        )
        assert resp.status_code == 403

    def test_list_roles(self, client, auth_headers):
        resp = client.get("/v1/actor_roles", headers=auth_headers)
        assert resp.status_code == 200


class TestApiDocs:
    def test_docs_disabled_by_default(self, substrate_instance, token_file):
        token_path, _, _ = token_file
        from substrate.sidecar.app import create_app
        from substrate.sidecar.auth import TokenRegistry

        tokens = TokenRegistry.from_file(token_path)
        app = create_app(substrate_instance, tokens)
        client2 = TestClient(app)
        assert client2.get("/docs").status_code == 404
        assert client2.get("/openapi.json").status_code == 404

    def test_docs_enabled_with_explicit_url(self, substrate_instance, token_file):
        token_path, _, _ = token_file
        from substrate.sidecar.app import create_app
        from substrate.sidecar.auth import TokenRegistry

        tokens = TokenRegistry.from_file(token_path)
        app = create_app(substrate_instance, tokens, docs_url="/docs", openapi_url="/openapi.json")
        client2 = TestClient(app)
        assert client2.get("/docs").status_code == 200


class TestNoValidatorOverHttp:
    def test_no_register_validator_route(self, client, auth_headers):
        resp = client.post(
            "/v1/register_validator",
            json={"name": "test"},
            headers=auth_headers,
        )
        assert resp.status_code == 404 or resp.status_code == 405


class TestHookQueue:
    @pytest.fixture(autouse=True)
    def _register_hook_workflow(self, substrate_instance):
        substrate_instance.register_workflow(HOOK_TEST_WORKFLOW_YAML)

    def test_claim_complete_round_trip(self, client, auth_headers, substrate_instance):
        resp = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "hook_test_workflow",
                "work_item_type": "task",
                "custom_fields": {"title": "hook test"},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        wi_id = resp.json()["work_item"]["work_item_id"]

        client.post(
            "/v1/register_actor_role",
            json={"role": "agent"},
            headers=auth_headers,
        )

        resp = client.post(
            "/v1/transition",
            json={
                "work_item_id": wi_id,
                "transition_name": "complete",
                "actor_metadata": {"role": "agent"},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200

        resp = client.post(
            "/v1/hooks/claim",
            json={"max_batch": 10, "lease_seconds": 60},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        hooks = resp.json()
        assert len(hooks) >= 1
        hook_id = hooks[0]["hook_queue_id"]

        resp = client.post(
            f"/v1/hooks/{hook_id}/complete",
            json={},
            headers=auth_headers,
        )
        assert resp.status_code == 200

    def test_hook_lease_expiry_requeues(self, client, auth_headers, substrate_instance):
        import time

        resp = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "hook_test_workflow",
                "work_item_type": "task",
                "custom_fields": {"title": "lease test"},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        wi_id = resp.json()["work_item"]["work_item_id"]

        client.post(
            "/v1/register_actor_role",
            json={"role": "agent"},
            headers=auth_headers,
        )

        resp = client.post(
            "/v1/transition",
            json={
                "work_item_id": wi_id,
                "transition_name": "complete",
                "actor_metadata": {"role": "agent"},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200

        resp = client.post(
            "/v1/hooks/claim",
            json={"max_batch": 10, "lease_seconds": 1},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        hooks = resp.json()
        assert len(hooks) >= 1

        time.sleep(2)

        resp = client.post("/v1/sweep_expired_hook_leases", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["swept"] >= 1

        resp = client.post(
            "/v1/hooks/claim",
            json={"max_batch": 10, "lease_seconds": 60},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        reclaimed = resp.json()
        assert len(reclaimed) >= 1

        hook_id = reclaimed[0]["hook_queue_id"]
        client.post(
            f"/v1/hooks/{hook_id}/complete",
            json={},
            headers=auth_headers,
        )

    def test_sweep_expired_hook_leases(self, client, auth_headers):
        resp = client.post("/v1/sweep_expired_hook_leases", headers=auth_headers)
        assert resp.status_code == 200


class TestTimestampRoutes:
    def test_trigger_requires_admin(self, client, nonadmin_headers):
        resp = client.post("/v1/timestamp/trigger", headers=nonadmin_headers)
        assert resp.status_code == 403

    def test_list_batches_requires_admin(self, client, nonadmin_headers):
        resp = client.get("/v1/timestamp/batches", headers=nonadmin_headers)
        assert resp.status_code == 403

    def test_verify_batch_requires_admin(self, client, nonadmin_headers):
        fake_id = str(uuid.uuid4())
        resp = client.post(
            f"/v1/timestamp/batches/{fake_id}/verify",
            headers=nonadmin_headers,
        )
        assert resp.status_code == 403

    def test_list_batches_empty(self, client, auth_headers):
        resp = client.get("/v1/timestamp/batches", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_trigger_without_tsa_config(self, client, auth_headers):
        resp = client.post("/v1/timestamp/trigger", headers=auth_headers)
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "TSA_NOT_CONFIGURED"

    def test_list_batches_with_status_filter(self, client, auth_headers):
        resp = client.get(
            "/v1/timestamp/batches?status=pending",
            headers=auth_headers,
        )
        assert resp.status_code == 200
