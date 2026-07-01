from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid

import pytest

from regista._errors import RegistaError

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

from fastapi.testclient import TestClient

from regista import Regista

DSN = os.environ.get(
    "TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
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
def regista_instance():
    project = f"sidecar_test_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, TEST_KEYS)
    yield sub
    sub.close()
    from regista._testing import drop_project_schema
    drop_project_schema(DSN, project)


@pytest.fixture(scope="module")
def client(regista_instance, token_file):
    token_path, _, _ = token_file
    from regista.sidecar.app import create_app
    from regista.sidecar.auth import TokenRegistry

    tokens = TokenRegistry.from_file(token_path)
    app = create_app(regista_instance, tokens, workflow_dir=os.path.dirname(TEST_WORKFLOW))
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
def workflow_id(regista_instance):
    yaml_content = open(TEST_WORKFLOW).read()
    regista_instance.register_workflow(yaml_content)
    return yaml_content


HOOK_TEST_WORKFLOW_YAML = """\
name: hook_test_workflow
version: 1
regista_version: "0.1.0"

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
    def test_docs_disabled_by_default(self, regista_instance, token_file):
        token_path, _, _ = token_file
        from regista.sidecar.app import create_app
        from regista.sidecar.auth import TokenRegistry

        tokens = TokenRegistry.from_file(token_path)
        app = create_app(regista_instance, tokens)
        client2 = TestClient(app)
        assert client2.get("/docs").status_code == 404
        assert client2.get("/openapi.json").status_code == 404

    def test_docs_enabled_with_explicit_url(self, regista_instance, token_file):
        token_path, _, _ = token_file
        from regista.sidecar.app import create_app
        from regista.sidecar.auth import TokenRegistry

        tokens = TokenRegistry.from_file(token_path)
        app = create_app(regista_instance, tokens, docs_url="/docs", openapi_url="/openapi.json")
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
    def _register_hook_workflow(self, regista_instance):
        regista_instance.register_workflow(HOOK_TEST_WORKFLOW_YAML)

    def test_claim_complete_round_trip(self, client, auth_headers, regista_instance):
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

    def test_hook_lease_expiry_requeues(self, client, auth_headers, regista_instance):
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


class TestLinkRoutes:
    def test_create_and_remove_link(self, client, auth_headers, workflow_id):
        resp1 = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "test_workflow",
                "work_item_type": "feature",
                "custom_fields": {"title": "link-src"},
            },
            headers=auth_headers,
        )
        assert resp1.status_code == 200
        src_id = resp1.json()["work_item"]["work_item_id"]

        resp2 = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "test_workflow",
                "work_item_type": "feature",
                "custom_fields": {"title": "link-dst"},
            },
            headers=auth_headers,
        )
        assert resp2.status_code == 200
        dst_id = resp2.json()["work_item"]["work_item_id"]

        resp = client.post(
            "/v1/create_link",
            json={
                "from_work_item_id": src_id,
                "to_work_item_id": dst_id,
                "link_type": "blocks",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200

        resp = client.post(
            "/v1/remove_link",
            json={
                "from_work_item_id": src_id,
                "to_work_item_id": dst_id,
                "link_type": "blocks",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200


class TestUpdateNotBeforeRoute:
    def test_update_not_before(self, client, auth_headers, workflow_id):
        resp = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "test_workflow",
                "work_item_type": "feature",
                "custom_fields": {"title": "nb-test"},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        wi_id = resp.json()["work_item"]["work_item_id"]

        resp = client.post(
            "/v1/update_not_before",
            json={
                "work_item_id": wi_id,
                "not_before": "2026-06-01T00:00:00+00:00",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200


class TestHeartbeatClaimRoute:
    def test_heartbeat_claim(self, client, auth_headers, workflow_id):
        resp = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "test_workflow",
                "work_item_type": "feature",
                "custom_fields": {"title": "hb-test"},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        wi_id = resp.json()["work_item"]["work_item_id"]

        resp = client.post(
            "/v1/acquire_claim",
            json={"work_item_id": wi_id, "ttl_seconds": 300},
            headers=auth_headers,
        )
        assert resp.status_code == 200

        resp = client.post(
            "/v1/heartbeat_claim",
            json={"work_item_id": wi_id, "ttl_seconds": 600},
            headers=auth_headers,
        )
        assert resp.status_code == 200


class TestWitnessRoutes:
    def test_register_list_delete_witness(self, client, auth_headers):
        resp = client.post(
            "/v1/witnesses",
            json={"url": "https://example.com/witness"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        witness_id = resp.json()["witness_id"]

        resp = client.get("/v1/witnesses", headers=auth_headers)
        assert resp.status_code == 200
        assert any(w["witness_id"] == witness_id for w in resp.json())

        resp = client.delete(f"/v1/witnesses/{witness_id}", headers=auth_headers)
        assert resp.status_code == 200

    def test_pause_resume_witness(self, client, auth_headers):
        resp = client.post(
            "/v1/witnesses",
            json={"url": "https://example.com/witness-pr"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        witness_id = resp.json()["witness_id"]

        resp = client.post(
            f"/v1/witnesses/{witness_id}/pause",
            headers=auth_headers,
        )
        assert resp.status_code == 200

        resp = client.post(
            f"/v1/witnesses/{witness_id}/reactivate",
            headers=auth_headers,
        )
        assert resp.status_code == 200

    def test_list_witness_receipts(self, client, auth_headers):
        resp = client.get("/v1/witnesses/receipts", headers=auth_headers)
        assert resp.status_code == 200

    def test_deliver_witness_receipts(self, client, auth_headers):
        resp = client.post("/v1/witnesses/deliver", headers=auth_headers)
        assert resp.status_code == 200

    def test_witness_requires_admin(self, client, nonadmin_headers):
        resp = client.post(
            "/v1/witnesses",
            json={"url": "https://example.com/nope"},
            headers=nonadmin_headers,
        )
        assert resp.status_code == 403


class TestRecurrenceRoutes:
    def test_register_list_cancel_recurrence(self, client, auth_headers):
        resp = client.post(
            "/v1/register_recurrence_rule",
            json={
                "workflow_name": "test_workflow",
                "workflow_version": 1,
                "work_item_type": "feature",
                "template": {"custom_fields": {"title": "recurring"}},
                "schedule_kind": "interval",
                "schedule_expr": "PT1H",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        rule_id = resp.json()["rule_id"]

        resp = client.get("/v1/recurrence_rules", headers=auth_headers)
        assert resp.status_code == 200
        assert any(r["rule_id"] == rule_id for r in resp.json())

        resp = client.post(
            "/v1/cancel_recurrence_rule",
            json={"rule_id": rule_id},
            headers=auth_headers,
        )
        assert resp.status_code == 200

    def test_fire_recurrence_requires_admin(self, client, nonadmin_headers):
        resp = client.post(
            "/v1/fire_recurrence",
            json={"rule_id": str(uuid.uuid4())},
            headers=nonadmin_headers,
        )
        assert resp.status_code == 403

    def test_update_recurrence_requires_admin(self, client, nonadmin_headers):
        resp = client.post(
            "/v1/update_recurrence_rule",
            json={"rule_id": str(uuid.uuid4()), "status": "cancelled"},
            headers=nonadmin_headers,
        )
        assert resp.status_code == 403


class TestBatchRoutes:
    def test_create_work_items_batch(self, client, auth_headers, workflow_id):
        resp = client.post(
            "/v1/create_work_items_batch",
            json={
                "items": [
                    {
                        "workflow_name": "test_workflow",
                        "work_item_type": "feature",
                        "custom_fields": {"title": "batch-1"},
                    },
                    {
                        "workflow_name": "test_workflow",
                        "work_item_type": "feature",
                        "custom_fields": {"title": "batch-2"},
                    },
                ]
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert len(resp.json()["results"]) == 2

    def test_create_work_items_batch_empty_rejected(self, client, auth_headers):
        resp = client.post(
            "/v1/create_work_items_batch",
            json={"items": []},
            headers=auth_headers,
        )
        assert resp.status_code == 400


class TestReadEventsSinceRoute:
    def test_read_events_since(self, client, auth_headers, workflow_id):
        resp = client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "test_workflow",
                "work_item_type": "feature",
                "custom_fields": {"title": "since-test"},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        wi_id = resp.json()["work_item"]["work_item_id"]

        resp = client.post(
            "/v1/read_events_since",
            json={"work_item_id": wi_id, "after_seq": 0},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert len(resp.json()) >= 1


class TestComposeWorkflowRoute:
    def test_compose_workflow(self, client, auth_headers):
        resp = client.post(
            "/v1/compose_workflow",
            json={"file_path": TEST_WORKFLOW},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert "composed" in resp.json()
        assert "source_map" in resp.json()

    def test_compose_requires_admin(self, client, nonadmin_headers):
        resp = client.post(
            "/v1/compose_workflow",
            json={"file_path": TEST_WORKFLOW},
            headers=nonadmin_headers,
        )
        assert resp.status_code == 403


class TestErrorCodeCoverage:
    def test_all_error_codes_have_status_mapping(self):
        from regista._errors import ErrorCode
        from regista.sidecar.errors import _STATUS_MAP

        missing = set(ErrorCode) - set(_STATUS_MAP.keys())
        assert missing == set(), (
            f"ErrorCode members missing from sidecar _STATUS_MAP: {missing}. "
            "Every ErrorCode must have an explicit HTTP status mapping."
        )

    def test_status_map_values_are_valid_http_codes(self):
        from regista.sidecar.errors import _STATUS_MAP

        valid = {400, 401, 403, 404, 409, 500, 502, 503}
        for code, status in _STATUS_MAP.items():
            assert status in valid, (
                f"_STATUS_MAP[{code!r}] = {status} is not a standard HTTP error status"
            )


HOOK_TEST_WORKFLOW_B_YAML = """\
name: hook_test_workflow_b
version: 1
regista_version: "0.1.0"

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
      - on_complete_b

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


def _make_workflow_scoped_token_file():
    scoped_raw = "scoped-secret-token-abc"
    scoped_sha256 = hashlib.sha256(scoped_raw.encode()).hexdigest()
    admin_raw = "admin-all-workflows-token-xyz"
    admin_sha256 = hashlib.sha256(admin_raw.encode()).hexdigest()
    data = {
        "tokens": [
            {
                "token_sha256": scoped_sha256,
                "actor_id": "scoped-agent",
                "actor_kind": "agent",
                "allowed_roles": ["agent"],
                "allowed_workflows": ["hook_test_workflow"],
            },
            {
                "token_sha256": admin_sha256,
                "actor_id": "admin-agent",
                "actor_kind": "agent",
                "allowed_roles": ["agent", "admin"],
            },
        ]
    }
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    json.dump(data, f)
    f.close()
    return f.name, scoped_raw, admin_raw


@pytest.fixture(scope="module")
def scoped_token_file():
    path, scoped_raw, admin_raw = _make_workflow_scoped_token_file()
    yield path, scoped_raw, admin_raw
    os.unlink(path)


@pytest.fixture(scope="module")
def scoped_client(regista_instance, scoped_token_file):
    regista_instance.register_workflow(HOOK_TEST_WORKFLOW_YAML)
    regista_instance.register_workflow(HOOK_TEST_WORKFLOW_B_YAML)
    token_path, _, _ = scoped_token_file
    from regista.sidecar.app import create_app
    from regista.sidecar.auth import TokenRegistry

    tokens = TokenRegistry.from_file(token_path)
    app = create_app(regista_instance, tokens)
    return TestClient(app)


@pytest.fixture(scope="module")
def scoped_headers(scoped_token_file):
    _, scoped_raw, _ = scoped_token_file
    return {"Authorization": f"Bearer {scoped_raw}"}


@pytest.fixture(scope="module")
def admin_all_workflows_headers(scoped_token_file):
    _, _, admin_raw = scoped_token_file
    return {"Authorization": f"Bearer {admin_raw}"}


class TestHookWorkflowScoping:
    def test_token_with_allowed_workflows_claims_only_matching_hooks(
        self, scoped_client, scoped_headers, admin_all_workflows_headers,
    ):
        resp = scoped_client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "hook_test_workflow",
                "work_item_type": "task",
                "custom_fields": {"title": "scoped wf_a"},
            },
            headers=scoped_headers,
        )
        assert resp.status_code == 200
        wi_a_id = resp.json()["work_item"]["work_item_id"]

        scoped_client.post(
            "/v1/register_actor_role",
            json={"role": "agent"},
            headers=scoped_headers,
        )

        resp = scoped_client.post(
            "/v1/transition",
            json={
                "work_item_id": wi_a_id,
                "transition_name": "complete",
                "actor_metadata": {"role": "agent"},
            },
            headers=scoped_headers,
        )
        assert resp.status_code == 200

        resp = scoped_client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "hook_test_workflow_b",
                "work_item_type": "task",
                "custom_fields": {"title": "scoped wf_b"},
            },
            headers=admin_all_workflows_headers,
        )
        assert resp.status_code == 200
        wi_b_id = resp.json()["work_item"]["work_item_id"]

        scoped_client.post(
            "/v1/register_actor_role",
            json={"role": "agent"},
            headers=admin_all_workflows_headers,
        )

        resp = scoped_client.post(
            "/v1/transition",
            json={
                "work_item_id": wi_b_id,
                "transition_name": "complete",
                "actor_metadata": {"role": "agent"},
            },
            headers=admin_all_workflows_headers,
        )
        assert resp.status_code == 200

        resp = scoped_client.post(
            "/v1/hooks/claim",
            json={"max_batch": 10, "lease_seconds": 60},
            headers=scoped_headers,
        )
        assert resp.status_code == 200
        hooks = resp.json()
        assert len(hooks) >= 1
        for h in hooks:
            assert h["hook_name"] == "on_complete"

    def test_scoped_token_complete_forbidden_for_unallowed_workflow(
        self, scoped_client, scoped_headers, admin_all_workflows_headers,
    ):
        resp = scoped_client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "hook_test_workflow_b",
                "work_item_type": "task",
                "custom_fields": {"title": "unauthorized wf_b"},
            },
            headers=admin_all_workflows_headers,
        )
        assert resp.status_code == 200
        wi_b_id = resp.json()["work_item"]["work_item_id"]

        scoped_client.post(
            "/v1/register_actor_role",
            json={"role": "agent"},
            headers=admin_all_workflows_headers,
        )

        resp = scoped_client.post(
            "/v1/transition",
            json={
                "work_item_id": wi_b_id,
                "transition_name": "complete",
                "actor_metadata": {"role": "agent"},
            },
            headers=admin_all_workflows_headers,
        )
        assert resp.status_code == 200

        resp = scoped_client.post(
            "/v1/hooks/claim",
            json={"max_batch": 10, "lease_seconds": 60},
            headers=admin_all_workflows_headers,
        )
        assert resp.status_code == 200
        wf_b_hooks = [
            h for h in resp.json() if h["hook_name"] == "on_complete_b"
        ]
        assert len(wf_b_hooks) >= 1
        hook_b_id = wf_b_hooks[0]["hook_queue_id"]

        resp = scoped_client.post(
            f"/v1/hooks/{hook_b_id}/complete",
            json={},
            headers=scoped_headers,
        )
        assert resp.status_code == 403

    def test_scoped_token_fail_forbidden_for_unallowed_workflow(
        self, scoped_client, scoped_headers, admin_all_workflows_headers,
    ):
        resp = scoped_client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "hook_test_workflow_b",
                "work_item_type": "task",
                "custom_fields": {"title": "fail wf_b"},
            },
            headers=admin_all_workflows_headers,
        )
        assert resp.status_code == 200
        wi_b_id = resp.json()["work_item"]["work_item_id"]

        scoped_client.post(
            "/v1/register_actor_role",
            json={"role": "agent"},
            headers=admin_all_workflows_headers,
        )

        resp = scoped_client.post(
            "/v1/transition",
            json={
                "work_item_id": wi_b_id,
                "transition_name": "complete",
                "actor_metadata": {"role": "agent"},
            },
            headers=admin_all_workflows_headers,
        )
        assert resp.status_code == 200

        resp = scoped_client.post(
            "/v1/hooks/claim",
            json={"max_batch": 10, "lease_seconds": 60},
            headers=admin_all_workflows_headers,
        )
        assert resp.status_code == 200
        hook_b_id = None
        for h in resp.json():
            if h["hook_name"] == "on_complete_b":
                hook_b_id = h["hook_queue_id"]
                break
        assert hook_b_id is not None

        resp = scoped_client.post(
            f"/v1/hooks/{hook_b_id}/fail",
            json={"error": "should be forbidden"},
            headers=scoped_headers,
        )
        assert resp.status_code == 403

    def test_unrestricted_token_can_access_all_workflow_hooks(
        self, scoped_client, admin_all_workflows_headers,
    ):
        resp = scoped_client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "hook_test_workflow",
                "work_item_type": "task",
                "custom_fields": {"title": "unrestricted wf_a"},
            },
            headers=admin_all_workflows_headers,
        )
        assert resp.status_code == 200
        wi_a_id = resp.json()["work_item"]["work_item_id"]

        scoped_client.post(
            "/v1/register_actor_role",
            json={"role": "agent"},
            headers=admin_all_workflows_headers,
        )

        resp = scoped_client.post(
            "/v1/transition",
            json={
                "work_item_id": wi_a_id,
                "transition_name": "complete",
                "actor_metadata": {"role": "agent"},
            },
            headers=admin_all_workflows_headers,
        )
        assert resp.status_code == 200

        resp = scoped_client.post(
            "/v1/hooks/claim",
            json={"max_batch": 10, "lease_seconds": 60},
            headers=admin_all_workflows_headers,
        )
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_token_file_parses_allowed_workflows(self):
        raw_token = "wf-scoped-token"
        token_sha256 = hashlib.sha256(raw_token.encode()).hexdigest()
        data = {
            "tokens": [
                {
                    "token_sha256": token_sha256,
                    "actor_id": "wf-only",
                    "actor_kind": "agent",
                    "allowed_roles": ["agent"],
                    "allowed_workflows": ["wf_a", "wf_b"],
                }
            ]
        }
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        json.dump(data, f)
        f.close()
        try:
            from regista.sidecar.auth import TokenRegistry
            registry = TokenRegistry.from_file(f.name)
            actor = registry.authenticate(raw_token)
            assert actor is not None
            assert actor.allowed_workflows == ("wf_a", "wf_b")
            assert actor.can_access_workflow("wf_a") is True
            assert actor.can_access_workflow("wf_c") is False
            assert actor.can_access_workflow(None) is False
        finally:
            os.unlink(f.name)

    def test_empty_allowed_workflows_rejected(self):
        raw_token = "empty-wf-token"
        token_sha256 = hashlib.sha256(raw_token.encode()).hexdigest()
        data = {
            "tokens": [
                {
                    "token_sha256": token_sha256,
                    "actor_id": "restricted-wf",
                    "actor_kind": "agent",
                    "allowed_roles": ["agent"],
                    "allowed_workflows": [],
                }
            ]
        }
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        json.dump(data, f)
        f.close()
        try:
            from regista.sidecar.auth import TokenRegistry
            with pytest.raises(RegistaError, match="cannot be empty"):
                TokenRegistry.from_file(f.name)
        finally:
            os.unlink(f.name)
