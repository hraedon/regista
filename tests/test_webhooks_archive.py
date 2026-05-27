from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from regista import Regista
from regista._testing import drop_project_schema

DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = "tests/test_keys.json"
WORKFLOW_PATH = "tests/test_workflow.yaml"


@pytest.fixture(scope="module")
def project():
    name = f"webhook_archive_{uuid.uuid4().hex[:8]}"
    yield name
    drop_project_schema(DSN, name)


@pytest.fixture(scope="module")
def sub(project):
    s = Regista.create_project(DSN, project, KEY_PATH)
    with open(WORKFLOW_PATH) as f:
        s.register_workflow(f.read())
    yield s
    s.close()


class TestWebhookLifecycle:
    def test_register_webhook(self, sub):
        result = sub.register_webhook(
            url="https://example.com/hook",
            transitions=["start"],
        )
        assert "webhook_id" in result
        assert result["url"] == "https://example.com/hook"
        assert result["status"] == "active"

    def test_list_webhooks(self, sub):
        result = sub.list_webhooks()
        assert len(result) >= 1
        assert any(w["url"] == "https://example.com/hook" for w in result)

    def test_list_webhooks_by_status(self, sub):
        result = sub.list_webhooks(status="active")
        assert len(result) >= 1
        assert all(w["status"] == "active" for w in result)

    def test_unregister_webhook(self, sub):
        reg = sub.register_webhook(url="https://example.com/hook2")
        webhook_id = reg["webhook_id"]
        sub.unregister_webhook(webhook_id)
        remaining = sub.list_webhooks()
        assert not any(str(w["webhook_id"]) == str(webhook_id) for w in remaining)

    def test_register_webhook_with_workflows(self, sub):
        result = sub.register_webhook(
            url="https://example.com/hook3",
            workflows=["test_workflow"],
        )
        assert result["status"] == "active"
        webhooks = sub.list_webhooks()
        match = [w for w in webhooks if str(w["webhook_id"]) == str(result["webhook_id"])]
        assert len(match) == 1
        assert match[0]["workflows"] == ["test_workflow"]

    def test_pause_resume_webhook(self, sub):
        reg = sub.register_webhook(url="https://example.com/hook4")
        webhook_id = reg["webhook_id"]
        sub.pause_webhook(webhook_id)
        paused = sub.list_webhooks(status="paused")
        assert any(str(w["webhook_id"]) == str(webhook_id) for w in paused)
        sub.resume_webhook(webhook_id)
        active = sub.list_webhooks(status="active")
        assert any(str(w["webhook_id"]) == str(webhook_id) for w in active)


class TestArchiveEvents:
    def test_archive_dry_run_empty(self, sub):
        count = sub.archive_events(
            before_timestamp=datetime.now(UTC) + timedelta(days=365),
            dry_run=True,
        )
        assert count == 0

    def test_archive_dry_run_with_events(self, sub):
        sub.create_work_item("test_workflow", "feature", "archive-test",
                             custom_fields={"title": "archive-test"})
        count = sub.archive_events(
            before_timestamp=datetime.now(UTC) + timedelta(days=365),
            dry_run=True,
        )
        assert count >= 1

    def test_archive_actual(self, sub):
        wi, _ = sub.create_work_item("test_workflow", "feature", "archive-actual",
                                     custom_fields={"title": "archive-actual"})
        before = datetime.now(UTC) + timedelta(days=365)
        count = sub.archive_events(before_timestamp=before, dry_run=False)
        assert count >= 1
        remaining = sub.read_events(work_item_id=wi.work_item_id)
        assert len(remaining) == 0

    def test_archive_idempotent(self, sub):
        sub.create_work_item("test_workflow", "feature", "archive-idem",
                             custom_fields={"title": "archive-idem"})
        before = datetime.now(UTC) + timedelta(days=365)
        sub.archive_events(before_timestamp=before)
        count2 = sub.archive_events(before_timestamp=before)
        assert count2 == 0


class TestWebhookSidecarRoutes:
    @pytest.fixture(autouse=True)
    def _setup(self, sub):
        self.sub = sub

    def test_register_list_remove_via_sidecar(self, client, auth_headers):
        resp = client.post(
            "/v1/webhooks",
            json={"url": "https://example.com/sc-hook"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        webhook_id = resp.json()["webhook_id"]

        resp = client.get("/v1/webhooks", headers=auth_headers)
        assert resp.status_code == 200
        assert any(w["webhook_id"] == webhook_id for w in resp.json())

        resp = client.delete(f"/v1/webhooks/{webhook_id}", headers=auth_headers)
        assert resp.status_code == 200

    def test_pause_resume_via_sidecar(self, client, auth_headers):
        resp = client.post(
            "/v1/webhooks",
            json={"url": "https://example.com/sc-pause"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        webhook_id = resp.json()["webhook_id"]

        resp = client.post(
            f"/v1/webhooks/{webhook_id}/pause",
            headers=auth_headers,
        )
        assert resp.status_code == 200

        resp = client.post(
            f"/v1/webhooks/{webhook_id}/resume",
            headers=auth_headers,
        )
        assert resp.status_code == 200

    def test_register_requires_admin(self, client, nonadmin_headers):
        resp = client.post(
            "/v1/webhooks",
            json={"url": "https://example.com/nope"},
            headers=nonadmin_headers,
        )
        assert resp.status_code == 403


class TestArchiveSidecarRoutes:
    def test_archive_dry_run_via_sidecar(self, client, auth_headers):
        resp = client.post(
            "/v1/archive_events",
            json={
                "before_timestamp": "2099-01-01T00:00:00+00:00",
                "dry_run": True,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["dry_run"] is True

    def test_archive_requires_admin(self, client, nonadmin_headers):
        resp = client.post(
            "/v1/archive_events",
            json={
                "before_timestamp": "2099-01-01T00:00:00+00:00",
                "dry_run": True,
            },
            headers=nonadmin_headers,
        )
        assert resp.status_code == 403


@pytest.fixture(scope="module")
def client(sub):
    import hashlib
    import json
    import tempfile

    from fastapi.testclient import TestClient

    from regista.sidecar.app import create_app
    from regista.sidecar.auth import TokenRegistry

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
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    json.dump(data, f)
    f.close()
    tokens = TokenRegistry.from_file(f.name)
    app = create_app(sub, tokens)
    yield TestClient(app)
    import os
    os.unlink(f.name)


@pytest.fixture(scope="module")
def auth_headers():
    return {"Authorization": "Bearer test-secret-token-12345"}


@pytest.fixture(scope="module")
def nonadmin_headers():
    return {"Authorization": "Bearer test-nonadmin-token-67890"}
