from __future__ import annotations

import hashlib
import os
import tempfile
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

from regista._errors import ErrorCode, RegistaError
from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = os.environ.get(
    "TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)
KEY_PATH = str(TESTS_DIR / "test_keys.json")

HOOK_WORKFLOW_YAML = """\
name: toctou_hook_test
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
    hooks: [on_complete]

roles:
  - name: agent

work_item_types:
  - name: task
    custom_fields: []

link_types: []
attempt_threshold: 99
"""


def _trigger_hook(regista):
    wi, _ = regista.create_work_item(
        workflow_name="toctou_hook_test",
        work_item_type="task",
        actor_id="agent-1",
        custom_fields={},
    )
    regista.transition(
        work_item_id=wi.work_item_id,
        transition_name="complete",
        actor_id="agent-1",
    )
    return wi


class TestInMemoryHookOwnership:
    @pytest.fixture
    def regista(self):
        sub = InMemoryRegista(hmac_key_path=KEY_PATH)
        sub.register_workflow(HOOK_WORKFLOW_YAML)
        return sub

    def test_complete_rejects_wrong_actor(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        assert len(claimed) == 1
        hook_id = claimed[0].hook_queue_id

        with pytest.raises(RegistaError) as exc:
            regista.complete_hook(hook_id, actor_id="bob")
        assert exc.value.code == ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER

    def test_complete_works_with_matching_actor(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        regista.complete_hook(hook_id, actor_id="alice")
        entry = next(e for e in regista._hook_queue if e["id"] == hook_id)
        assert entry["status"] == "completed"
        assert entry["claimed_by"] is None

    def test_complete_backward_compat_no_actor_id(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        regista.complete_hook(hook_id)
        entry = next(e for e in regista._hook_queue if e["id"] == hook_id)
        assert entry["status"] == "completed"

    def test_fail_rejects_wrong_actor(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        with pytest.raises(RegistaError) as exc:
            regista.fail_hook(hook_id, "error", actor_id="bob")
        assert exc.value.code == ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER

    def test_fail_works_with_matching_actor(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        regista.fail_hook(hook_id, "error", actor_id="alice")
        entry = next(e for e in regista._hook_queue if e["id"] == hook_id)
        assert entry["status"] == "pending"
        assert entry["claimed_by"] is None

    def test_fail_backward_compat_no_actor_id(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        regista.fail_hook(hook_id, "error")
        entry = next(e for e in regista._hook_queue if e["id"] == hook_id)
        assert entry["status"] == "pending"

    def test_sweep_clears_claimed_by(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=1, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        import time
        time.sleep(2)

        swept = regista.sweep_expired_hook_leases()
        assert swept >= 1
        entry = next(e for e in regista._hook_queue if e["id"] == hook_id)
        assert entry["status"] == "pending"
        assert entry["claimed_by"] is None

    def test_claim_without_actor_id_backward_compat(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60)
        hook_id = claimed[0].hook_queue_id

        regista.complete_hook(hook_id)
        entry = next(e for e in regista._hook_queue if e["id"] == hook_id)
        assert entry["status"] == "completed"

    def test_claim_without_actor_id_rejects_actor_id_complete(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60)
        hook_id = claimed[0].hook_queue_id

        with pytest.raises(RegistaError) as exc:
            regista.complete_hook(hook_id, actor_id="anyone")
        assert exc.value.code == ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER

    def test_toctou_scenario_wrong_actor_after_steal(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=1, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        import time
        time.sleep(2)
        regista.sweep_expired_hook_leases()

        re_claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="bob")
        assert any(c.hook_queue_id == hook_id for c in re_claimed)

        with pytest.raises(RegistaError) as exc:
            regista.complete_hook(hook_id, actor_id="alice")
        assert exc.value.code == ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER

        regista.complete_hook(hook_id, actor_id="bob")
        entry = next(e for e in regista._hook_queue if e["id"] == hook_id)
        assert entry["status"] == "completed"


def _raw_conn(schema: str):
    conn = psycopg.connect(DSN, row_factory=dict_row, autocommit=True)
    conn.execute(f'SET search_path TO "{schema}"')
    return conn


class TestPostgresHookOwnership:
    @pytest.fixture(scope="class")
    def regista(self):
        from regista import Regista

        project = f"test_toctou_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        sub.register_workflow(HOOK_WORKFLOW_YAML)
        yield sub
        sub.close()
        drop_project_schema(DSN, project)

    def test_complete_rejects_wrong_actor(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        assert len(claimed) == 1
        hook_id = claimed[0].hook_queue_id

        with pytest.raises(RegistaError) as exc:
            regista.complete_hook(hook_id, actor_id="bob")
        assert exc.value.code == ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER

    def test_complete_works_with_matching_actor(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        regista.complete_hook(hook_id, actor_id="alice")

        schema = regista._mgr.schema
        with _raw_conn(schema) as conn:
            row = conn.execute(
                "SELECT status, claimed_by FROM hook_queue WHERE id = %s",
                [hook_id],
            ).fetchone()
        assert row["status"] == "completed"
        assert row["claimed_by"] is None

    def test_complete_backward_compat_no_actor_id(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        regista.complete_hook(hook_id)

        schema = regista._mgr.schema
        with _raw_conn(schema) as conn:
            row = conn.execute(
                "SELECT status FROM hook_queue WHERE id = %s",
                [hook_id],
            ).fetchone()
        assert row["status"] == "completed"

    def test_fail_rejects_wrong_actor(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        with pytest.raises(RegistaError) as exc:
            regista.fail_hook(hook_id, "error", actor_id="bob")
        assert exc.value.code == ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER

    def test_fail_works_with_matching_actor(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        regista.fail_hook(hook_id, "error", actor_id="alice")

        schema = regista._mgr.schema
        with _raw_conn(schema) as conn:
            row = conn.execute(
                "SELECT status, claimed_by FROM hook_queue WHERE id = %s",
                [hook_id],
            ).fetchone()
        assert row["status"] == "pending"
        assert row["claimed_by"] is None

    def test_fail_backward_compat_no_actor_id(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        regista.fail_hook(hook_id, "error")

        schema = regista._mgr.schema
        with _raw_conn(schema) as conn:
            row = conn.execute(
                "SELECT status FROM hook_queue WHERE id = %s",
                [hook_id],
            ).fetchone()
        assert row["status"] == "pending"

    def test_claimed_by_column_populated(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=60, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        schema = regista._mgr.schema
        with _raw_conn(schema) as conn:
            row = conn.execute(
                "SELECT claimed_by FROM hook_queue WHERE id = %s",
                [hook_id],
            ).fetchone()
        assert row["claimed_by"] == "alice"

    def test_sweep_clears_claimed_by(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=1, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        schema = regista._mgr.schema
        with _raw_conn(schema) as conn:
            conn.execute(
                "UPDATE hook_queue SET lease_expires_at = now() - interval '1 second' "
                "WHERE id = %s",
                [hook_id],
            )

        regista.sweep_expired_hook_leases()

        with _raw_conn(schema) as conn:
            row = conn.execute(
                "SELECT status, claimed_by FROM hook_queue WHERE id = %s",
                [hook_id],
            ).fetchone()
        assert row["status"] == "pending"
        assert row["claimed_by"] is None

    def test_toctou_scenario_wrong_actor_after_steal(self, regista):
        _trigger_hook(regista)
        claimed = regista.claim_hooks(max_batch=1, lease_seconds=1, actor_id="alice")
        hook_id = claimed[0].hook_queue_id

        schema = regista._mgr.schema
        with _raw_conn(schema) as conn:
            conn.execute(
                "UPDATE hook_queue SET lease_expires_at = now() - interval '1 second' "
                "WHERE id = %s",
                [hook_id],
            )

        regista.sweep_expired_hook_leases()

        re_claimed = regista.claim_hooks(max_batch=100, lease_seconds=60, actor_id="bob")
        assert any(c.hook_queue_id == hook_id for c in re_claimed)

        with pytest.raises(RegistaError) as exc:
            regista.complete_hook(hook_id, actor_id="alice")
        assert exc.value.code == ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER

        regista.complete_hook(hook_id, actor_id="bob")

        with _raw_conn(schema) as conn:
            row = conn.execute(
                "SELECT status FROM hook_queue WHERE id = %s",
                [hook_id],
            ).fetchone()
        assert row["status"] == "completed"


def _make_token_file():
    raw_token = "toctou-secret-token-12345"
    token_sha256 = hashlib.sha256(raw_token.encode()).hexdigest()
    other_raw = "toctou-other-token-67890"
    other_sha256 = hashlib.sha256(other_raw.encode()).hexdigest()
    data = {
        "tokens": [
            {
                "token_sha256": token_sha256,
                "actor_id": "alice",
                "actor_kind": "agent",
                "allowed_roles": ["agent", "admin"],
            },
            {
                "token_sha256": other_sha256,
                "actor_id": "bob",
                "actor_kind": "agent",
                "allowed_roles": ["agent", "admin"],
            },
        ]
    }
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    import json
    json.dump(data, f)
    f.close()
    return f.name, raw_token, other_raw


@pytest.fixture(scope="module")
def token_file():
    path, raw, other_raw = _make_token_file()
    yield path, raw, other_raw
    os.unlink(path)


@pytest.fixture(scope="module")
def sidecar_regista():
    from regista import Regista

    project = f"test_toctou_sidecar_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow(HOOK_WORKFLOW_YAML)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


@pytest.fixture(scope="module")
def sidecar_client(sidecar_regista, token_file):
    pytest.importorskip("fastapi")
    pytest.importorskip("uvicorn")

    from fastapi.testclient import TestClient

    from regista.sidecar.app import create_app
    from regista.sidecar.auth import TokenRegistry

    token_path, _, _ = token_file
    tokens = TokenRegistry.from_file(token_path)
    app = create_app(sidecar_regista, tokens)
    client = TestClient(app)
    yield client


@pytest.fixture(scope="module")
def alice_headers(token_file):
    _, raw, _ = token_file
    return {"Authorization": f"Bearer {raw}"}


@pytest.fixture(scope="module")
def bob_headers(token_file):
    _, _, other_raw = token_file
    return {"Authorization": f"Bearer {other_raw}"}


class TestSidecarHookOwnership:
    def test_complete_rejects_wrong_actor(
        self, sidecar_client, alice_headers, bob_headers, sidecar_regista,
    ):
        sidecar_regista.register_actor_role("alice", "agent")
        sidecar_regista.register_actor_role("bob", "agent")

        resp = sidecar_client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "toctou_hook_test",
                "work_item_type": "task",
                "custom_fields": {},
            },
            headers=alice_headers,
        )
        assert resp.status_code == 200
        wi_id = resp.json()["work_item"]["work_item_id"]

        sidecar_client.post(
            "/v1/transition",
            json={
                "work_item_id": wi_id,
                "transition_name": "complete",
                "actor_metadata": {"role": "agent"},
            },
            headers=alice_headers,
        )

        resp = sidecar_client.post(
            "/v1/hooks/claim",
            json={"max_batch": 10, "lease_seconds": 60},
            headers=alice_headers,
        )
        assert resp.status_code == 200
        hooks = resp.json()
        assert len(hooks) >= 1
        hook_id = hooks[0]["hook_queue_id"]

        resp = sidecar_client.post(
            f"/v1/hooks/{hook_id}/complete",
            json={},
            headers=bob_headers,
        )
        assert resp.status_code == 409
        assert resp.json()["error"]["code"] == "HOOK_NOT_CLAIMED_BY_CALLER"

    def test_complete_works_with_matching_actor(
        self, sidecar_client, alice_headers, sidecar_regista,
    ):
        resp = sidecar_client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "toctou_hook_test",
                "work_item_type": "task",
                "custom_fields": {},
            },
            headers=alice_headers,
        )
        wi_id = resp.json()["work_item"]["work_item_id"]

        sidecar_client.post(
            "/v1/transition",
            json={
                "work_item_id": wi_id,
                "transition_name": "complete",
                "actor_metadata": {"role": "agent"},
            },
            headers=alice_headers,
        )

        resp = sidecar_client.post(
            "/v1/hooks/claim",
            json={"max_batch": 10, "lease_seconds": 60},
            headers=alice_headers,
        )
        hooks = resp.json()
        hook_id = hooks[0]["hook_queue_id"]

        resp = sidecar_client.post(
            f"/v1/hooks/{hook_id}/complete",
            json={},
            headers=alice_headers,
        )
        assert resp.status_code == 200

    def test_fail_rejects_wrong_actor(
        self, sidecar_client, alice_headers, bob_headers, sidecar_regista,
    ):
        resp = sidecar_client.post(
            "/v1/create_work_item",
            json={
                "workflow_name": "toctou_hook_test",
                "work_item_type": "task",
                "custom_fields": {},
            },
            headers=alice_headers,
        )
        wi_id = resp.json()["work_item"]["work_item_id"]

        sidecar_client.post(
            "/v1/transition",
            json={
                "work_item_id": wi_id,
                "transition_name": "complete",
                "actor_metadata": {"role": "agent"},
            },
            headers=alice_headers,
        )

        resp = sidecar_client.post(
            "/v1/hooks/claim",
            json={"max_batch": 10, "lease_seconds": 60},
            headers=alice_headers,
        )
        hooks = resp.json()
        hook_id = hooks[0]["hook_queue_id"]

        resp = sidecar_client.post(
            f"/v1/hooks/{hook_id}/fail",
            json={"error": "should be rejected"},
            headers=bob_headers,
        )
        assert resp.status_code == 409
        assert resp.json()["error"]["code"] == "HOOK_NOT_CLAIMED_BY_CALLER"
