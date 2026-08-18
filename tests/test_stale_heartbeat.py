from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from _v6_fixtures import make_v6_keyset, open_v6_epoch

from regista._errors import ErrorCode, RegistaError
from regista._testing import raw_transaction
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

#: Two canonical claimants (``TRUST-DOMAIN.md`` §2.1). The bare ``agent-1``/``agent-2``
#: spellings are refused at the v6 ingress; "two distinct agents contest one claim" is
#: all this file needs of them.
OWNER = "agent:worker"
OTHER = "agent:reviewer"


@pytest.fixture
def regista(tmp_path):
    from regista import Regista

    project = f"test_ac07_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(DSN, project, keyset.path)
    # The clean v6 epoch before the registration: `register_workflow_file` emits
    # the signed `workflow_registered` event admission gate 1 requires, and there
    # is no epoch to append it to until `open_v6_epoch` returns.
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestAC07StaleHeartbeat:
    def test_heartbeat_rejects_different_actor(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=OWNER,
            custom_fields={"title": "Stale heartbeat"},
        )
        regista.acquire_claim(wi.work_item_id, OWNER, ttl_seconds=300)

        with pytest.raises(RegistaError) as exc_info:
            regista.heartbeat_claim(wi.work_item_id, OTHER, ttl_seconds=300)
        assert exc_info.value.code == ErrorCode.CLAIM_LOST

    def test_heartbeat_rejects_after_auto_steal(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=OWNER,
            custom_fields={"title": "Auto-steal"},
        )

        regista.acquire_claim(wi.work_item_id, OWNER, ttl_seconds=300)

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE claims SET expires_at = now() - interval '1 second' "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        claim2 = regista.acquire_claim(wi.work_item_id, OTHER, ttl_seconds=300)
        assert claim2.attempt_number == 2

        with pytest.raises(RegistaError) as exc_info:
            regista.heartbeat_claim(wi.work_item_id, OWNER, ttl_seconds=300)
        assert exc_info.value.code == ErrorCode.CLAIM_LOST

    def test_valid_heartbeat_succeeds(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=OWNER,
            custom_fields={"title": "Valid heartbeat"},
        )
        claim1 = regista.acquire_claim(wi.work_item_id, OWNER, ttl_seconds=60)
        claim2 = regista.heartbeat_claim(wi.work_item_id, OWNER, ttl_seconds=300)
        assert claim2.actor_id == OWNER
        assert claim2.expires_at > claim1.expires_at
