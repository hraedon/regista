from __future__ import annotations

from pathlib import Path

import pytest
from _helpers import DSN
from _v6_fixtures import make_v6_keyset, open_v6_epoch

from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

#: Canonical per TRUST-DOMAIN.md §2.1. "agent-1" is ungrammatical and the v6 ingress
#: refuses it, which is criterion 19's inversion doing its job.
ACTOR = "agent:hash-chain"
#: The pre-epoch spelling, still used by the one unmigrated test below.
LEGACY_ACTOR = "agent-1"
KEY_PATH = str(TESTS_DIR / "test_keys.json")


@pytest.fixture
def keyset(tmp_path):
    return make_v6_keyset(tmp_path, principals=(ACTOR,))


@pytest.fixture
def regista(keyset):
    from regista import Regista

    project = f"test_hash_chain_{__import__('uuid').uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, keyset.path)
    open_v6_epoch(sub, keyset, principals=(ACTOR,))
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


@pytest.fixture
def unmigrated_regista():
    """A project with NO v6 epoch, for the one test here that calls ``replay()``.

    Deliberate, and narrow. ``_replay`` verifies every event through
    ``verify_event_strict``, which still returns ``INVALID`` /
    ``envelope_schema_incomplete`` for **every** v6 row — the Phase 2 clamp
    (``_verification._verify_v6_row``'s final return). So a migrated fixture makes
    ``replay()`` report ``halted=1`` on a perfectly good chain, which is a Phase 2
    dependency and not a defect in this test.

    Keeping this one node on an unmigrated project preserves the ``GENESIS_REQUIRED``
    form the epoch-blocked manifest records for it, so the other two nodes in this file
    can leave the manifest now instead of waiting. **This is a last-resort pattern, not
    the plan:** every file whose nodes verify should be migrated AFTER Phase 2, in one
    pass, rather than split like this.
    """
    from regista import Regista

    project = f"test_hash_chain_legacy_{__import__('uuid').uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestBC233HashChain:
    def test_first_event_has_no_prev_hash(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR,
            custom_fields={"title": "first"},
        )
        evts = regista.read_events(work_item_id=wi.work_item_id, limit=1)
        assert evts[0].prev_event_hash is None

    def test_replay_hash_chain_check(self, unmigrated_regista):
        sub = unmigrated_regista
        sub.register_actor_role(LEGACY_ACTOR, "agent")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=LEGACY_ACTOR,
            custom_fields={"title": "replay"},
        )
        sub.transition(
            wi.work_item_id,
            "start",
            LEGACY_ACTOR,
            actor_metadata={"role": "agent"},
        )
        report = sub.replay()
        assert report.halted == 0
        assert report.warnings == 0


class TestBC233HashChainInMemory:
    def test_first_event_has_no_prev_hash(self, keyset):
        # The SAME two-call migration as the Postgres fixture above, on the in-memory
        # backend: WI-287 gave InMemoryRegista a real v6 epoch and P1.7 routed the
        # ordinary API to the shared writer, so nothing here is backend-specific.
        sub = InMemoryRegista(project="test", hmac_key_path=keyset.path)
        open_v6_epoch(sub, keyset, principals=(ACTOR,))
        sub.register_workflow_file(WORKFLOW_PATH)
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR,
            custom_fields={"title": "first"},
        )
        evts = sub.read_events(work_item_id=wi.work_item_id, limit=1)
        assert evts[0].prev_event_hash is None
