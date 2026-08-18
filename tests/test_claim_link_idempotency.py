from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._errors import RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


ACTOR = "agent:worker"


@pytest.fixture(scope="module")
def regista(tmp_path_factory):
    from regista import Regista
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project = f"test_claim_link_idem_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path_factory.mktemp("claim_link_keys"))
    sub = Regista.create_project(DSN, project, keyset.path)
    # Genesis before registration: `register_workflow_file` emits the signed
    # `workflow_registered` event and has no epoch to append it to before
    # `open_v6_epoch` returns.
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestClaimIdempotency:
    def test_acquire_claim_same_event_id_no_duplicate_events(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR,
            custom_fields={"title": "claim idem"},
        )

        eid = uuid.uuid4()
        regista.acquire_claim(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR,
            ttl_seconds=60,
            event_id=eid,
        )
        events_after_first = regista.read_events(work_item_id=wi.work_item_id)
        first_count = len(events_after_first)

        regista.acquire_claim(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR,
            ttl_seconds=60,
            event_id=eid,
        )
        events_after_second = regista.read_events(work_item_id=wi.work_item_id)

        assert len(events_after_second) == first_count

    def test_release_claim_event_id_dedup(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR,
            custom_fields={"title": "release idem"},
        )

        regista.acquire_claim(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR,
            ttl_seconds=60,
        )

        eid = uuid.uuid4()
        regista.release_claim(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR,
            event_id=eid,
        )

        events_after = regista.read_events(work_item_id=wi.work_item_id)
        release_count = sum(1 for e in events_after if e.transition == "claim_released")
        assert release_count == 1


class TestLinkIdempotency:
    def test_create_link_same_event_id_no_duplicate_events(self, regista):
        wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR,
            custom_fields={"title": "link from"},
        )
        wi2, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR,
            custom_fields={"title": "link to"},
        )

        eid = uuid.uuid4()
        regista.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="blocks",
            actor_id=ACTOR,
            event_id=eid,
        )
        events_after_first = regista.read_events(work_item_id=wi1.work_item_id)
        first_count = len(events_after_first)

        regista.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="blocks",
            actor_id=ACTOR,
            event_id=eid,
        )
        events_after_second = regista.read_events(work_item_id=wi1.work_item_id)

        assert len(events_after_second) == first_count

    def test_remove_link_same_event_id_no_duplicate_events(self, regista):
        wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR,
            custom_fields={"title": "rm from"},
        )
        wi2, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR,
            custom_fields={"title": "rm to"},
        )

        regista.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="blocks",
            actor_id=ACTOR,
        )

        eid = uuid.uuid4()
        regista.remove_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="blocks",
            actor_id=ACTOR,
            event_id=eid,
        )
        events_after_first = regista.read_events(work_item_id=wi1.work_item_id)
        first_count = len(events_after_first)

        with pytest.raises(RegistaError, match="LINK_NOT_FOUND"):
            regista.remove_link(
                from_work_item_id=wi1.work_item_id,
                to_work_item_id=wi2.work_item_id,
                link_type="blocks",
                actor_id=ACTOR,
                event_id=eid,
            )

        events_after_second = regista.read_events(work_item_id=wi1.work_item_id)
        assert len(events_after_second) == first_count


class TestClaimActorMetadataWI224:
    """WI-224 (Postgres path): claim ops record the caller's actor_metadata
    on the events they emit rather than dropping it; omitting it keeps the
    pre-fix event shape (``None``).

    The metadata carried here is no longer ``model_lineage``. Under v6 the
    harness/model identity lives in the ``producer`` block and
    ``_validate_v6_object`` refuses a producer field inside ``actor.metadata``
    ("producer fields must not appear in actor.metadata") — the producer is a
    property of the running process, not of the actor. What WI-224 is about is
    whether the claim path *propagates* the caller's metadata, and that is
    unchanged; only the field it is demonstrated with had to become a
    non-producer one.
    """

    def test_claim_events_record_actor_metadata(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR,
            custom_fields={"title": "claim lineage"},
        )
        lineage = {"role": "agent"}

        regista.acquire_claim(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR,
            ttl_seconds=60,
            actor_metadata=dict(lineage),
        )
        regista.heartbeat_claim(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR,
            ttl_seconds=60,
            actor_metadata=dict(lineage),
        )
        regista.release_claim(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR,
            actor_metadata=dict(lineage),
        )

        events = regista.read_events(work_item_id=wi.work_item_id, limit=100)
        by_transition = {e.transition: e for e in events}
        assert by_transition["claim_acquired"].actor_metadata == lineage
        assert by_transition["claim_heartbeat"].actor_metadata == lineage
        assert by_transition["claim_released"].actor_metadata == lineage

    def test_claim_without_metadata_records_none(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR,
            custom_fields={"title": "claim no lineage"},
        )
        regista.acquire_claim(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR,
            ttl_seconds=60,
        )
        events = regista.read_events(work_item_id=wi.work_item_id, limit=100)
        by_transition = {e.transition: e for e in events}
        assert by_transition["claim_acquired"].actor_metadata is None
