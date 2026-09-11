from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from conftest import WORKFLOW_NAME, WORKFLOW_VERSION

from regista import RegistaError
from regista._errors import ErrorCode


def test_create_and_get(sub, make_feature) -> None:
    work_item = make_feature(title="hello", priority="high", metadata={"k": 1})

    assert work_item.workflow_name == WORKFLOW_NAME
    assert work_item.workflow_version == WORKFLOW_VERSION
    assert work_item.work_item_type == "feature"
    assert work_item.current_state == "new"
    assert work_item.custom_fields == {
        "title": "hello",
        "priority": "high",
        "metadata": {"k": 1},
    }

    fetched = sub.get_work_item(work_item.work_item_id)
    assert fetched == work_item
    assert sub.get_work_item(__import__("uuid").uuid4()) is None


def test_undeclared_work_item_type_is_rejected(sub) -> None:
    with pytest.raises(RegistaError) as exc:
        sub.create_work_item(WORKFLOW_NAME, "ghost", "alice")
    assert exc.value.code is ErrorCode.WORK_ITEM_TYPE_NOT_DECLARED


@pytest.mark.parametrize(
    "custom_fields",
    [
        {"priority": "low", "metadata": {}},  # missing required title
        {"title": "t", "priority": "urgent", "metadata": {}},  # bad enum value
        {"title": 123, "priority": "low", "metadata": {}},  # wrong scalar type
        {"title": "t", "priority": "low", "metadata": {}, "extra": 1},  # unknown field
    ],
)
def test_custom_field_violations_on_create(sub, custom_fields) -> None:
    with pytest.raises(RegistaError) as exc:
        sub.create_work_item(
            WORKFLOW_NAME, "feature", "alice", custom_fields=custom_fields
        )
    assert exc.value.code is ErrorCode.CUSTOM_FIELD_VIOLATION


def test_missing_required_field_on_other_type(sub) -> None:
    with pytest.raises(RegistaError) as exc:
        sub.create_work_item(WORKFLOW_NAME, "bug", "alice", custom_fields={})
    assert exc.value.code is ErrorCode.CUSTOM_FIELD_VIOLATION


def test_query_by_state_type_and_workflow(sub, make_feature, make_bug) -> None:
    feature = make_feature()
    bug = make_bug()

    by_state = sub.query_work_items(current_states=["new"])
    assert {w.work_item_id for w in by_state.items} == {
        feature.work_item_id,
        bug.work_item_id,
    }

    by_type = sub.query_work_items(work_item_types=["bug"])
    assert [w.work_item_id for w in by_type.items] == [bug.work_item_id]

    by_workflow = sub.query_work_items(
        workflow_name=WORKFLOW_NAME, workflow_version=WORKFLOW_VERSION
    )
    assert {w.work_item_id for w in by_workflow.items} == {
        feature.work_item_id,
        bug.work_item_id,
    }

    assert sub.query_work_items(current_states=["done"]).items == []


def test_cursor_pagination(sub, make_feature) -> None:
    created = [make_feature() for _ in range(5)]

    page = sub.query_work_items(page_size=2)
    assert len(page.items) == 2
    assert page.has_more is True
    assert page.cursor is not None

    seen: list = list(page.items)
    while page.has_more:
        assert page.cursor is not None
        page = sub.query_work_items(page_size=2, cursor=page.cursor)
        seen.extend(page.items)

    assert len(seen) == 5
    assert {w.work_item_id for w in seen} == {w.work_item_id for w in created}
    assert len({w.work_item_id for w in seen}) == 5


def test_custom_field_filters(sub, make_feature) -> None:
    high = make_feature(priority="high")
    low = make_feature(priority="low")

    matching = sub.query_work_items(custom_field_filters={"priority": "high"})
    assert [w.work_item_id for w in matching.items] == [high.work_item_id]
    assert low.work_item_id not in {w.work_item_id for w in matching.items}

    non_matching = sub.query_work_items(custom_field_filters={"priority": "medium"})
    assert non_matching.items == []

    unknown_key = sub.query_work_items(custom_field_filters={"ghost": 1})
    assert unknown_key.items == []


def test_claimable_now_excludes_claimed_and_gated(sub, make_feature) -> None:
    plain = make_feature()
    gated = sub.create_work_item(
        WORKFLOW_NAME,
        "feature",
        "alice",
        custom_fields={
            "title": "later",
            "priority": "low",
            "metadata": {},
        },
        not_before=datetime.now(UTC) + timedelta(hours=1),
    )[0]

    claimable_ids = {w.work_item_id for w in sub.query_work_items(claimable_now=True).items}
    assert plain.work_item_id in claimable_ids
    assert gated.work_item_id not in claimable_ids

    sub.acquire_claim(plain.work_item_id, "alice")
    claimable_ids = {w.work_item_id for w in sub.query_work_items(claimable_now=True).items}
    assert plain.work_item_id not in claimable_ids


def test_not_before_future_blocks_acquire(sub, make_feature) -> None:
    future = datetime.now(UTC) + timedelta(hours=1)
    work_item = sub.create_work_item(
        WORKFLOW_NAME,
        "feature",
        "alice",
        custom_fields={"title": "later", "priority": "low", "metadata": {}},
        not_before=future,
    )[0]

    with pytest.raises(RegistaError) as exc:
        sub.acquire_claim(work_item.work_item_id, "alice")
    assert exc.value.code is ErrorCode.NOT_BEFORE_FUTURE

    assert work_item.work_item_id not in {
        w.work_item_id for w in sub.query_work_items(claimable_now=True).items
    }

    sub.update_not_before(work_item.work_item_id, None, "alice")
    refreshed = sub.get_work_item(work_item.work_item_id)
    assert refreshed is not None
    assert refreshed.not_before is None

    claim = sub.acquire_claim(work_item.work_item_id, "alice")
    assert claim.actor_id == "alice"


def test_update_not_before_can_re_gate(sub, make_feature) -> None:
    work_item = make_feature()
    future = datetime.now(UTC) + timedelta(hours=2)

    sub.update_not_before(work_item.work_item_id, future, "alice")
    refreshed = sub.get_work_item(work_item.work_item_id)
    assert refreshed is not None
    assert refreshed.not_before is not None

    with pytest.raises(RegistaError) as exc:
        sub.acquire_claim(work_item.work_item_id, "alice")
    assert exc.value.code is ErrorCode.NOT_BEFORE_FUTURE
