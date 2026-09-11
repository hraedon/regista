from __future__ import annotations

import uuid

import pytest

from regista import RegistaError
from regista._errors import ErrorCode


def test_create_list_remove_link(sub, make_feature) -> None:
    source = make_feature()
    target = make_feature()

    link = sub.create_link(
        source.work_item_id,
        target.work_item_id,
        "blocks",
        "alice",
        payload={"reason": "dependency"},
    )
    assert link.link_type == "blocks"
    assert link.from_work_item_id == source.work_item_id
    assert link.to_work_item_id == target.work_item_id

    live = sub.list_links(source.work_item_id)
    assert len(live) == 1
    assert live[0].link_id == link.link_id
    assert live[0].payload == {"reason": "dependency"}

    sub.remove_link(source.work_item_id, target.work_item_id, "blocks", "alice")
    assert sub.list_links(source.work_item_id) == []


def test_disallowed_link_type(sub, make_feature, make_bug) -> None:
    source = make_feature()
    bug = make_bug()

    with pytest.raises(RegistaError) as exc:
        sub.create_link(source.work_item_id, bug.work_item_id, "blocks", "alice")
    assert exc.value.code is ErrorCode.LINK_TYPE_NOT_ALLOWED


def test_declared_cross_type_link_is_allowed(sub, make_feature, make_bug) -> None:
    source = make_feature()
    bug = make_bug()

    link = sub.create_link(source.work_item_id, bug.work_item_id, "fixes", "alice")
    assert link.link_type == "fixes"


def test_missing_link_target(sub, make_feature) -> None:
    source = make_feature()

    with pytest.raises(RegistaError) as exc:
        sub.create_link(source.work_item_id, uuid.uuid4(), "blocks", "alice")
    assert exc.value.code is ErrorCode.LINK_TARGET_NOT_FOUND


def test_remove_non_existent_link(sub, make_feature) -> None:
    source = make_feature()
    target = make_feature()

    with pytest.raises(RegistaError) as exc:
        sub.remove_link(source.work_item_id, target.work_item_id, "blocks", "alice")
    assert exc.value.code is ErrorCode.LINK_NOT_FOUND


def test_has_link_type_query_filter(sub, make_feature, make_bug) -> None:
    source = make_feature()
    target = make_feature()
    bug = make_bug()

    sub.create_link(source.work_item_id, target.work_item_id, "blocks", "alice")
    blocked = sub.query_work_items(has_link_type="blocks")
    blocked_ids = {w.work_item_id for w in blocked.items}
    assert source.work_item_id in blocked_ids
    assert target.work_item_id not in blocked_ids

    sub.remove_link(source.work_item_id, target.work_item_id, "blocks", "alice")
    after_removal = {
        w.work_item_id for w in sub.query_work_items(has_link_type="blocks").items
    }
    assert source.work_item_id not in after_removal

    sub.create_link(source.work_item_id, bug.work_item_id, "fixes", "alice")
    fixes = {w.work_item_id for w in sub.query_work_items(has_link_type="fixes").items}
    assert fixes == {source.work_item_id}
