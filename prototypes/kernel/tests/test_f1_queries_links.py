from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import psycopg
import pytest
from kernel import InvalidFieldError, InvalidQueryError, Kernel, Workflow, WorkItem
from psycopg.sql import SQL, Identifier


def seed(k: Kernel, count: int = 7) -> list[WorkItem]:
    return [
        k.create_work_item(workflow="review", type="task", actor_id="w", fields={"n": i})
        for i in range(count)
    ]


@pytest.mark.parametrize(
    "query", ["all", "available", "owned", "in_states", "blocked", "review_ready"]
)
def test_query_order_and_paging(registered: Kernel, dsn: str, schema: str, query: str) -> None:
    items = seed(registered)
    blocker = seed(registered, 1)[0]
    for item in items:
        if query == "owned":
            registered.claim(item.id, actor_id="owner")
        if query == "review_ready":
            registered.transition(item.id, transition="start", actor_id="w")
            registered.transition(
                item.id, transition="submit", actor_id="w", fields={"note": "ready"}
            )
        if query == "blocked":
            registered.link(blocker.id, item.id, "blocks")
    # Force timestamp ties so removal of the UUID tiebreaker has consequences.
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            SQL(
                "UPDATE {}.work_items_current SET created_at = (SELECT min(created_at) "
                "FROM {}.work_items_current)"
            ).format(Identifier(schema), Identifier(schema))
        )
    calls: dict[str, Callable[..., list[WorkItem]]] = {
        "all": registered.list_items,
        "available": registered.available,
        "owned": lambda **kw: registered.owned("owner", **kw),
        "in_states": lambda **kw: registered.in_states(("new",), **kw),
        "review_ready": lambda **kw: registered.in_states(("review",), **kw),
        "blocked": lambda **kw: registered.blocked(
            link_type="blocks", direction="incoming", satisfied_states=("done",), **kw
        ),
    }
    call = calls[query]
    expected = sorted(
        [
            i.id
            for i in (items if query in ("owned", "blocked", "review_ready") else [*items, blocker])
        ]
    )
    seen: list[uuid.UUID] = []
    after = None
    while True:
        page = call(limit=2, after=after)
        assert len(page) <= 2
        if not page:
            break
        seen.extend(i.id for i in page)
        after = page[-1].id
    assert seen == expected and len(seen) == len(set(seen))


def test_query_filters_and_liveness(registered: Kernel, dsn: str, schema: str) -> None:
    items = seed(registered, 3)
    registered.claim(items[0].id, actor_id="w")
    registered.claim(items[1].id, actor_id="w", ttl_seconds=-1)
    assert [i.id for i in registered.available()] == [items[1].id, items[2].id]
    assert [i.id for i in registered.owned("w")] == [items[0].id]
    assert registered.owned("other") == []
    assert [i.id for i in registered.list_items()] == [i.id for i in items]
    assert registered.list_items(workflow="other") == []
    assert registered.list_items(type="source") == []
    assert registered.in_states(("review",)) == []
    assert registered.list_items(
        workflow="review", type="task", states=("new",), where_fields={"n": 2}
    ) == [items[2]]
    assert registered.list_items(where_fields={"missing": "x"}) == []


@pytest.mark.parametrize(
    "case",
    [
        "zero",
        "too_large",
        "dead_cursor",
        "empty_states",
        "nested_filter",
        "too_many_filters",
        "direction",
        "satisfied",
    ],
)
def test_query_refusals(registered: Kernel, case: str) -> None:
    calls: dict[str, Callable[[], Any]] = {
        "zero": lambda: registered.list_items(limit=0),
        "too_large": lambda: registered.available(limit=501),
        "dead_cursor": lambda: registered.list_items(after=uuid.uuid4()),
        "empty_states": lambda: registered.in_states(()),
        "nested_filter": lambda: registered.list_items(where_fields={"v": {"nested": 1}}),
        "too_many_filters": lambda: registered.list_items(
            where_fields={f"k{i}": i for i in range(9)}
        ),
        "direction": lambda: registered.blocked(
            link_type="blocks",
            direction="bad",  # type: ignore[arg-type]
            satisfied_states=("done",),
        ),
        "satisfied": lambda: registered.blocked(
            link_type="blocks", direction="incoming", satisfied_states=("typo",)
        ),
    }
    with pytest.raises(InvalidQueryError):
        calls[case]()


def test_links_lookup_and_idempotency(registered: Kernel) -> None:
    source, a, b = seed(registered, 3)
    for target, kind in [(a, "blocks"), (a, "related"), (b, "blocks"), (a, "blocks")]:
        registered.link(source.id, target.id, kind)
    expected = sorted(
        [(a.id, "blocks"), (a.id, "related"), (b.id, "blocks")], key=lambda r: (r[1], r[0])
    )
    assert registered.links_from(source.id) == expected
    first = registered.links_from(source.id, limit=1)
    assert first + registered.links_from(source.id, after=(first[0][1], first[0][0])) == expected
    assert registered.links_from(source.id, link_type="blocks") == [
        r for r in expected if r[1] == "blocks"
    ]
    assert registered.links_from(a.id) == []


@pytest.mark.parametrize("case", ["self", "missing_source", "missing_target"])
def test_link_refusals(registered: Kernel, case: str) -> None:
    a, b = seed(registered, 2)
    source = uuid.uuid4() if case == "missing_source" else a.id
    target = a.id if case == "self" else uuid.uuid4() if case == "missing_target" else b.id
    with pytest.raises(InvalidFieldError):
        registered.link(source, target, "blocks")
    assert registered.links_from(a.id) == []


def test_d6_single_hop_no_scheduler(registered: Kernel) -> None:
    a, b, c, d = seed(registered, 4)
    registered.transition(b.id, transition="abandon", actor_id="w")  # terminal != satisfied
    registered.link(a.id, b.id, "blocks")
    registered.link(b.id, c.id, "blocks")
    registered.link(c.id, d.id, "related")
    assert [
        i.id
        for i in registered.blocked(
            link_type="blocks", direction="incoming", satisfied_states=("done",)
        )
    ] == [b.id, c.id]
    assert [
        i.id
        for i in registered.blocked(
            link_type="blocks", direction="outgoing", satisfied_states=("done",)
        )
    ] == [a.id, b.id]
    # Explicitly satisfying b releases c even though a still blocks b: no recursion.
    assert [
        i.id
        for i in registered.blocked(
            link_type="blocks", direction="incoming", satisfied_states=("done", "rejected")
        )
    ] == [b.id]
    claim = registered.claim(b.id, actor_id="w")
    assert claim.attempt == 1 and registered.get(c.id).state == "new"


def test_link_vocabulary_and_removal(kernel: Kernel, workflow: Workflow) -> None:
    from dataclasses import replace

    kernel.register_workflow(replace(workflow, link_type_names=("blocks",)))
    a, b = seed(kernel, 2)
    with pytest.raises(InvalidFieldError, match="undeclared"):
        kernel.link(a.id, b.id, "typo")
    assert kernel.links_from(a.id) == []
    kernel.link(a.id, b.id, "blocks")
    assert kernel.links_from(a.id) == [(b.id, "blocks")]
    kernel.remove_link(a.id, b.id, "blocks")
    assert kernel.links_from(a.id) == []
    with pytest.raises(InvalidFieldError, match="no such"):
        kernel.remove_link(a.id, b.id, "blocks")


def test_remove_absent_link(registered: Kernel) -> None:
    a, b = seed(registered, 2)
    with pytest.raises(InvalidFieldError, match="no such"):
        registered.remove_link(a.id, b.id, "blocks")
    assert registered.links_from(a.id) == []
