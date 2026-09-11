from __future__ import annotations

import time

import pytest

from regista import RegistaError
from regista._errors import ErrorCode


def test_acquire_sets_projection(sub, make_feature) -> None:
    work_item = make_feature()
    claim = sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=300)

    assert claim.actor_id == "alice"
    assert claim.attempt_number == 1

    refreshed = sub.get_work_item(work_item.work_item_id)
    assert refreshed is not None
    assert refreshed.claimed_by == "alice"
    assert refreshed.claim_expires_at == claim.expires_at


def test_same_actor_reacquire_extends(sub, make_feature) -> None:
    work_item = make_feature()
    first = sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=60)
    second = sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=600)

    assert second.actor_id == "alice"
    assert second.attempt_number == first.attempt_number
    assert second.expires_at > first.expires_at


def test_cross_actor_contention(sub, make_feature) -> None:
    work_item = make_feature()
    sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=300)

    with pytest.raises(RegistaError) as exc:
        sub.acquire_claim(work_item.work_item_id, "bob", ttl_seconds=300)
    assert exc.value.code is ErrorCode.CLAIM_CONTESTED


def test_release_then_reacquire(sub, make_feature) -> None:
    work_item = make_feature()
    sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=300)
    sub.release_claim(work_item.work_item_id, "alice")

    refreshed = sub.get_work_item(work_item.work_item_id)
    assert refreshed is not None
    assert refreshed.claimed_by is None

    claim = sub.acquire_claim(work_item.work_item_id, "bob", ttl_seconds=300)
    assert claim.actor_id == "bob"


def test_release_by_non_holder_is_refused(sub, make_feature) -> None:
    work_item = make_feature()
    sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=300)

    with pytest.raises(RegistaError) as exc:
        sub.release_claim(work_item.work_item_id, "bob")
    assert exc.value.code is ErrorCode.CLAIM_LOST


def test_sweep_expired_claims(sub, make_feature) -> None:
    work_item = make_feature()
    sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=1)
    time.sleep(1.3)

    swept = sub.sweep_expired_claims()
    assert swept >= 1

    refreshed = sub.get_work_item(work_item.work_item_id)
    assert refreshed is not None
    assert refreshed.claimed_by is None


def test_takeover_after_expiry_increments_attempt(sub, make_feature) -> None:
    work_item = make_feature()
    sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=1)
    time.sleep(1.3)

    claim = sub.acquire_claim(work_item.work_item_id, "bob", ttl_seconds=300)
    assert claim.actor_id == "bob"
    assert claim.attempt_number == 2

    transitions = [
        e.transition for e in sub.read_events(work_item_id=work_item.work_item_id)
    ]
    assert "claim_stolen" in transitions


def test_heartbeat_renews_for_holder(sub, make_feature) -> None:
    work_item = make_feature()
    first = sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=60)
    renewed = sub.heartbeat_claim(work_item.work_item_id, "alice", ttl_seconds=600)

    assert renewed.actor_id == "alice"
    assert renewed.attempt_number == first.attempt_number
    assert renewed.expires_at > first.expires_at


def test_heartbeat_by_non_holder_is_lost(sub, make_feature) -> None:
    work_item = make_feature()
    sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=300)

    with pytest.raises(RegistaError) as exc:
        sub.heartbeat_claim(work_item.work_item_id, "bob", ttl_seconds=300)
    assert exc.value.code is ErrorCode.CLAIM_LOST


def test_heartbeat_stale_attempt_number_is_lost(sub, make_feature) -> None:
    work_item = make_feature()
    sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=300)

    with pytest.raises(RegistaError) as exc:
        sub.heartbeat_claim(
            work_item.work_item_id,
            "alice",
            ttl_seconds=300,
            expected_attempt_number=99,
        )
    assert exc.value.code is ErrorCode.CLAIM_LOST


def test_heartbeat_without_claim_is_not_found(sub, make_feature) -> None:
    work_item = make_feature()
    with pytest.raises(RegistaError) as exc:
        sub.heartbeat_claim(work_item.work_item_id, "alice", ttl_seconds=300)
    assert exc.value.code is ErrorCode.CLAIM_NOT_FOUND
