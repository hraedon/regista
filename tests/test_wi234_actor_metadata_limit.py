"""WI-234: validate_actor_metadata (64 KB cap) had zero call sites.

``_contract.validate_actor_metadata`` enforced ``MAX_ACTOR_METADATA_BYTES``
(64 KB) but nothing called it, so ``actor_metadata`` was bounded only by
the generic 1 MiB ``MAX_JSONB_BYTES`` — while spec.md section on payload
limits documents the stricter 64 KB limit as part of the contract ("The
``actor_metadata`` field has a separate stricter limit of 64 KB").

The fix wires the validator into ``validate_mutation_params`` (the shared
boundary validation for all mutation entry points) and passes
``actor_metadata`` at every entry point that accepts it, on both
backends. This is a deliberate behavior change for new writes only:
metadata between 64 KB and 1 MiB is now rejected with
``INVALID_ARGUMENT``. Events already recorded are untouched — replay and
verification never re-run boundary validation.

These tests run on the in-memory backend; the Postgres entry points are
wired through the same ``validate_mutation_params`` choke point and are
exercised by the DB-dependent suite in CI.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from regista._contract import MAX_ACTOR_METADATA_BYTES, validate_actor_metadata
from regista._errors import ErrorCode, RegistaError
from regista.testing import InMemoryRegista

TESTS_DIR = Path(__file__).parent
KEY_PATH = str(TESTS_DIR / "test_keys.json")

WORKFLOW = """\
name: wi234_limit
version: 1
regista_version: "0.4.0"

states:
  - name: open
    initial: true
  - name: done
    terminal: true

transitions:
  - name: close
    from: open
    to: done

roles: []

work_item_types:
  - name: issue
    custom_fields: []

link_types:
  - name: blocks
    source_type: issue
    target_type: issue
"""


def _metadata_of_size(total_bytes: int) -> dict:
    """Build a metadata dict whose JSON serialization is exactly *total_bytes*."""
    overhead = len(json.dumps({"pad": ""}).encode("utf-8"))
    return {"pad": "x" * (total_bytes - overhead)}


OVERSIZED = _metadata_of_size(MAX_ACTOR_METADATA_BYTES + 1)


def _sub() -> InMemoryRegista:
    sub = InMemoryRegista(project="test_wi234", hmac_key_path=KEY_PATH)
    sub.register_workflow(WORKFLOW)
    return sub


def _assert_rejected(exc_info) -> None:
    assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
    assert "actor_metadata exceeds maximum size" in str(exc_info.value)


class TestValidateActorMetadata:
    def test_none_passes(self):
        validate_actor_metadata(None)

    def test_small_metadata_passes(self):
        validate_actor_metadata({"model_lineage": "claude-opus"})

    def test_exactly_at_limit_passes(self):
        validate_actor_metadata(_metadata_of_size(MAX_ACTOR_METADATA_BYTES))

    def test_one_byte_over_limit_rejected(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_actor_metadata(_metadata_of_size(MAX_ACTOR_METADATA_BYTES + 1))
        _assert_rejected(exc_info)


class TestLimitEnforcedAtMutationEntryPoints:
    def test_create_work_item_rejects_oversized_metadata(self):
        sub = _sub()
        with pytest.raises(RegistaError) as exc_info:
            sub.create_work_item(
                workflow_name="wi234_limit",
                work_item_type="issue",
                actor_id="agent-1",
                actor_kind="agent",
                actor_metadata=OVERSIZED,
            )
        _assert_rejected(exc_info)

    def test_transition_rejects_oversized_metadata(self):
        sub = _sub()
        wi, _ = sub.create_work_item(
            workflow_name="wi234_limit",
            work_item_type="issue",
            actor_id="agent-1",
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.transition(
                wi.work_item_id, "close", "agent-1",
                actor_kind="agent",
                actor_metadata=OVERSIZED,
            )
        _assert_rejected(exc_info)

    def test_create_link_rejects_oversized_metadata(self):
        sub = _sub()
        wi1, _ = sub.create_work_item(
            workflow_name="wi234_limit",
            work_item_type="issue",
            actor_id="agent-1",
        )
        wi2, _ = sub.create_work_item(
            workflow_name="wi234_limit",
            work_item_type="issue",
            actor_id="agent-1",
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.create_link(
                from_work_item_id=wi1.work_item_id,
                to_work_item_id=wi2.work_item_id,
                link_type="blocks",
                actor_id="agent-1",
                actor_metadata=OVERSIZED,
            )
        _assert_rejected(exc_info)

    def test_update_not_before_rejects_oversized_metadata(self):
        sub = _sub()
        wi, _ = sub.create_work_item(
            workflow_name="wi234_limit",
            work_item_type="issue",
            actor_id="agent-1",
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.update_not_before(
                wi.work_item_id, None, "agent-1",
                actor_kind="agent",
                actor_metadata=OVERSIZED,
            )
        _assert_rejected(exc_info)

    def test_metadata_between_64kb_and_1mib_is_now_rejected(self):
        """Pins the intended behavior change: sizes the old 1 MiB Jsonb
        bound would have admitted are rejected at the 64 KB contract."""
        sub = _sub()
        with pytest.raises(RegistaError) as exc_info:
            sub.create_work_item(
                workflow_name="wi234_limit",
                work_item_type="issue",
                actor_id="agent-1",
                actor_metadata=_metadata_of_size(100 * 1024),
            )
        _assert_rejected(exc_info)

    def test_metadata_under_limit_still_accepted(self):
        sub = _sub()
        wi, evt = sub.create_work_item(
            workflow_name="wi234_limit",
            work_item_type="issue",
            actor_id="agent-1",
            actor_metadata=_metadata_of_size(32 * 1024),
        )
        assert evt.actor_metadata is not None
        sub.transition(
            wi.work_item_id, "close", "agent-1",
            actor_kind="agent",
            actor_metadata={"model_lineage": "claude-opus"},
        )


class TestClaimPathHonoursTheLimit:
    """The claim ops gained actor_metadata in WI-224; whichever of the two
    changes landed second had to connect them (both PRs' merge note), or
    claim metadata would be the one write path exempt from the 64 KB cap."""

    def _item(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="wi234_limit",
            work_item_type="issue",
            actor_id="agent-1",
        )
        return wi

    def test_oversized_claim_metadata_rejected(self):
        sub = _sub()
        wi = self._item(sub)
        with pytest.raises(RegistaError) as exc_info:
            sub.acquire_claim(
                wi.work_item_id,
                actor_id="agent-2",
                actor_kind="agent",
                actor_metadata=_metadata_of_size(100 * 1024),
            )
        _assert_rejected(exc_info)

    def test_claim_metadata_under_limit_accepted(self):
        sub = _sub()
        wi = self._item(sub)
        claim = sub.acquire_claim(
            wi.work_item_id,
            actor_id="agent-2",
            actor_kind="agent",
            actor_metadata={"model_lineage": "claude-opus"},
        )
        assert claim is not None
