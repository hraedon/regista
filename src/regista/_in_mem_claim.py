from __future__ import annotations

import uuid
from typing import Any

from ._in_mem_base import _InMemoryBase
from ._types import (
    Claim,
    Link,
)


class InMemClaimMixin(_InMemoryBase):

    def acquire_claim(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        ttl_seconds: int = 300,
        *,
        event_id: uuid.UUID | None = None,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
    ) -> Claim:
        from ._in_memory_claims import in_memory_acquire_claim

        return in_memory_acquire_claim(
            self._store, self._work_items, self._claims, self._workflows,
            self._key_set, work_item_id, actor_id, ttl_seconds,
            event_id=event_id, actor_kind=actor_kind,
            actor_metadata=actor_metadata,
        )

    def heartbeat_claim(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        ttl_seconds: int = 300,
        *,
        expected_attempt_number: int | None = None,
        coalesce_threshold: float | None = None,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
    ) -> Claim:
        from ._in_memory_claims import in_memory_heartbeat_claim

        return in_memory_heartbeat_claim(
            self._store, self._work_items, self._claims, self._key_set,
            work_item_id, actor_id, ttl_seconds,
            expected_attempt_number=expected_attempt_number,
            coalesce_threshold=coalesce_threshold,
            actor_kind=actor_kind,
            actor_metadata=actor_metadata,
        )

    def release_claim(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        *,
        event_id: uuid.UUID | None = None,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
    ) -> None:
        from ._in_memory_claims import in_memory_release_claim

        in_memory_release_claim(
            self._store, self._work_items, self._claims, self._key_set,
            work_item_id, actor_id, event_id=event_id, actor_kind=actor_kind,
            actor_metadata=actor_metadata,
        )

    def sweep_expired_claims(self) -> int:
        from ._in_memory_claims import in_memory_sweep_expired_claims

        return in_memory_sweep_expired_claims(
            self._store, self._work_items, self._claims, self._key_set,
        )

    def create_link(
        self,
        from_work_item_id: uuid.UUID,
        to_work_item_id: uuid.UUID,
        link_type: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
        *,
        event_id: uuid.UUID | None = None,
        payload: dict[str, Any] | None = None,
        target_project: str | None = None,
        target_entity_kind: str | None = None,
        content_hash: str | None = None,
    ) -> Link:
        from ._contract import validate_content_hash
        from ._in_memory_links import in_memory_create_link

        validate_content_hash(content_hash)
        return in_memory_create_link(
            self._store, self._work_items, self._workflows, self._links,
            self._key_set, from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata, event_id=event_id,
            payload=payload,
            target_project=target_project,
            target_entity_kind=target_entity_kind,
            content_hash=content_hash,
        )

    def remove_link(
        self,
        from_work_item_id: uuid.UUID,
        to_work_item_id: uuid.UUID,
        link_type: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
        *,
        event_id: uuid.UUID | None = None,
        target_project: str | None = None,
    ) -> None:
        from ._in_memory_links import in_memory_remove_link

        in_memory_remove_link(
            self._store, self._work_items, self._workflows, self._links,
            self._key_set, from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata, event_id=event_id,
            target_project=target_project,
        )

    def list_links(
        self,
        work_item_id: uuid.UUID,
    ) -> list[Link]:
        """Return all live (non-removed) links from *work_item_id*."""
        events = sorted(
            self._store.events_for("work_item", work_item_id),
            key=lambda e: e.event_seq,
        )
        created: dict[tuple[Any, ...], dict[str, Any]] = {}
        for e in events:
            if e.transition == "link_created":
                p = e.payload or {}
                key = (
                    p.get("to_work_item_id", ""),
                    p.get("link_type", ""),
                    p.get("target_project"),
                )
                created[key] = p
            elif e.transition == "link_removed":
                p = e.payload or {}
                key = (
                    p.get("to_work_item_id", ""),
                    p.get("link_type", ""),
                    p.get("target_project"),
                )
                created.pop(key, None)

        links: list[Link] = []
        for p in created.values():
            links.append(
                Link(
                    link_id=uuid.UUID(p["link_id"]) if p.get("link_id") else uuid.uuid4(),
                    from_work_item_id=work_item_id,
                    to_work_item_id=uuid.UUID(p["to_work_item_id"]),
                    link_type=p["link_type"],
                    payload=p.get("link_payload"),
                    target_project=p.get("target_project"),
                    target_entity_kind=p.get("target_entity_kind"),
                    content_hash=p.get("content_hash"),
                )
            )
        return links
