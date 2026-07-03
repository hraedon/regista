from __future__ import annotations

from ._api_base import _RegistaBase
from ._errors import RegistaError
from ._types import Event


class MetaApiMixin(_RegistaBase):

    def export_public_keys(self) -> list[dict[str, object]]:
        """Export public key material for external signature verification.

        Returns asymmetric keys only (Ed25519 and future PQC schemes). Secret
        material is never included. An auditor who receives this export and
        the event log can verify signatures without the signing secret.

        Returns:
            List of dicts with ``key_id``, ``scheme``, ``public_key``
            (base64), ``fingerprint``, ``principal_id``, ``status``,
            ``revoked_at``.
        """
        self._require_open()
        return self._keys.export_public_keys()

    def verify_event_signature(
        self, event: Event, *, public_key: bytes | None = None,
    ) -> bool:
        """Verify an event's cryptographic signature.

        When ``public_key`` is provided, verification uses only that key
        (no secret material needed — the independent-verification path).
        When omitted, the key is resolved from the project's key set.

        Args:
            event: The event to verify.
            public_key: Optional raw public key bytes for external
                verification. If omitted, the project's key set is used.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        from ._signing import verify_event_with_public_key

        if public_key is None:
            self._require_open()
            try:
                key_entry = self._keys.get_key(event.key_id)
            except RegistaError:
                return False
            if key_entry.public_key is not None:
                public_key = key_entry.public_key
            else:
                public_key = key_entry.secret
        return verify_event_with_public_key(event, public_key)

    def verify_event_principal_binding(
        self, event: Event,
    ) -> dict[str, object]:
        """Verify an event's signature against the principal key registry.

        Looks up the active public key for the event's ``actor_id`` in the
        principal_keys registry, verifies the signature under that key, and
        confirms the actor↔signer binding. This is the non-repudiation
        verification path (Plan 026 WI-1.2).

        Args:
            event: The event to verify.

        Returns:
            Dict with ``verified`` (bool), ``principal_id`` (str|None),
            ``key_id`` (str|None), and ``error`` (str|None).
        """
        from ._signing import verify_event_with_principal_binding

        self._require_open()
        result = verify_event_with_principal_binding(event, self._mgr)
        return {
            "verified": result.verified,
            "principal_id": result.principal_id,
            "key_id": result.key_id,
            "error": result.error,
        }

    @staticmethod
    def validate_actor_metadata(
        event: Event,
        expected_schema: dict | None = None,
    ) -> list[str]:
        """Lint helper: validate actor_metadata against recommended fields.

        Args:
            event: Event to inspect.
            expected_schema: Optional JSON Schema to validate against.

        Returns:
            List of issue descriptions (empty if clean).
        """
        from ._lint import validate_actor_metadata as _validate

        return _validate(event, expected_schema)

    @staticmethod
    def actor_metadata_complete(
        events: list[Event],
        expected_keys: list[str],
    ) -> list[Event]:
        """Lint helper: return events missing any of the expected actor_metadata keys.

        Args:
            events: Events to inspect.
            expected_keys: List of keys that must be present in actor_metadata.

        Returns:
            List of events with incomplete actor_metadata.
        """
        from ._lint import actor_metadata_complete as _complete

        return _complete(events, expected_keys)
