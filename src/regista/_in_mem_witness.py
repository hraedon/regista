from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, TypeAlias

import structlog

if TYPE_CHECKING:
    from ._in_memory import InMemoryRegista

from ._errors import ErrorCode, RegistaError
from ._in_mem_base import _InMemoryBase
from ._types import Event
from ._witness import witness_principal_id as _witness_principal_id

_WitnessList: TypeAlias = list[dict[str, Any]]

log = structlog.get_logger()


# NB6 (P2.2 review): the in-memory backend does NOT mirror the Postgres backend's
# witness key-lifecycle refusals. `_witness.py` refuses ed25519 registration, key
# rotation, and unregister-with-active-rows with WITNESS_LIFECYCLE_CUT (§7 CUT
# marker, D-7); this backend still performs them against its in-process state.
#
# Left divergent deliberately rather than silently: InMemoryRegista's v6 parity is
# tracked separately (WI-287, "D2: v6 parity for InMemoryRegista under the
# SUITE-RECONCILIATION conformance split"), and making this backend refuse without
# that conformance work would create a second, unreviewed definition of which
# operations are cut. The divergence matters only for tests — no estate deployment
# uses the in-memory backend for witness lifecycle, and preflight measured zero
# witness registrations estate-wide.

class InMemWitnessMixin(_InMemoryBase):

    def register_witness(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        event_filter: dict[str, Any] | None = None,
        max_failures: int = 10,
        max_retries: int = 3,
        *,
        mode: str = "witness",
        sign_secret: bytes | None = None,
        public_key: bytes | None = None,
        key_scheme: str = "hmac-sha256",
    ) -> uuid.UUID:
        from ._witness import _validate_event_filter, _validate_url

        _validate_url(url)
        event_filter = _validate_event_filter(event_filter)
        if mode not in ("witness", "push"):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"mode must be 'witness' or 'push', got {mode!r}",
            )
        if max_failures < 1:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"max_failures must be >= 1, got {max_failures}",
            )
        if max_retries < 1:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"max_retries must be >= 1, got {max_retries}",
            )
        if key_scheme not in ("hmac-sha256", "ed25519"):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"key_scheme must be 'hmac-sha256' or 'ed25519', got {key_scheme!r}",
            )
        if key_scheme == "ed25519":
            if public_key is None:
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    "public_key is required when key_scheme is 'ed25519'",
                )
            if len(public_key) != 32:
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    "ed25519 public_key must be exactly 32 bytes, "
                    f"got {len(public_key)}",
                )
        witness_id = uuid.uuid4()
        self._witnesses[witness_id] = {
            "witness_id": witness_id,
            "url": url,
            "headers": dict(headers) if headers else None,
            "event_filter": dict(event_filter) if event_filter else None,
            "status": "active",
            "max_failures": max_failures,
            "consecutive_failures": 0,
            "max_retries": max_retries,
            "mode": mode,
            "sign_secret": sign_secret,
            "public_key": public_key,
            "key_scheme": key_scheme,
            "last_success_at": None,
            "last_failure_at": None,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }
        if key_scheme == "ed25519" and public_key is not None:
            self._enrolled_witness_keys[witness_id] = {
                "principal_id": _witness_principal_id(witness_id),
                "key_id": f"pk_{uuid.uuid4().hex[:16]}",
                "public_key": public_key,
                "scheme": "ed25519",
                "fingerprint": f"ed25519:sha256:{hashlib.sha256(public_key).hexdigest()}",
                "status": "active",
            }
        return witness_id

    def unregister_witness(self, witness_id: uuid.UUID) -> None:
        if witness_id not in self._witnesses:
            raise RegistaError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
        del self._witnesses[witness_id]
        self._witness_receipts = [
            r for r in self._witness_receipts
            if r["witness_id"] != witness_id
        ]
        enrolled = self._enrolled_witness_keys.pop(witness_id, None)
        if enrolled is not None:
            enrolled["status"] = "revoked"
            enrolled["revoked_reason"] = "witness unregistered"
            self._enrolled_witness_keys[witness_id] = enrolled

    def rotate_witness_key(
        self,
        witness_id: uuid.UUID,
        new_public_key: bytes,
    ) -> dict[str, Any]:
        if len(new_public_key) != 32:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "ed25519 new_public_key must be exactly 32 bytes, "
                f"got {len(new_public_key)}",
            )
        w = self._witnesses.get(witness_id)
        if w is None:
            raise RegistaError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
        if w["key_scheme"] != "ed25519":
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "witness key rotation requires key_scheme='ed25519' "
                f"(witness is {w['key_scheme']!r})",
            )
        w["public_key"] = new_public_key
        w["updated_at"] = datetime.now(UTC)
        prev = self._enrolled_witness_keys.get(witness_id)
        if prev is not None and prev["status"] == "active":
            prev["status"] = "superseded"
        new_key_id = f"pk_{uuid.uuid4().hex[:16]}"
        entry = {
            "principal_id": _witness_principal_id(witness_id),
            "key_id": new_key_id,
            "public_key": new_public_key,
            "scheme": "ed25519",
            "status": "active",
            "fingerprint": f"ed25519:sha256:{hashlib.sha256(new_public_key).hexdigest()}",
        }
        self._enrolled_witness_keys[witness_id] = entry
        log.info(
            "witness.key_rotated",
            project=self._project,
            witness_id=str(witness_id),
            key_id=new_key_id,
        )
        return dict(entry)

    def enrolled_witness_key(self, witness_id: uuid.UUID) -> dict[str, Any] | None:
        enrolled = self._enrolled_witness_keys.get(witness_id)
        if enrolled is None or enrolled["status"] != "active":
            return None
        return dict(enrolled)

    def pause_witness(self, witness_id: uuid.UUID) -> None:
        if witness_id not in self._witnesses:
            raise RegistaError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
        self._witnesses[witness_id]["status"] = "paused"

    def reactivate_witness(self, witness_id: uuid.UUID) -> None:
        if witness_id not in self._witnesses:
            raise RegistaError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
        w = self._witnesses[witness_id]
        w["status"] = "active"
        w["consecutive_failures"] = 0

    def list_witnesses(
        self, status: str | None = None, mode: str | None = None,
    ) -> list[dict[str, Any]]:
        results = []
        for w in self._witnesses.values():
            if status is not None and w["status"] != status:
                continue
            if mode is not None and w.get("mode") != mode:
                continue
            d = dict(w)
            d["witness_id"] = str(d["witness_id"])
            d.pop("sign_secret", None)
            for key in ("last_success_at", "last_failure_at", "created_at", "updated_at"):
                if d.get(key) is not None:
                    d[key] = d[key].isoformat()
            results.append(d)
        return results

    def list_witness_receipts(
        self,
        event_id: uuid.UUID | None = None,
        witness_id: uuid.UUID | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        results = []
        for r in self._witness_receipts:
            if event_id is not None and r["event_id"] != event_id:
                continue
            if witness_id is not None and r["witness_id"] != witness_id:
                continue
            if status is not None and r["status"] != status:
                continue
            d = dict(r)
            d["receipt_id"] = str(d["receipt_id"])
            d["witness_id"] = str(d["witness_id"])
            d["event_id"] = str(d["event_id"])
            for key in ("submitted_at", "last_attempt_at", "confirmed_at", "created_at"):
                if d.get(key) is not None:
                    d[key] = d[key].isoformat()
            if d.get("witness_signature") is not None:
                d["witness_signature"] = bytes(d["witness_signature"]).hex()
            results.append(d)
        return results[:limit]

    def deliver_pending_witness_receipts(self) -> int:
        if self._witness_transport is None:
            return 0

        with self._witness_delivery_lock:
            total = 0
            active_witnesses = [
                w for w in self._witnesses.values()
                if w["status"] == "active"
            ]

            for w in active_witnesses:
                witness_id = w["witness_id"]
                url = w["url"]
                base_headers = dict(w["headers"]) if w["headers"] else {}
                max_retries = w["max_retries"]
                max_failures = w["max_failures"]
                sign_secret = w["sign_secret"]
                witness_key_scheme = w["key_scheme"]

                pending = [
                    r for r in self._witness_receipts
                    if r["witness_id"] == witness_id and r["status"] == "pending"
                ]
                if not pending:
                    continue

                for receipt in pending:
                    receipt["status"] = "in_progress"
                    receipt["last_attempt_at"] = datetime.now(UTC)

                for receipt in pending:
                    event_id = receipt["event_id"]
                    event = self._store.find_by_event_id(event_id)
                    if event is None:
                        now = datetime.now(UTC)
                        receipt["status"] = "pending"
                        receipt["retry_count"] += 1
                        receipt["error_message"] = "event not found"
                        receipt["last_attempt_at"] = now
                        receipt["witness_scheme"] = witness_key_scheme
                        w["consecutive_failures"] += 1
                        w["last_failure_at"] = now
                        w["updated_at"] = now
                        if receipt["retry_count"] >= max_retries:
                            receipt["status"] = "paused"
                        if w["consecutive_failures"] >= max_failures:
                            w["status"] = "paused"
                            log.warning(
                                "witness.auto_paused",
                                project=self._project,
                                witness_id=str(witness_id),
                                consecutive_failures=w["consecutive_failures"],
                            )
                        continue

                    try:
                        evt_dict = event.to_dict()
                        payload = {
                            "event": evt_dict,
                            "receipt_id": str(receipt["receipt_id"]),
                            "witness_id": str(witness_id),
                            "submitted_at": datetime.now(UTC).isoformat(),
                        }
                        body = json.dumps(payload)
                    except Exception as exc:
                        now = datetime.now(UTC)
                        receipt["status"] = "pending"
                        receipt["retry_count"] += 1
                        receipt["last_attempt_at"] = now
                        receipt["error_message"] = f"payload error: {str(exc)[:400]}"
                        receipt["witness_scheme"] = witness_key_scheme
                        w["consecutive_failures"] += 1
                        w["last_failure_at"] = now
                        w["updated_at"] = now
                        if receipt["retry_count"] >= max_retries:
                            receipt["status"] = "paused"
                        if w["consecutive_failures"] >= max_failures:
                            w["status"] = "paused"
                            log.warning(
                                "witness.auto_paused",
                                project=self._project,
                                witness_id=str(witness_id),
                                consecutive_failures=w["consecutive_failures"],
                            )
                        continue
                    req_headers = {
                        "Content-Type": "application/json",
                        "User-Agent": "regista-delivery/0",
                        **base_headers,
                    }
                    if sign_secret:
                        sig = _hmac.new(
                            sign_secret, body.encode(), hashlib.sha256,
                        ).hexdigest()
                        req_headers["X-Regista-Signature"] = f"sha256={sig}"

                    try:
                        result = self._witness_transport(url, req_headers, payload)
                    except Exception as exc:
                        from ._in_memory import TransportResult

                        result = TransportResult(
                            status_code=0, error=str(exc)[:500],
                        )

                    now = datetime.now(UTC)

                    if 200 <= result.status_code < 300 and result.error is None:
                        witness_sig = None
                        if result.body and "witness_signature" in result.body:
                            try:
                                witness_sig = bytes.fromhex(
                                    result.body["witness_signature"],
                                )
                            except (ValueError, TypeError):
                                witness_sig = None

                        witness_pubkey = w.get("public_key")
                        sig_verified = True
                        if witness_key_scheme == "ed25519":
                            sig_verified = False
                            if (
                                witness_pubkey is not None
                                and witness_sig is not None
                                and event.canonical_envelope is not None
                                and event.payload_canonical_hash is not None
                            ):
                                try:
                                    from ._signing_scheme import Ed25519Scheme

                                    sig_verified = Ed25519Scheme().verify(
                                        event.canonical_envelope,
                                        witness_sig,
                                        event.payload_canonical_hash,
                                        witness_pubkey,
                                    )
                                except Exception:
                                    sig_verified = False

                        if sig_verified:
                            receipt["status"] = "confirmed"
                            receipt["confirmed_at"] = now
                            receipt["witness_response"] = result.body
                            receipt["witness_signature"] = witness_sig
                            receipt["witness_scheme"] = witness_key_scheme
                            receipt["submitted_at"] = receipt["submitted_at"] or now
                            receipt["error_message"] = None
                            w["consecutive_failures"] = 0
                            w["last_success_at"] = now
                            w["updated_at"] = now
                            total += 1
                        else:
                            error_msg = "ed25519 signature verification failed"
                            receipt["retry_count"] += 1
                            receipt["last_attempt_at"] = now
                            receipt["error_message"] = error_msg
                            receipt["witness_scheme"] = witness_key_scheme
                            receipt["status"] = "pending"

                            w["consecutive_failures"] += 1
                            w["last_failure_at"] = now
                            w["updated_at"] = now

                            if receipt["retry_count"] >= max_retries:
                                receipt["status"] = "paused"

                            if w["consecutive_failures"] >= max_failures:
                                w["status"] = "paused"
                                log.warning(
                                    "witness.auto_paused",
                                    project=self._project,
                                    witness_id=str(witness_id),
                                    consecutive_failures=w["consecutive_failures"],
                                )
                    else:
                        error_msg = result.error or f"HTTP {result.status_code}"
                        receipt["retry_count"] += 1
                        receipt["last_attempt_at"] = now
                        receipt["error_message"] = error_msg
                        receipt["witness_scheme"] = witness_key_scheme
                        receipt["status"] = "pending"

                        w["consecutive_failures"] += 1
                        w["last_failure_at"] = now
                        w["updated_at"] = now

                        if receipt["retry_count"] >= max_retries:
                            receipt["status"] = "paused"

                        if w["consecutive_failures"] >= max_failures:
                            w["status"] = "paused"
                            log.warning(
                                "witness.auto_paused",
                                project=self._project,
                                witness_id=str(witness_id),
                                consecutive_failures=w["consecutive_failures"],
                            )

            return total

    def sweep_stuck_witness_receipts(self, max_age_seconds: int = 300) -> int:
        return self.witnesses.sweep_stuck(max_age_seconds)  # type: ignore[no-any-return]

    def _try_create_witness_receipts(self, event: Event) -> None:
        from ._witness import event_matches_filter

        try:
            for w in list(self._witnesses.values()):
                if w["status"] != "active":
                    continue
                if not event_matches_filter(event.to_dict(), w.get("event_filter")):
                    continue
                receipt_id = uuid.uuid4()
                self._witness_receipts.append({
                    "receipt_id": receipt_id,
                    "witness_id": w["witness_id"],
                    "event_id": event.event_id,
                    "status": "pending",
                    "retry_count": 0,
                    "submitted_at": None,
                    "last_attempt_at": None,
                    "confirmed_at": None,
                    "witness_signature": None,
                    "witness_response": None,
                    "witness_scheme": None,
                    "error_message": None,
                    "created_at": datetime.now(UTC),
                })
        except Exception:
            structlog.get_logger().warning(
                "witness.create_receipts_failed_in_memory",
                event_id=str(event.event_id),
            )


class _InMemoryWitnessOps:
    def __init__(self, sub: InMemoryRegista) -> None:
        self._sub = sub

    def register(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        event_filter: dict[str, Any] | None = None,
        max_failures: int = 10,
        max_retries: int = 3,
        *,
        mode: str = "witness",
        sign_secret: bytes | None = None,
        public_key: bytes | None = None,
        key_scheme: str = "hmac-sha256",
    ) -> uuid.UUID:
        return self._sub.register_witness(
            url, headers=headers, event_filter=event_filter,
            max_failures=max_failures, max_retries=max_retries,
            mode=mode, sign_secret=sign_secret,
            public_key=public_key, key_scheme=key_scheme,
        )

    def rotate_key(
        self,
        witness_id: uuid.UUID,
        new_public_key: bytes,
    ) -> dict[str, Any]:
        return self._sub.rotate_witness_key(witness_id, new_public_key)

    def enrolled_key(self, witness_id: uuid.UUID) -> dict[str, Any] | None:
        return self._sub.enrolled_witness_key(witness_id)

    def unregister(self, witness_id: uuid.UUID) -> None:
        self._sub.unregister_witness(witness_id)

    def pause(self, witness_id: uuid.UUID) -> None:
        self._sub.pause_witness(witness_id)

    def reactivate(self, witness_id: uuid.UUID) -> None:
        self._sub.reactivate_witness(witness_id)

    def list(self, status: str | None = None, mode: str | None = None) -> list[dict[str, Any]]:
        witnesses = self._sub.list_witnesses(status=status)
        if mode is not None:
            witnesses = [w for w in witnesses if w.get("mode") == mode]
        return witnesses

    def receipts(
        self,
        event_id: uuid.UUID | None = None,
        witness_id: uuid.UUID | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> _WitnessList:
        return self._sub.list_witness_receipts(
            event_id=event_id, witness_id=witness_id,
            status=status, limit=limit,
        )

    def deliver(self) -> int:
        return self._sub.deliver_pending_witness_receipts()

    def sweep_stuck(self, max_age_seconds: int = 300) -> int:
        if max_age_seconds <= 0:
            from ._errors import ErrorCode, RegistaError

            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "max_age_seconds must be a positive integer",
            )
        now = datetime.now(UTC)
        threshold = now - timedelta(seconds=max_age_seconds)
        count = 0
        with self._sub._witness_delivery_lock:
            for r in self._sub._witness_receipts:
                if r["status"] == "in_progress" and r.get("last_attempt_at") is not None:
                    if r["last_attempt_at"] < threshold:
                        r["status"] = "pending"
                        count += 1
        return count

    def create_receipts_for_event(self, event_dict: dict[str, Any]) -> int:
        from regista._types import Event

        evt_id = uuid.UUID(event_dict["event_id"])
        self._sub._try_create_witness_receipts(Event(**event_dict))
        return sum(
            1 for r in self._sub._witness_receipts
            if r["event_id"] == evt_id
        )

    @staticmethod
    def event_matches_filter(
        event_dict: dict[str, Any], event_filter: dict[str, Any] | None,
    ) -> bool:
        from ._witness import event_matches_filter

        return event_matches_filter(event_dict, event_filter)
