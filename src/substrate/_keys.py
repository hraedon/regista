from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

import structlog

from ._errors import ErrorCode, SubstrateError

log = structlog.get_logger()


@dataclass(frozen=True)
class KeyEntry:
    key_id: str
    alg: str
    secret: bytes
    public_key: bytes | None
    status: str
    role: str
    revoked_at: str | None
    principal_id: str | None
    scheme: str = "hmac-sha256"

    def __repr__(self) -> str:
        return (
            f"KeyEntry(key_id={self.key_id!r}, alg={self.alg!r}, "
            f"secret=<redacted>, status={self.status!r}, role={self.role!r}, "
            f"scheme={self.scheme!r})"
        )

    def fingerprint(self) -> str:
        if self.alg == "HMAC-SHA256":
            return f"hmac:sha256:{hashlib.sha256(self.secret).hexdigest()}"
        if self.public_key is not None:
            return f"{self.alg}:sha256:{hashlib.sha256(self.public_key).hexdigest()}"
        raise SubstrateError(
            ErrorCode.INVALID_ARGUMENT,
            f"Cannot compute fingerprint for algorithm {self.alg!r} without public_key",
        )


class KeySet:
    def __init__(
        self,
        path: str | Path,
        poll_interval: float = 30.0,
        expected_key_count: int | None = None,
        env_prefix: str = "SUBSTRATE_HMAC_KEY_",
    ) -> None:
        self._path = Path(path)
        self._poll_interval = poll_interval
        self._expected_key_count = expected_key_count
        self._env_prefix = env_prefix
        self._keys: dict[str, KeyEntry] = {}
        self._active_key_id: str | None = None
        self._last_mtime: float = 0.0
        self._last_check: float = 0.0
        self._load()

    def _env_var_name(self, key_id: str) -> str:
        return self._env_prefix + key_id.upper().replace("-", "_")

    def _load(self) -> None:
        try:
            raw = self._path.read_text()
        except OSError as e:
            raise SubstrateError(
                ErrorCode.KEY_LOAD_ERROR,
                f"Cannot read key set from {self._path}: {e}",
            )

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise SubstrateError(
                ErrorCode.KEY_LOAD_ERROR,
                f"Invalid JSON in key set {self._path}: {e}",
            )

        if not isinstance(data, dict) or "keys" not in data:
            raise SubstrateError(
                ErrorCode.KEY_LOAD_ERROR,
                f"Key set {self._path} must be a JSON object with a 'keys' array",
            )

        new_keys: dict[str, KeyEntry] = {}
        new_active: str | None = None
        key_sources: dict[str, str] = {}
        for entry in data["keys"]:
            key_id = entry["key_id"]
            status = entry.get("status", "active")
            if status not in ("active", "deprecated", "revoked"):
                raise SubstrateError(
                    ErrorCode.KEY_LOAD_ERROR,
                    f"Key {key_id!r} has unknown status {status!r}; "
                    "expected 'active', 'deprecated', or 'revoked'",
                )
            alg = entry.get("alg", "HMAC-SHA256")
            role = entry.get("role", "actor")
            if role not in ("actor", "auditor", "recovery"):
                raise SubstrateError(
                    ErrorCode.INVALID_KEY_ROLE,
                    f"Key {key_id!r} has unknown role {role!r}; "
                    "expected 'actor', 'auditor', or 'recovery'",
                )
            revoked_at = entry.get("revoked_at")
            principal_id = entry.get("principal_id")

            env_var = self._env_var_name(key_id)
            env_val = os.environ.get(env_var)
            if env_val is not None:
                secret = env_val.encode("utf-8")
                key_sources[key_id] = "env"
            else:
                secret = entry["secret"]
                encoding = entry.get("encoding", "utf8")
                if encoding == "base64":
                    import base64

                    secret = base64.b64decode(secret)
                elif isinstance(secret, str):
                    secret = secret.encode("utf-8")
                key_sources[key_id] = "file"

            public_key = entry.get("public_key")
            if isinstance(public_key, str):
                import base64

                public_key = base64.b64decode(public_key)

            scheme = entry.get("scheme", "hmac-sha256")
            if scheme not in ("hmac-sha256", "ed25519"):
                raise SubstrateError(
                    ErrorCode.KEY_LOAD_ERROR,
                    f"Key {key_id!r} has unknown scheme {scheme!r}; "
                    "expected 'hmac-sha256' or 'ed25519'",
                )
            if scheme == "ed25519":
                try:
                    __import__("nacl")
                except ImportError:
                    raise SubstrateError(
                        ErrorCode.KEY_LOAD_ERROR,
                        "Scheme 'ed25519' requires PyNaCl: "
                        "pip install substrate[ed25519]",
                    )

            new_keys[key_id] = KeyEntry(
                key_id=key_id,
                alg=alg,
                secret=bytes(secret),
                public_key=public_key,
                status=status,
                role=role,
                revoked_at=revoked_at,
                principal_id=principal_id,
                scheme=scheme,
            )
            if status == "active" and new_active is None:
                new_active = key_id

        self._keys = new_keys
        self._active_key_id = new_active
        self._last_mtime = self._path.stat().st_mtime
        self._last_check = time.monotonic()

        if self._expected_key_count is not None and len(new_keys) != self._expected_key_count:
            raise SubstrateError(
                ErrorCode.KEY_LOAD_ERROR,
                f"Expected {self._expected_key_count} keys but loaded {len(new_keys)}",
            )

        log.warning("keys.plaintext_at_rest", path=str(self._path))
        log.info(
            "keys_loaded",
            key_count=len(self._keys),
            active_key_id=self._active_key_id,
            key_sources=key_sources,
        )
        log.info(
            "keys.loaded",
            path=str(self._path),
            key_count=len(self._keys),
            active=self._active_key_id,
        )

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if now - self._last_check < self._poll_interval:
            return
        self._last_check = now
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            return
        if mtime != self._last_mtime:
            log.info("keys.hot_reload_triggered", path=str(self._path))
            self._load()

    def get_key(self, key_id: str) -> KeyEntry:
        self._maybe_reload()
        entry = self._keys.get(key_id)
        if entry is None:
            log.warning(
                "keys.unknown_key_id",
                key_id_claim=key_id,
            )
            raise SubstrateError(
                ErrorCode.UNKNOWN_KEY_ID,
                f"Unknown key_id: {key_id!r}",
            )
        return entry

    def active_key(self) -> KeyEntry:
        self._maybe_reload()
        keys = self._keys
        active_id = self._active_key_id
        if active_id is None or active_id not in keys:
            raise SubstrateError(
                ErrorCode.UNKNOWN_KEY_ID,
                "No active signing key available",
            )
        entry = keys[active_id]
        if entry.status == "revoked":
            raise SubstrateError(
                ErrorCode.REVOKED_KEY_ID,
                f"Active key {active_id!r} is revoked",
            )
        return entry

    def active_keys_for(self, principal_id: str) -> list[KeyEntry]:
        self._maybe_reload()
        return [
            e for e in self._keys.values()
            if e.status == "active" and e.principal_id == principal_id
        ]

    def resolve_signing_key(self, actor_id: str, key_id: str | None = None) -> KeyEntry:
        self._maybe_reload()
        if key_id is not None:
            entry = self.get_key(key_id)
            if entry.status == "revoked":
                raise SubstrateError(
                    ErrorCode.REVOKED_KEY_ID,
                    f"Key {key_id!r} is revoked",
                )
            if entry.status == "deprecated":
                log.warning(
                    "keys.deprecated_key_used_explicitly",
                    key_id=key_id,
                    actor_id=actor_id,
                )
            return entry
        candidates = self.active_keys_for(actor_id)
        if candidates:
            return candidates[0]
        return self.active_key()

    def active_scheme(self) -> str:
        self._maybe_reload()
        entry = self.active_key()
        return entry.scheme

    def get_scheme(self, key_id: str) -> str:
        self._maybe_reload()
        entry = self.get_key(key_id)
        return entry.scheme

    def verify_key_status(self, key_id: str, event_timestamp: str | None = None) -> KeyEntry:
        entry = self.get_key(key_id)
        if entry.status == "revoked":
            if event_timestamp is not None and entry.revoked_at is not None:
                if event_timestamp < entry.revoked_at:
                    log.warning(
                        "keys.revoked_key_predates_event",
                        key_id=key_id,
                        revoked_at=entry.revoked_at,
                        event_timestamp=event_timestamp,
                    )
                    return entry
            raise SubstrateError(
                ErrorCode.REVOKED_KEY_ID,
                f"Key {key_id!r} is revoked",
            )
        if entry.status == "deprecated":
            log.warning("keys.deprecated_key_used", key_id=key_id)
        return entry

    @property
    def key_count(self) -> int:
        return len(self._keys)
