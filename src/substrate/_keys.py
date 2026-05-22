from __future__ import annotations

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
    secret: bytes
    status: str


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
                ErrorCode.UNKNOWN_KEY_ID,
                f"Cannot read key set from {self._path}: {e}",
            )

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise SubstrateError(
                ErrorCode.UNKNOWN_KEY_ID,
                f"Invalid JSON in key set {self._path}: {e}",
            )

        if not isinstance(data, dict) or "keys" not in data:
            raise SubstrateError(
                ErrorCode.UNKNOWN_KEY_ID,
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
            env_var = self._env_var_name(key_id)
            env_val = os.environ.get(env_var)
            if env_val is not None:
                secret = env_val.encode("utf-8")
                key_sources[key_id] = "env"
            else:
                secret = entry["secret"]
                if isinstance(secret, str):
                    secret = secret.encode("utf-8")
                key_sources[key_id] = "file"
            new_keys[key_id] = KeyEntry(
                key_id=key_id,
                secret=bytes(secret),
                status=status,
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

    def verify_key_status(self, key_id: str) -> KeyEntry:
        entry = self.get_key(key_id)
        if entry.status == "revoked":
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
