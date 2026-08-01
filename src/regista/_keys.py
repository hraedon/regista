from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import structlog

from ._errors import ErrorCode, RegistaError

log = structlog.get_logger()

#: The signing-key transport encodings a KeySet entry may declare (WI-236).
#: ``base64`` is the only transform; ``utf8`` is the explicit spelling of the
#: default (the value's textual bytes are the key). This set is deliberately
#: closed — an unrecognized value fails at load rather than falling through to
#: textual bytes, because a fall-through silently derives a *different* signing
#: key than the entry declared.
SUPPORTED_KEY_ENCODINGS: tuple[str, ...] = ("base64", "utf8")


def _validated_encoding(key_id: str, entry: dict[str, object]) -> str | None:
    """Return the entry's declared ``encoding``, refusing unknown values.

    ``None`` (absent) means the effective key is the textual bytes as-is —
    even when the value happens to *look* base64. That is the effective-key
    trap WI-236 exists to make visible: decoding such a key on migration would
    silently change the signing key, so nothing here ever guesses.
    """
    encoding = entry.get("encoding")
    if encoding is None:
        return None
    if isinstance(encoding, str) and encoding in SUPPORTED_KEY_ENCODINGS:
        return encoding
    raise RegistaError(
        ErrorCode.KEY_LOAD_ERROR,
        f"Key {key_id!r} declares unknown encoding {encoding!r}; supported "
        f"encodings: {', '.join(repr(e) for e in SUPPORTED_KEY_ENCODINGS)} "
        f"(omit 'encoding' to use the textual bytes as-is). Refusing to fall "
        f"through to textual bytes — that would silently derive a different "
        f"signing key than the entry declared.",
    )


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
        if self.scheme == "hmac-sha256":
            return f"{self.scheme}:sha256:{hashlib.sha256(self.secret).hexdigest()}"
        if self.public_key is not None:
            return f"{self.scheme}:sha256:{hashlib.sha256(self.public_key).hexdigest()}"
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Cannot compute fingerprint for scheme {self.scheme!r} without public_key",
        )


def _asymmetric_schemes() -> frozenset[str]:
    from ._signing_scheme import asymmetric_scheme_ids

    return asymmetric_scheme_ids()


def select_signing_key_id(
    candidates: Sequence[tuple[str, str, str]],
) -> str | None:
    """Pure form of the signer's per-principal key selection rule.

    ``candidates`` is a sequence of ``(key_id, scheme, status)`` triples for a
    single principal, **in key-file order**. Returns the ``key_id`` the signer
    would pick, or ``None`` when no active key is available.

    This exists so that surfaces which reason about the signer's choice
    without loading secrets (``regista doctor``'s custody checks) cannot drift
    from :meth:`KeySet._latest_active_key_for`, which delegates here. WI-223:
    that divergence is how a project's chain came to be signed by a key the
    project never registered while every health surface stayed green.
    """
    active = [c for c in candidates if c[2] == "active"]
    if not active:
        return None
    if len(active) == 1:
        return active[0][0]
    asym = _asymmetric_schemes()
    asym_active = [c for c in active if c[1] in asym]
    if asym_active:
        return asym_active[-1][0]
    return active[-1][0]


class KeySet:
    def __init__(
        self,
        path: str | Path,
        poll_interval: float = 30.0,
        expected_key_count: int | None = None,
        env_prefix: str = "REGISTA_HMAC_KEY_",
        strict_asymmetric: bool = False,
    ) -> None:
        self._path = Path(path)
        self._poll_interval = poll_interval
        self._expected_key_count = expected_key_count
        self._env_prefix = env_prefix
        self._strict_asymmetric = strict_asymmetric
        self._keys: dict[str, KeyEntry] = {}
        self._key_sources: dict[str, str] = {}
        self._key_encodings: dict[str, str | None] = {}
        self._active_key_id: str | None = None
        self._last_mtime: float = 0.0
        self._last_check: float = 0.0
        self._lock = threading.Lock()
        self._load()

    def _env_var_name(self, key_id: str) -> str:
        return self._env_prefix + key_id.upper().replace("-", "_")

    def _load(self) -> None:
        try:
            st = self._path.stat()
            mtime = st.st_mtime
            raw = self._path.read_text()
        except OSError as e:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"Cannot read key set from {self._path}: {e}",
            )

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"Invalid JSON in key set {self._path}: {e}",
            )

        if not isinstance(data, dict) or "keys" not in data:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"Key set {self._path} must be a JSON object with a 'keys' array",
            )

        new_keys: dict[str, KeyEntry] = {}
        new_active: str | None = None
        key_sources: dict[str, str] = {}
        key_encodings: dict[str, str | None] = {}
        seen_env_vars: dict[str, str] = {}
        for entry in data["keys"]:
            key_id = entry["key_id"]
            status = entry.get("status", "active")
            if status not in ("active", "deprecated", "revoked"):
                raise RegistaError(
                    ErrorCode.KEY_LOAD_ERROR,
                    f"Key {key_id!r} has unknown status {status!r}; "
                    "expected 'active', 'deprecated', or 'revoked'",
                )
            alg = entry.get("alg", "HMAC-SHA256")
            role = entry.get("role", "actor")
            if role not in ("actor", "auditor", "recovery"):
                raise RegistaError(
                    ErrorCode.INVALID_KEY_ROLE,
                    f"Key {key_id!r} has unknown role {role!r}; "
                    "expected 'actor', 'auditor', or 'recovery'",
                )
            revoked_at = entry.get("revoked_at")
            principal_id = entry.get("principal_id")

            env_var = self._env_var_name(key_id)
            if env_var in seen_env_vars:
                raise RegistaError(
                    ErrorCode.KEY_LOAD_ERROR,
                    f"Key IDs {key_id!r} and {seen_env_vars[env_var]!r} both map to "
                    f"env var {env_var}; rename one to avoid ambiguity",
                )
            seen_env_vars[env_var] = key_id
            # Validated for every entry — an unknown encoding is a broken key
            # file even when an env override means it would not be applied on
            # this host (WI-236: fail loudly at load, never fall through).
            encoding = _validated_encoding(key_id, entry)
            env_val = os.environ.get(env_var)
            if env_val is not None:
                secret = env_val.encode("utf-8")
                key_sources[key_id] = "env"
                # An env override is used textually; the declared encoding is
                # not applied to it (pre-existing behavior, preserved).
                key_encodings[key_id] = None
            elif "secret_ref" in entry:
                from ._secrets import resolve as _resolve_secret

                try:
                    secret = _resolve_secret(entry["secret_ref"])
                except RegistaError:
                    raise
                except Exception as e:
                    raise RegistaError(
                        ErrorCode.KEY_LOAD_ERROR,
                        f"Failed to resolve secret_ref for key {key_id!r}: "
                        f"{type(e).__name__}: {e}",
                    ) from e
                if encoding == "base64":
                    import base64 as _b64

                    secret = _b64.b64decode(secret)
                key_sources[key_id] = f"secret_ref:{entry['secret_ref'].split(':', 1)[0]}"
                key_encodings[key_id] = encoding
            else:
                secret = entry["secret"]
                if encoding == "base64":
                    import base64

                    secret = base64.b64decode(secret)
                elif isinstance(secret, str):
                    secret = secret.encode("utf-8")
                key_sources[key_id] = "file"
                key_encodings[key_id] = encoding

            public_key = entry.get("public_key")
            if isinstance(public_key, str):
                import base64

                public_key = base64.b64decode(public_key)

            scheme = entry.get("scheme", "hmac-sha256")
            from ._signing_scheme import get_scheme

            try:
                get_scheme(scheme)
            except RegistaError:
                raise RegistaError(
                    ErrorCode.KEY_LOAD_ERROR,
                    f"Key {key_id!r} has unknown scheme {scheme!r}; "
                    f"not found in signing scheme registry "
                    f"(available: see available_schemes())",
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

        if self._expected_key_count is not None and len(new_keys) != self._expected_key_count:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"Expected {self._expected_key_count} keys but loaded {len(new_keys)}",
            )

        with self._lock:
            self._keys = new_keys
            self._key_sources = key_sources
            self._key_encodings = key_encodings
            self._active_key_id = new_active
            self._last_mtime = mtime
            self._last_check = time.monotonic()

        if any(s == "file" for s in key_sources.values()):
            log.warning("keys.plaintext_at_rest", path=str(self._path))
        log.info(
            "keys_loaded",
            key_count=len(new_keys),
            active_key_id=new_active,
            key_sources=key_sources,
        )
        log.info(
            "keys.loaded",
            path=str(self._path),
            key_count=len(new_keys),
            active=new_active,
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
        with self._lock:
            entry = self._keys.get(key_id)
        if entry is None:
            log.warning(
                "keys.unknown_key_id",
                key_id_claim=key_id,
            )
            raise RegistaError(
                ErrorCode.UNKNOWN_KEY_ID,
                f"Unknown key_id: {key_id!r}",
            )
        return entry

    def active_key(self) -> KeyEntry:
        self._maybe_reload()
        with self._lock:
            keys = self._keys
            active_id = self._active_key_id
        if active_id is None or active_id not in keys:
            raise RegistaError(
                ErrorCode.UNKNOWN_KEY_ID,
                "No active signing key available",
            )
        entry = keys[active_id]
        if entry.status == "revoked":
            raise RegistaError(
                ErrorCode.REVOKED_KEY_ID,
                f"Active key {active_id!r} is revoked",
            )
        return entry

    def active_keys_for(self, principal_id: str) -> list[KeyEntry]:
        self._maybe_reload()
        with self._lock:
            keys = list(self._keys.values())
        return [
            e for e in keys
            if e.status == "active" and e.principal_id == principal_id
        ]

    def _latest_active_key_for(self, principal_id: str) -> KeyEntry | None:
        candidates = self.active_keys_for(principal_id)
        if not candidates:
            return None
        chosen = select_signing_key_id(
            [(c.key_id, c.scheme, c.status) for c in candidates]
        )
        if chosen is None:
            return None
        return next(c for c in candidates if c.key_id == chosen)

    def _enforce_strict_asymmetric(self, entry: KeyEntry, actor_id: str) -> None:
        asym = _asymmetric_schemes()
        if entry.scheme not in asym:
            raise RegistaError(
                ErrorCode.KEY_ROLE_NOT_PERMITTED,
                f"strict_asymmetric: key {entry.key_id!r} uses scheme "
                f"{entry.scheme!r}; asymmetric scheme required "
                f"(allowed: {sorted(asym)})",
            )
        if entry.public_key is None:
            raise RegistaError(
                ErrorCode.KEY_ROLE_NOT_PERMITTED,
                f"strict_asymmetric: key {entry.key_id!r} has no public_key; "
                f"asymmetric keys must include public_key for independent verification",
            )
        if entry.principal_id != actor_id:
            raise RegistaError(
                ErrorCode.KEY_ROLE_NOT_PERMITTED,
                f"strict_asymmetric: key {entry.key_id!r} is bound to principal "
                f"{entry.principal_id!r} but actor is {actor_id!r}; "
                f"key must be bound to the signing actor",
            )

    def resolve_signing_key(self, actor_id: str, key_id: str | None = None) -> KeyEntry:
        self._maybe_reload()
        if key_id is not None:
            entry = self.get_key(key_id)
            if entry.status == "revoked":
                raise RegistaError(
                    ErrorCode.REVOKED_KEY_ID,
                    f"Key {key_id!r} is revoked",
                )
            if entry.status == "deprecated":
                log.warning(
                    "keys.deprecated_key_used_explicitly",
                    key_id=key_id,
                    actor_id=actor_id,
                )
            if self._strict_asymmetric:
                self._enforce_strict_asymmetric(entry, actor_id)
            return entry
        candidates = self.active_keys_for(actor_id)
        if self._strict_asymmetric:
            asym = _asymmetric_schemes()
            candidates = [c for c in candidates if c.scheme in asym]
        if candidates:
            latest = self._latest_active_key_for(actor_id)
            if latest is not None:
                entry = latest
            else:
                entry = candidates[0]
            if self._strict_asymmetric:
                self._enforce_strict_asymmetric(entry, actor_id)
            return entry
        with self._lock:
            all_for_principal = [
                e for e in self._keys.values() if e.principal_id == actor_id
            ]
        if all_for_principal and all(e.status == "revoked" for e in all_for_principal):
            raise RegistaError(
                ErrorCode.REVOKED_KEY_ID,
                f"All keys for principal {actor_id!r} are revoked",
            )
        if self._strict_asymmetric:
            raise RegistaError(
                ErrorCode.UNKNOWN_KEY_ID,
                f"strict_asymmetric: no active asymmetric key bound to "
                f"actor {actor_id!r}; each actor must have a registered "
                f"per-principal asymmetric key",
            )
        return self.active_key()

    def export_public_keys(self) -> list[dict[str, object]]:
        self._maybe_reload()
        import base64

        with self._lock:
            entries = list(self._keys.values())
        out: list[dict[str, object]] = []
        for entry in entries:
            if entry.public_key is None:
                continue
            out.append({
                "key_id": entry.key_id,
                "scheme": entry.scheme,
                "public_key": base64.b64encode(entry.public_key).decode("ascii"),
                "fingerprint": entry.fingerprint(),
                "principal_id": entry.principal_id,
                "status": entry.status,
                "revoked_at": entry.revoked_at,
            })
        return out

    def describe_keys(self) -> list[dict[str, object]]:
        """Secret-free description of every loaded key, for operator surfaces.

        Each row carries the key_id; where its material came from (``inline``
        — the value in the key file itself — ``env``, or
        ``secret_ref:<provider>``); the transport encoding that was applied to
        derive the effective bytes (``None`` means the textual bytes were used
        as-is, *even when the value looks base64* — the WI-236 effective-key
        trap); and the fingerprint of the EFFECTIVE key bytes via
        :meth:`KeyEntry.fingerprint`. Key material never appears here, so the
        result is safe to print and log.

        The fingerprint is the before/after equality primitive for custody
        changes: identical fingerprints for a key_id prove the effective key is
        byte-for-byte unchanged. This method only *describes* loading — it must
        never influence how an entry's effective key is derived.
        """
        self._maybe_reload()
        with self._lock:
            entries = list(self._keys.values())
            sources = dict(self._key_sources)
            encodings = dict(self._key_encodings)
        out: list[dict[str, object]] = []
        for entry in entries:
            source = sources.get(entry.key_id, "inline")
            # The loader's log label for an inline value is "file", which an
            # operator reads as "a separate key file" — call it what it is.
            if source == "file":
                source = "inline"
            try:
                fingerprint: str | None = entry.fingerprint()
            except RegistaError:
                # An asymmetric entry without a public_key has no reportable
                # fingerprint; say so rather than failing the whole listing.
                fingerprint = None
            out.append({
                "key_id": entry.key_id,
                "source": source,
                "scheme": entry.scheme,
                "status": entry.status,
                "principal_id": entry.principal_id,
                "encoding": encodings.get(entry.key_id),
                "fingerprint": fingerprint,
            })
        return out

    def active_scheme(self) -> str:
        self._maybe_reload()
        entry = self.active_key()
        return entry.scheme

    def get_scheme(self, key_id: str) -> str:
        self._maybe_reload()
        entry = self.get_key(key_id)
        return entry.scheme

    def verify_key_status(self, key_id: str, event_timestamp: str | None = None) -> KeyEntry:
        from datetime import datetime

        entry = self.get_key(key_id)
        if entry.status == "revoked":
            if event_timestamp is not None and entry.revoked_at is not None:
                try:
                    event_dt = datetime.fromisoformat(
                        event_timestamp.replace("Z", "+00:00")
                    )
                    revoked_dt = datetime.fromisoformat(
                        entry.revoked_at.replace("Z", "+00:00")
                    )
                except (ValueError, TypeError):
                    pass
                else:
                    if event_dt < revoked_dt:
                        log.warning(
                            "keys.revoked_key_predates_event",
                            key_id=key_id,
                            revoked_at=entry.revoked_at,
                            event_timestamp=event_timestamp,
                        )
                        return entry
            raise RegistaError(
                ErrorCode.REVOKED_KEY_ID,
                f"Key {key_id!r} is revoked",
            )
        if entry.status == "deprecated":
            log.warning("keys.deprecated_key_used", key_id=key_id)
        return entry

    @property
    def key_count(self) -> int:
        return len(self._keys)
