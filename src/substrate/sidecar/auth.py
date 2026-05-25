from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import yaml

from substrate._errors import ErrorCode, SubstrateError


@dataclass(frozen=True)
class AuthenticatedActor:
    actor_id: str
    actor_kind: str
    allowed_roles: tuple[str, ...]

    def __post_init__(self):
        if not isinstance(self.allowed_roles, tuple):
            object.__setattr__(self, "allowed_roles", tuple(self.allowed_roles))


class TokenRegistry:
    def __init__(self) -> None:
        self._tokens: dict[str, AuthenticatedActor] = {}

    @classmethod
    def from_file(cls, path: str | Path) -> TokenRegistry:
        reg = cls()
        data = yaml.safe_load(Path(path).read_text())
        if not isinstance(data, dict):
            raise SubstrateError(
                ErrorCode.INVALID_ARGUMENT,
                f"Token file {path} must contain a top-level YAML mapping",
            )
        tokens = data.get("tokens")
        if not isinstance(tokens, list):
            raise SubstrateError(
                ErrorCode.INVALID_ARGUMENT,
                f"Token file {path} must contain a 'tokens' list",
            )
        for entry in tokens:
            if not isinstance(entry, dict):
                raise SubstrateError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"Token file {path} contains non-dict entry in tokens list",
                )
            token_sha256 = entry.get("token_sha256")
            actor_id = entry.get("actor_id")
            if not isinstance(token_sha256, str):
                raise SubstrateError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"Token file entry missing 'token_sha256' string in {path}",
                )
            if not isinstance(actor_id, str):
                raise SubstrateError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"Token file entry missing 'actor_id' string in {path}",
                )
            actor = AuthenticatedActor(
                actor_id=actor_id,
                actor_kind=entry.get("actor_kind", "agent"),
                allowed_roles=entry.get("allowed_roles", []),
            )
            reg._tokens[token_sha256] = actor
        return reg

    def authenticate(self, raw_token: str) -> AuthenticatedActor:
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        actor = self._tokens.get(token_hash)
        if actor is None:
            return None
        return actor
