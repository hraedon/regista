from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import yaml
from fastapi import HTTPException, Request

from regista._errors import ErrorCode, RegistaError


@dataclass(frozen=True)
class AuthenticatedActor:
    actor_id: str
    actor_kind: str
    allowed_roles: tuple[str, ...]
    allowed_workflows: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_roles, tuple):
            object.__setattr__(self, "allowed_roles", tuple(self.allowed_roles))
        if self.allowed_workflows is not None and not isinstance(
            self.allowed_workflows, tuple
        ):
            object.__setattr__(self, "allowed_workflows", tuple(self.allowed_workflows))

    def can_access_workflow(self, workflow_name: str | None) -> bool:
        if self.allowed_workflows is None:
            return True
        if workflow_name is None:
            return False
        return workflow_name in self.allowed_workflows


def get_actor(request: Request) -> AuthenticatedActor:
    actor = getattr(request.state, "actor", None)
    if actor is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return cast(AuthenticatedActor, actor)


ADMIN_ROLE = "admin"


def require_admin(request: Request) -> AuthenticatedActor:
    actor = get_actor(request)
    if ADMIN_ROLE not in actor.allowed_roles:
        raise HTTPException(
            status_code=403,
            detail=f"Role {ADMIN_ROLE!r} required",
        )
    return actor


class TokenRegistry:
    def __init__(self) -> None:
        self._tokens: dict[str, AuthenticatedActor] = {}

    @classmethod
    def from_file(cls, path: str | Path) -> TokenRegistry:
        reg = cls()
        data = yaml.safe_load(Path(path).read_text())
        if not isinstance(data, dict):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"Token file {path} must contain a top-level YAML mapping",
            )
        tokens = data.get("tokens")
        if not isinstance(tokens, list):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"Token file {path} must contain a 'tokens' list",
            )
        for entry in tokens:
            if not isinstance(entry, dict):
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"Token file {path} contains non-dict entry in tokens list",
                )
            token_sha256 = entry.get("token_sha256")
            actor_id = entry.get("actor_id")
            if not isinstance(token_sha256, str):
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"Token file entry missing 'token_sha256' string in {path}",
                )
            if not isinstance(actor_id, str):
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"Token file entry missing 'actor_id' string in {path}",
                )
            raw_workflows = entry.get("allowed_workflows")
            if raw_workflows is not None:
                if not isinstance(raw_workflows, list):
                    raise RegistaError(
                        ErrorCode.INVALID_ARGUMENT,
                        f"Token file entry 'allowed_workflows' must be a list in {path}",
                    )
                if len(raw_workflows) == 0:
                    raise RegistaError(
                        ErrorCode.INVALID_ARGUMENT,
                        f"Token file entry 'allowed_workflows' cannot be empty "
                        f"(omit the field for unrestricted access) in {path}",
                    )
                if not all(isinstance(wf, str) for wf in raw_workflows):
                    raise RegistaError(
                        ErrorCode.INVALID_ARGUMENT,
                        f"Token file entry 'allowed_workflows' must contain only "
                        f"strings in {path}",
                    )
            actor = AuthenticatedActor(
                actor_id=actor_id,
                actor_kind=entry.get("actor_kind", "agent"),
                allowed_roles=entry.get("allowed_roles", []),
                allowed_workflows=entry.get("allowed_workflows"),
            )
            reg._tokens[token_sha256] = actor
        return reg

    def authenticate(self, raw_token: str) -> AuthenticatedActor | None:
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        actor = self._tokens.get(token_hash)
        if actor is None:
            return None
        return actor
