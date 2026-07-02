from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._errors import ErrorCode, RegistaError

CANONICAL_VARS = frozenset({
    "REGISTA_DSN",
    "REGISTA_KEY_PATH",
    "REGISTA_REQUIRE_SSL",
    "REGISTA_PROJECT",
})

_ALIASES: dict[str, tuple[str, ...]] = {
    "REGISTA_DSN": (),
    "REGISTA_KEY_PATH": ("REGISTA_HMAC_KEY_PATH",),
    "REGISTA_REQUIRE_SSL": (),
    "REGISTA_PROJECT": (),
}


def _user_config_path() -> Path:
    return Path(
        os.environ.get("AGENT_SUITE_CONFIG", "~/.config/agent-suite/suite.env")
    ).expanduser()


def _system_config_path() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(base) / "agent-suite" / "suite.env"
    return Path("/etc/agent-suite/suite.env")


def _parse_env_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.is_file():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            value = value[1:-1]
        result[key] = value
    return result


@dataclass(frozen=True)
class SuiteConfig:
    dsn: str | None = None
    key_path: str | None = None
    require_ssl: bool = False
    project: str | None = None
    source: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dsn": self.dsn,
            "key_path": self.key_path,
            "require_ssl": self.require_ssl,
            "project": self.project,
            "source": dict(self.source),
        }


def resolve(
    *,
    env: dict[str, str] | None = None,
    user_config: Path | None = None,
    system_config: Path | None = None,
) -> SuiteConfig:
    if env is None:
        env = dict(os.environ)
    if user_config is None:
        user_config = _user_config_path()
    if system_config is None:
        system_config = _system_config_path()

    file_user = _parse_env_file(user_config)
    file_system = _parse_env_file(system_config)

    sources: dict[str, str] = {}

    def _resolve(var: str) -> str | None:
        env_val = env.get(var)
        if env_val is not None:
            sources[var] = "env"
            return env_val
        for alias in _ALIASES.get(var, ()):
            alias_val = env.get(alias)
            if alias_val is not None:
                sources[var] = f"env:{alias}"
                return alias_val
        file_val = file_user.get(var)
        if file_val is not None:
            sources[var] = f"user:{user_config}"
            return file_val
        for alias in _ALIASES.get(var, ()):
            alias_val = file_user.get(alias)
            if alias_val is not None:
                sources[var] = f"user:{user_config}:{alias}"
                return alias_val
        file_val = file_system.get(var)
        if file_val is not None:
            sources[var] = f"system:{system_config}"
            return file_val
        for alias in _ALIASES.get(var, ()):
            alias_val = file_system.get(alias)
            if alias_val is not None:
                sources[var] = f"system:{system_config}:{alias}"
                return alias_val
        return None

    dsn = _resolve("REGISTA_DSN")
    key_path = _resolve("REGISTA_KEY_PATH")
    project = _resolve("REGISTA_PROJECT")

    require_ssl_raw = _resolve("REGISTA_REQUIRE_SSL")
    require_ssl = False
    if require_ssl_raw is not None:
        require_ssl = require_ssl_raw.lower() in ("1", "true", "yes", "on")

    return SuiteConfig(
        dsn=dsn,
        key_path=key_path,
        require_ssl=require_ssl,
        project=project,
        source=sources,
    )


def resolve_or_raise(
    *,
    env: dict[str, str] | None = None,
    user_config: Path | None = None,
    system_config: Path | None = None,
) -> SuiteConfig:
    cfg = resolve(env=env, user_config=user_config, system_config=system_config)
    missing: list[str] = []
    if cfg.dsn is None:
        missing.append("REGISTA_DSN")
    if cfg.key_path is None:
        missing.append("REGISTA_KEY_PATH")
    if missing:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Missing required config: {', '.join(missing)}. "
            f"Set via env vars, suite.env, or pass explicitly.",
        )
    return cfg
