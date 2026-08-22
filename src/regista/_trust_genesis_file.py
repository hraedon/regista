"""Load an operator-pinned trust-genesis document from a JSON file."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ._errors import ErrorCode, RegistaError

TRUST_GENESIS_PATH_ENV = "REGISTA_TRUST_GENESIS_PATH"

def trust_genesis_path_from_env() -> str | None:
    """Resolve the canonical pinned-genesis environment variable."""
    return os.environ.get(TRUST_GENESIS_PATH_ENV)


def load_trust_genesis_document(path: str | None) -> dict[str, Any] | None:
    """Load one configured genesis path, or return ``None`` only when absent.

    File and JSON failures are configuration errors, not an empty-log signal. Keeping
    this distinction at the file boundary prevents a typo in an operator path from
    silently downgrading a configured trust pin into the no-genesis posture.
    """
    if path is None:
        return None
    if not path.strip():
        raise _genesis_file_error(
            "genesis_path_empty", "the configured trust-genesis path is empty", path
        )

    try:
        with Path(path).open(encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError as exc:
        raise _genesis_file_error(
            "genesis_file_not_found", "the configured trust-genesis file does not exist", path
        ) from exc
    except PermissionError as exc:
        raise _genesis_file_error(
            "genesis_file_unreadable", "the configured trust-genesis file is not readable", path
        ) from exc
    except IsADirectoryError as exc:
        raise _genesis_file_error(
            "genesis_path_not_file", "the configured trust-genesis path is a directory", path
        ) from exc
    except OSError as exc:
        raise _genesis_file_error(
            "genesis_file_unreadable", "the configured trust-genesis file could not be read", path
        ) from exc
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise _genesis_file_error(
            "genesis_file_invalid_json", "the configured trust-genesis file is not valid JSON", path
        ) from exc
    except ValueError as exc:
        raise _genesis_file_error(
            "genesis_path_invalid", "the configured trust-genesis path is invalid", path
        ) from exc

    if not isinstance(raw, Mapping):
        raise _genesis_file_error(
            "genesis_document_not_object",
            "the configured trust-genesis JSON document must be an object",
            path,
        )
    return dict(raw)


def _genesis_file_error(reason: str, message: str, path: str) -> RegistaError:
    return RegistaError(
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        message,
        {"reason": reason, "path": path},
    )


__all__ = [
    "TRUST_GENESIS_PATH_ENV",
    "load_trust_genesis_document",
    "trust_genesis_path_from_env",
]
