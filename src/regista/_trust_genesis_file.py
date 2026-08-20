"""Load an operator-pinned trust-genesis document from a JSON file."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ._errors import ErrorCode, RegistaError

#: The canonical environment variable naming the operator's pinned trust-genesis
#: document. WI-324: every call site used to read ``REGISTRA_...`` — a misspelling
#: of the product name — so an operator who exported the documented spelling got a
#: silent miss and the no-genesis posture instead of an error.
TRUST_GENESIS_PATH_ENV = "REGISTA_TRUST_GENESIS_PATH"

#: The misspelling shipped in 0.6.0 pre-release. Honoured as a deprecated fallback so
#: an environment already configured against the typo keeps working, but never
#: silently: reading it emits a stderr deprecation warning naming both spellings.
DEPRECATED_TRUST_GENESIS_PATH_ENV = "REGISTRA_TRUST_GENESIS_PATH"

_DEPRECATION_WARNING = (
    f"WARNING: {DEPRECATED_TRUST_GENESIS_PATH_ENV} is a deprecated misspelling of "
    f"{TRUST_GENESIS_PATH_ENV} (WI-324). Its value is being honoured, but rename the "
    f"variable: the misspelled name will stop being read in a future release."
)


def trust_genesis_path_from_env(environ: Mapping[str, str] | None = None) -> str | None:
    """Resolve the pinned-genesis path from the environment, canonical name first.

    Returns ``None`` when neither spelling is set. The canonical name wins outright
    when both are present — a mixed environment is not ambiguous, it has one right
    answer — and the deprecated spelling is never read silently.
    """
    env = os.environ if environ is None else environ
    canonical = env.get(TRUST_GENESIS_PATH_ENV)
    if canonical is not None and canonical.strip():
        return canonical
    legacy = env.get(DEPRECATED_TRUST_GENESIS_PATH_ENV)
    if legacy is not None and legacy.strip():
        print(_DEPRECATION_WARNING, file=sys.stderr)
        return legacy
    # An explicitly-set-but-blank value is a configuration error, not an absence:
    # hand it on so load_trust_genesis_document raises `genesis_path_empty` rather
    # than downgrading a configured pin to the no-genesis posture.
    if canonical is not None:
        return canonical
    if legacy is not None:
        print(_DEPRECATION_WARNING, file=sys.stderr)
        return legacy
    return None


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
    "DEPRECATED_TRUST_GENESIS_PATH_ENV",
    "TRUST_GENESIS_PATH_ENV",
    "load_trust_genesis_document",
    "trust_genesis_path_from_env",
]
