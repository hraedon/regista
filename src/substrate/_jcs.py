from __future__ import annotations

from typing import Any

from substrate._vendor.rfc8785 import dumps


def canonicalize(obj: Any) -> bytes:
    return dumps(obj)
