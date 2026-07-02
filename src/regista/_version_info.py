from __future__ import annotations

import functools
import hashlib
from dataclasses import dataclass, field
from typing import Any

from ._integrity import REGISTA_VERSION

SCHEMA_VERSION: int = 38
ENVELOPE_VERSION: int = 4


@functools.lru_cache(maxsize=1)
def _canonical_workflow_info() -> tuple[str, str]:
    import yaml

    from ._workflow import canonical_workflow_yaml

    raw = canonical_workflow_yaml()
    doc = yaml.safe_load(raw)
    version = str(doc.get("version", "1"))
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return version, h


@dataclass(frozen=True)
class VersionInfo:
    library_version: str
    schema_version: int
    canonical_workflow_version: str
    envelope_version: int
    canonical_workflow_hash: str = ""
    available_signing_schemes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": "regista",
            "library_version": self.library_version,
            "schema_version": self.schema_version,
            "canonical_workflow_version": self.canonical_workflow_version,
            "envelope_version": self.envelope_version,
            "canonical_workflow_hash": self.canonical_workflow_hash,
            "available_signing_schemes": list(self.available_signing_schemes),
        }


def versions() -> VersionInfo:
    from ._signing_scheme import available_schemes

    wf_version, wf_hash = _canonical_workflow_info()
    return VersionInfo(
        library_version=REGISTA_VERSION,
        schema_version=SCHEMA_VERSION,
        canonical_workflow_version=wf_version,
        envelope_version=ENVELOPE_VERSION,
        canonical_workflow_hash=wf_hash,
        available_signing_schemes=tuple(available_schemes()),
    )
