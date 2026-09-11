from __future__ import annotations

import functools
import hashlib
from dataclasses import dataclass, field
from typing import Any

from ._integrity import REGISTA_VERSION

#: The fresh single-baseline schema version (0.8.0 reduced kernel). There is no
#: migration chain behind it: initialization creates this schema on an empty
#: destination and refuses old/unknown schemas.
SCHEMA_VERSION: int = 1


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
    canonical_workflow_hash: str = ""
    extras: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": "regista",
            "library_version": self.library_version,
            "schema_version": self.schema_version,
            "canonical_workflow_version": self.canonical_workflow_version,
            "canonical_workflow_hash": self.canonical_workflow_hash,
            "extras": dict(self.extras),
        }


def versions() -> VersionInfo:
    wf_version, wf_hash = _canonical_workflow_info()
    return VersionInfo(
        library_version=REGISTA_VERSION,
        schema_version=SCHEMA_VERSION,
        canonical_workflow_version=wf_version,
        canonical_workflow_hash=wf_hash,
    )
