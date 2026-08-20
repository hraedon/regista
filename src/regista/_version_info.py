from __future__ import annotations

import functools
import hashlib
from dataclasses import dataclass, field
from typing import Any

from ._integrity import REGISTA_VERSION

# Schema version is the highest migration number. 045 drops the dead subsystem
# tables (P1.4, on main); 046 adds the §5.9 projection columns to principal_keys and
# 047 the v2 possession-challenge fields to lifecycle_challenges (both P2.2); 048 adds
# the action-delegation credential store; 049 adds the v6 epoch-boundary guard trigger.
SCHEMA_VERSION: int = 49
# The envelope version this library WRITES (surfaced as "writable envelope" by
# `regista version` / `regista doctor`). 0.6.0 removed the legacy write path:
# post-genesis every ordinary event is stamped v6 by `_v6_writer.append_v6_event`
# and legacy (v1-v5) writers are refused (`_genesis.check_legacy_append`). v6 is
# therefore the sole writable version. It stayed 5 until the v6 writer landed
# (P1.7, #50); it is 6 from 0.6.0 on. This is NOT the max legacy version and is
# not consulted by the verifier — the verifier classifies each stored envelope
# via `classify_envelope_version`.
ENVELOPE_VERSION: int = 6


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
    available_encryption_schemes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": "regista",
            "library_version": self.library_version,
            "schema_version": self.schema_version,
            "canonical_workflow_version": self.canonical_workflow_version,
            "envelope_version": self.envelope_version,
            "canonical_workflow_hash": self.canonical_workflow_hash,
            "available_signing_schemes": list(self.available_signing_schemes),
            "available_encryption_schemes": list(self.available_encryption_schemes),
        }


def versions() -> VersionInfo:
    from ._encryption import available_encryption_schemes
    from ._signing_scheme import available_schemes

    wf_version, wf_hash = _canonical_workflow_info()
    return VersionInfo(
        library_version=REGISTA_VERSION,
        schema_version=SCHEMA_VERSION,
        canonical_workflow_version=wf_version,
        envelope_version=ENVELOPE_VERSION,
        canonical_workflow_hash=wf_hash,
        available_signing_schemes=tuple(available_schemes()),
        available_encryption_schemes=tuple(available_encryption_schemes()),
    )
