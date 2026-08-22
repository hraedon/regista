"""Public test-only helpers for legacy-to-v6 consumer migrations.

The v6 helpers create caller-owned throwaway keysets and open an epoch only
when a test calls them. They do not change production construction or write
paths.
"""

from __future__ import annotations

from ._in_memory import InMemoryRegista as InMemoryRegista
from ._testing import drop_project_schema as drop_project_schema
from ._testing import seed_legacy_principal_key as seed_legacy_principal_key
from ._testing import (
    seed_legacy_principal_key_revocation as seed_legacy_principal_key_revocation,
)
from ._testing import (
    seed_legacy_principal_key_rotation as seed_legacy_principal_key_rotation,
)
from ._testing_v6 import ACTOR_PRINCIPALS as ACTOR_PRINCIPALS
from ._testing_v6 import BOOTSTRAP_PRINCIPAL as BOOTSTRAP_PRINCIPAL
from ._testing_v6 import GENESIS_ENTITY_KINDS as GENESIS_ENTITY_KINDS
from ._testing_v6 import TEST_ENTITY_KINDS as TEST_ENTITY_KINDS
from ._testing_v6 import TEST_HARNESS as TEST_HARNESS
from ._testing_v6 import TEST_HARNESS_VERSION as TEST_HARNESS_VERSION
from ._testing_v6 import TEST_MODEL as TEST_MODEL
from ._testing_v6 import TEST_MODEL_LINEAGE as TEST_MODEL_LINEAGE
from ._testing_v6 import Producer as Producer
from ._testing_v6 import TestKey as TestKey
from ._testing_v6 import V6TestKeyset as V6TestKeyset
from ._testing_v6 import accept_key as accept_key
from ._testing_v6 import acceptance_payload as acceptance_payload
from ._testing_v6 import genesis_envelope as genesis_envelope
from ._testing_v6 import make_v6_keyset as make_v6_keyset
from ._testing_v6 import open_v6_epoch as open_v6_epoch
from ._testing_v6 import project_identity_of as project_identity_of
from ._testing_v6 import register_test_workflow as register_test_workflow
from ._testing_v6 import set_v6_producer_env as set_v6_producer_env
from ._testing_v6 import v6_producer as v6_producer
from ._testing_v6 import write_test_genesis as write_test_genesis
from ._workflow import validate_yaml as validate_yaml

__all__ = [
    "ACTOR_PRINCIPALS",
    "BOOTSTRAP_PRINCIPAL",
    "GENESIS_ENTITY_KINDS",
    "TEST_ENTITY_KINDS",
    "TEST_HARNESS",
    "TEST_HARNESS_VERSION",
    "TEST_MODEL",
    "TEST_MODEL_LINEAGE",
    "InMemoryRegista",
    "Producer",
    "TestKey",
    "V6TestKeyset",
    "accept_key",
    "acceptance_payload",
    "drop_project_schema",
    "genesis_envelope",
    "make_v6_keyset",
    "open_v6_epoch",
    "project_identity_of",
    "register_test_workflow",
    "seed_legacy_principal_key",
    "seed_legacy_principal_key_revocation",
    "seed_legacy_principal_key_rotation",
    "set_v6_producer_env",
    "v6_producer",
    "validate_yaml",
    "write_test_genesis",
]
