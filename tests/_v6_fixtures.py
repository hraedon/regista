"""Compatibility imports for the installed public v6 testing API."""

from __future__ import annotations

from regista.testing import ACTOR_PRINCIPALS as ACTOR_PRINCIPALS
from regista.testing import BOOTSTRAP_PRINCIPAL as BOOTSTRAP_PRINCIPAL
from regista.testing import GENESIS_ENTITY_KINDS as GENESIS_ENTITY_KINDS
from regista.testing import TEST_ENTITY_KINDS as TEST_ENTITY_KINDS
from regista.testing import TEST_HARNESS as TEST_HARNESS
from regista.testing import TEST_HARNESS_VERSION as TEST_HARNESS_VERSION
from regista.testing import TEST_MODEL as TEST_MODEL
from regista.testing import TEST_MODEL_LINEAGE as TEST_MODEL_LINEAGE
from regista.testing import Producer as Producer
from regista.testing import TestKey as TestKey
from regista.testing import V6TestKeyset as V6TestKeyset
from regista.testing import accept_key as accept_key
from regista.testing import acceptance_payload as acceptance_payload
from regista.testing import genesis_envelope as genesis_envelope
from regista.testing import make_v6_keyset as make_v6_keyset
from regista.testing import open_v6_epoch as open_v6_epoch
from regista.testing import project_identity_of as project_identity_of
from regista.testing import register_test_workflow as register_test_workflow
from regista.testing import set_v6_producer_env as set_v6_producer_env
from regista.testing import v6_producer as v6_producer
from regista.testing import write_test_genesis as write_test_genesis

__all__ = [
    "ACTOR_PRINCIPALS",
    "BOOTSTRAP_PRINCIPAL",
    "GENESIS_ENTITY_KINDS",
    "TEST_ENTITY_KINDS",
    "TEST_HARNESS",
    "TEST_HARNESS_VERSION",
    "TEST_MODEL",
    "TEST_MODEL_LINEAGE",
    "Producer",
    "TestKey",
    "V6TestKeyset",
    "accept_key",
    "acceptance_payload",
    "genesis_envelope",
    "make_v6_keyset",
    "open_v6_epoch",
    "project_identity_of",
    "register_test_workflow",
    "set_v6_producer_env",
    "v6_producer",
    "write_test_genesis",
]
