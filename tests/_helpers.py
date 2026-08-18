from __future__ import annotations

import os
from pathlib import Path

TESTS_DIR = Path(__file__).parent

# DSN is configurable via REGISTA_TEST_DSN so CI / operators can point at a
# real Postgres. When unset, the default localhost DSN is used and DB-dependent
# tests are skipped cleanly if that host is unreachable (see conftest.py).
DSN = os.environ.get(
    "REGISTA_TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


def seed_precut_ed25519_witness(regista, url: str, public_key: bytes):
    """Insert an ed25519 ``witness_registrations`` row directly, bypassing register.

    Witness key **lifecycle** is cut from 0.6.0 (``TRUST-DOMAIN.md`` §7 CUT marker,
    D-7), so ``register_witness(key_scheme="ed25519")`` now refuses. Webhook
    *delivery* is explicitly preserved as non-evidentiary transport, and the doctor's
    witness-enrolment check still has to describe whatever rows a store contains.

    Both of those still need an ed25519 registration row to exist. This helper makes
    one the only honest way left: a direct insert that represents a **pre-cut**
    registration. It deliberately does not touch ``principal_keys`` — under the cut,
    an ed25519 witness has no enrolled registry key, which is exactly the state the
    doctor check reports on.

    (The estate has zero witness registrations, per preflight, so no real store is in
    this state; these are tests of how the code describes it if one were.)
    """
    import uuid as _uuid

    witness_id = _uuid.uuid4()
    with regista._mgr.connect() as conn:
        conn.execute(
            "INSERT INTO witness_registrations "
            "(witness_id, url, mode, public_key, key_scheme) "
            "VALUES (%s, %s, %s, %s, %s)",
            [witness_id, url, "witness", public_key, "ed25519"],
        )
        conn.commit()
    return witness_id
