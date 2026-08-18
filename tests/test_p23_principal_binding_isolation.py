"""P2.3 — conformance criterion 21: an alias NEVER affects principal↔actor binding.

Criterion 21: "An alias never affects ``key.principal_id == actor_id`` binding: a covered
legacy event still binds to its exact old id."

§2.5 states how that is guaranteed: the two live binding checks —
``_bundle._verify_event_signatures`` ("key.principal_id must equal event.actor_id") and
``verify_principal_binding`` (``_principal_keys.py``, a literal ``principal_id != actor_id``
raise) — "continue to compare *exact* strings; the alias is invisible to both. This is
ratified WI-055 wording and is enforced **structurally** by the fact that no verifier code
path may load aliases before the binding check."

So this file proves the invariant twice:

1. **Behaviourally** — a legacy event covered by a valid alias still binds to its exact old
   id, and does *not* bind to the canonical id the alias points at.
2. **Structurally** — the import graph. ``regista._principal_alias`` is unreachable from
   either binding path, so no future edit can "just consult the alias here": it would have
   to add an import first, and that turns this test red.

The structural half is why the alias contract lives in its own module rather than inside
``regista._principals`` (which the verifier *does* import, for §2.6 reporting).
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from regista._errors import ErrorCode, RegistaError

_BINDING_MODULES = ("regista._bundle", "regista._principal_keys")
_ALIAS_MODULE = "regista._principal_alias"


# ---------------------------------------------------------------------------
# 1. Structural: the import graph witnesses the invariant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", _BINDING_MODULES)
def test_the_binding_modules_cannot_reach_the_alias_module(module):
    """A fresh interpreter imports only the binding module; the alias module must not
    appear in ``sys.modules``, transitively or otherwise.

    Run in a subprocess because this process has already imported everything.
    """
    code = (
        "import sys, importlib;"
        f"importlib.import_module({module!r});"
        f"print({_ALIAS_MODULE!r} in sys.modules)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "False", (
        f"{module} transitively imports {_ALIAS_MODULE}; §2.5 requires that no verifier "
        "code path may load aliases before the binding check (criterion 21)"
    )


def test_the_verifier_cannot_reach_the_alias_module_either():
    """``verify_event_strict`` is 'the only function in the tree that decides whether an
    event is authenticated'. It must not be able to see an alias."""
    code = (
        "import sys, importlib;"
        "importlib.import_module('regista._verification');"
        f"print({_ALIAS_MODULE!r} in sys.modules)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "False"


def test_the_public_package_import_does_not_pull_in_the_alias_module():
    """If ``import regista`` loaded it, every test above would be vacuous."""
    code = f"import sys, regista; print({_ALIAS_MODULE!r} in sys.modules)"
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "False"


def test_the_binding_check_sources_contain_no_alias_vocabulary():
    """Belt and braces on the import test: an inline copy of alias logic would not add an
    import. Neither binding site may mention aliasing at all."""
    import pathlib

    import regista._bundle as bundle_mod
    import regista._principal_keys as pk_mod

    for mod in (bundle_mod, pk_mod):
        source = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
        lowered = source.lower()
        for needle in (
            "principal_alias",
            "principal-alias",
            "reporting_join_only",
            "alias_covers_actor_id",
        ):
            assert needle not in lowered, f"{mod.__name__} mentions {needle!r}"


# ---------------------------------------------------------------------------
# 2. Behavioural: a covered legacy event still binds to its exact old id
# ---------------------------------------------------------------------------


def _covering_alias():
    """A *valid* alias covering the legacy actor ``mvmcc03-agent`` → ``agent:mvmcc03``."""
    from regista._principal_alias import parse_principal_alias

    return parse_principal_alias(
        {
            "type": "regista.principal-alias",
            "version": 1,
            "alias_id": "3f2c8a10-1111-4222-8333-444455556666",
            "trust_domain_id": "0f6c1b2e-7777-4888-8999-aaaabbbbcccc",
            "from_principal_id": "mvmcc03-agent",
            "to_principal_id": "agent:mvmcc03",
            "relation": "renamed",
            "scope": {
                "kind": "unscoped",
                "project_instance_id": None,
                "event_hash_set_root": None,
                "event_count": None,
                "first_event_hash": None,
                "last_event_hash": None,
            },
            "asserted_by": {
                "principal_id": "human:itadmin",
                "method": "operator-inspection",
                "evidence": "suite.env:38",
            },
            "asserted_at": "2026-08-08T00:00:00.000000Z",
            "binding_effect": "reporting_join_only",
        }
    )


def test_the_alias_used_by_these_tests_is_genuinely_valid_and_covering():
    """Otherwise the tests below would prove only that an invalid alias does nothing."""
    from regista._principal_alias import alias_covers_actor_id

    alias = _covering_alias()
    assert alias_covers_actor_id(alias, "mvmcc03-agent") is True
    assert alias.to_principal_id == "agent:mvmcc03"
    assert alias.binding_effect == "reporting_join_only"
    assert alias.satisfies_signature_binding is False


def test_verify_principal_binding_still_compares_exact_strings():
    """``_principal_keys.verify_principal_binding`` is a literal ``principal_id != actor_id``
    raise. A covered legacy actor must still mismatch the canonical principal."""
    from regista._principal_keys import verify_principal_binding

    alias = _covering_alias()
    # A key registered to the canonical principal signing an event whose actor_id is the
    # aliased legacy name: the alias covers exactly this pair, and it must still fail.
    with pytest.raises(RegistaError) as exc:
        verify_principal_binding(
            None,  # never reached: the comparison precedes any registry lookup
            alias.to_principal_id,
            alias.from_principal_id,
        )
    assert exc.value.code == ErrorCode.ACTOR_SIGNER_MISMATCH
    assert alias.from_principal_id in exc.value.message
    assert alias.to_principal_id in exc.value.message


def test_verify_principal_binding_rejects_in_the_other_direction_too():
    """Aliases are directional; binding is not. Neither direction may be bridged."""
    from regista._principal_keys import verify_principal_binding

    alias = _covering_alias()
    with pytest.raises(RegistaError) as exc:
        verify_principal_binding(None, alias.from_principal_id, alias.to_principal_id)
    assert exc.value.code == ErrorCode.ACTOR_SIGNER_MISMATCH


def _ed25519_signed_bundle_event(*, actor_id: str):
    """A genuinely Ed25519-signed v5 event plus the bundle public-key registry entry that
    binds the key to ``actor_id``.

    Real signatures, so the bundle path runs its whole check rather than stopping at a
    forged one — otherwise "still binds" would prove nothing.
    """
    import uuid
    from datetime import UTC, datetime

    import nacl.signing

    from regista._signing import sign_event
    from regista._signing_scheme import Ed25519Scheme
    from regista._types import Event

    signing_key = nacl.signing.SigningKey.generate()
    public_key = bytes(signing_key.verify_key)
    key_id = "pk_p23_isolation"
    event_id = uuid.uuid4()
    entity_id = uuid.uuid4()
    ts = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    payload = {"n": 1}

    signature, canonical_hash, envelope = sign_event(
        event_id=event_id,
        work_item_id=entity_id,
        actor_id=actor_id,
        key_id=key_id,
        event_seq=1,
        workflow_name="test_workflow",
        workflow_version=1,
        timestamp=ts,
        transition="start",
        payload=payload,
        key=bytes(signing_key),
        on_behalf_of=None,
        entity_kind="work_item",
        hash_alg="sha-256",
        actor_kind="agent",
        actor_metadata={},
        scheme=Ed25519Scheme(),
    )
    event = Event(
        event_id=event_id,
        work_item_id=entity_id,
        event_seq=1,
        actor_id=actor_id,
        actor_kind="agent",
        actor_metadata={},
        key_id=key_id,
        workflow_name="test_workflow",
        workflow_version=1,
        timestamp=ts,
        transition="start",
        payload=payload,
        payload_canonical_hash=canonical_hash,
        signature=signature,
        canonical_envelope=envelope,
        scheme_id="ed25519",
        entity_kind="work_item",
        entity_id=entity_id,
        hash_alg="sha-256",
    )
    return event, public_key, key_id


def _key_registry(*, key_id: str, principal_id: str, public_key: bytes):
    return [
        {
            "key_id": key_id,
            "principal_id": principal_id,
            "scheme": "ed25519",
            "public_key": public_key.hex(),
            "status": "active",
        }
    ]


def test_the_bundle_binding_check_refuses_an_aliased_pair():
    """Criterion 21's negative half, at the site §2.5 names: an event whose ``actor_id`` is
    the aliased legacy name, signed by a key bound to the canonical principal the alias
    points at, must still be an actor-signer mismatch.

    This is the exact pairing the alias covers. Bridging it is what the criterion forbids.
    """
    from regista._bundle import _verify_event_signatures

    alias = _covering_alias()
    event, public_key, key_id = _ed25519_signed_bundle_event(
        actor_id=alias.from_principal_id
    )
    verified, unverifiable, errors = _verify_event_signatures(
        [event],
        _key_registry(
            key_id=key_id, principal_id=alias.to_principal_id, public_key=public_key
        ),
    )
    assert verified == 0
    assert unverifiable == 0
    assert len(errors) == 1
    assert "Actor-signer mismatch" in errors[0]
    assert alias.from_principal_id in errors[0]
    assert alias.to_principal_id in errors[0]


def test_a_covered_legacy_event_still_binds_to_its_exact_old_id():
    """Criterion 21 verbatim: 'a covered legacy event still binds to its exact old id'.

    The failure mode symmetric to bridging: an alias must not *invalidate* history either.
    """
    from regista._bundle import _verify_event_signatures

    alias = _covering_alias()
    event, public_key, key_id = _ed25519_signed_bundle_event(
        actor_id=alias.from_principal_id
    )
    verified, unverifiable, errors = _verify_event_signatures(
        [event],
        _key_registry(
            key_id=key_id, principal_id=alias.from_principal_id, public_key=public_key
        ),
    )
    assert errors == []
    assert verified == 1
    assert unverifiable == 0


def test_verify_principal_binding_passes_the_comparison_for_the_exact_old_id():
    """The other named site. Reaching the registry lookup (an ``AttributeError`` on the
    ``None`` manager) proves the string comparison passed rather than raising."""
    from regista._principal_keys import verify_principal_binding

    alias = _covering_alias()
    with pytest.raises(AttributeError):
        verify_principal_binding(None, alias.from_principal_id, alias.from_principal_id)


def test_the_bundle_binding_check_docstring_still_states_the_exact_string_rule():
    """§2.5 cites ``_bundle.py``'s comparison by its wording. If someone relaxes it, the
    wording is the first thing to change."""
    import inspect

    from regista._bundle import _verify_event_signatures

    doc = inspect.getdoc(_verify_event_signatures) or ""
    assert "key.principal_id must equal event.actor_id" in doc


def test_failure_reason_principal_actor_mismatch_still_exists_unraised_in_the_verifier():
    """§2.5's implementation note: ``FailureReason.PRINCIPAL_ACTOR_MISMATCH`` exists in the
    common verifier but is not raised there — the comparison still lives in ``_bundle`` and
    ``_principal_keys``. Consolidating it into ``verify_event_strict`` is the "one
    primitive, all consumers" discipline and is **not** P2.3's change; this test pins the
    current state so the consolidation is a deliberate, visible edit rather than a drift.
    """
    import pathlib

    from regista._verification import FailureReason

    assert FailureReason.PRINCIPAL_ACTOR_MISMATCH.value == "principal_actor_mismatch"
    source = pathlib.Path(
        __import__("regista._verification", fromlist=["x"]).__file__
    ).read_text(encoding="utf-8")
    # Named in the enum, never constructed into a result.
    assert source.count("PRINCIPAL_ACTOR_MISMATCH") == 1
