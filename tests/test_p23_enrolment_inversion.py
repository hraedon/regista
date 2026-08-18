"""P2.3 — the enrolment inversion (§2.4, conformance criterion 19) and the §2.7 boundaries.

Criterion 19: ``enroll_principal("mvmcc03-agent")`` is refused post-cutover;
``enroll_principal("agent:...")`` succeeds. "This is the inversion of
``_provision.py:234-247``."

The pre-P2.3 validator was ``^[a-zA-Z0-9._-]+$`` — regista's *only* principal-id validator —
so the canonical grammar could not be enrolled at all while ``append`` took ``actor_id``
unvalidated. Every assertion below inverts one direction of that.

**Which paths are always-strict and which are cutover-gated**, stated plainly because §2.7
is a table and a reader will otherwise guess:

* **Always strict** (no gate, no flag, no project state consulted):
  ``_provision.provision_principal`` → ``_validate_principal_id``, and therefore
  ``Regista.enroll_principal`` and ``regista provision-principal`` /
  ``regista principal enroll``. Also ``_verification._v6_require_principal_id``: a v6
  envelope exists only post-cutover, so its ``actor.principal_id`` is unconditionally held
  to the grammar.
* **Cutover-gated, per project, from its cutover event onward**: the ``append_event``
  ``actor_id`` check, wired as ``require_canonical`` on
  ``regista._contract.validate_actor_id`` / ``validate_mutation_params``. It defaults
  **off** because that function has no project context. Under the epoch reset every new
  store is v6-from-genesis, so for a v6 store the gate is on from the first event and
  P1.7's ordinary writer must pass ``require_canonical=True``.
* **Never** (§2.7 last row): verification, replay, bundle import, historical key lookup.
  Proven by ``test_a_historical_bare_name_event_still_verifies`` and
  ``test_a_historical_bare_name_event_still_replays``.

Not wired here, and deliberately: ``_principal_keys.register_principal_key_conn`` (the
``principal_keys`` projection insert) is untouched. §5.9 rule 2 / criterion 17 remove those
mutators from the package surface in P2.2, and adding a validator to a function that is
being deleted would conflict for no benefit. **P2.2 seam: whichever of the two happens,
that path must end up either gone or calling ``regista._principals.validate_principal_id``.**
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from _helpers import DSN, KEY_PATH

from regista._errors import ErrorCode, RegistaError
from regista._provision import _validate_principal_id, provision_principal
from regista.testing import drop_project_schema

# ---------------------------------------------------------------------------
# Criterion 19 — at the validator, with no database
# ---------------------------------------------------------------------------


def test_canonical_ids_are_now_enrollable_at_all():
    """The pre-P2.3 regex rejected the colon, so *none* of these could be enrolled."""
    for value in (
        "agent:mvmcc03",
        "human:itadmin",
        "service:idp:tenant-a/svc-7",
        "service:witness.0f6c1b2e-1111-4222-8333-444455556666",
    ):
        assert _validate_principal_id(value) == value


def test_bare_names_are_now_refused_with_a_named_error():
    """The pre-P2.3 regex *accepted* every one of these."""
    for value in ("mvmcc03-agent", "human-1", "suite-service", "alice", "agent-notes"):
        with pytest.raises(RegistaError) as exc:
            _validate_principal_id(value)
        assert exc.value.code == ErrorCode.PRINCIPAL_ID_NOT_CANONICAL, value
        assert exc.value.detail["remedy"] == "principal_alias_bound"


def test_key_ids_are_refused_at_the_enrolment_path():
    """§2.1: 'regista enforces it by rejecting ``key`` as a kind at every creation path'."""
    with pytest.raises(RegistaError) as exc:
        _validate_principal_id("key:pk_4f70570b481745a8")
    assert exc.value.code == ErrorCode.PRINCIPAL_ID_UNGRAMMATICAL
    assert exc.value.detail["reason"] == "key_is_never_a_principal"


def test_the_old_validator_regex_no_longer_exists_anywhere_in_the_package():
    """§2.4 names ``_provision.py:234-247`` as regista's *only* copy. Mirrors in dossier
    (`keys.py:19-32`) and agent-suite (`identity.py:566-578`) are those repos' to fix; this
    asserts regista has no second copy left, including the one that used to live in
    ``_verification.py`` as ``_V6_PRINCIPAL_RE``."""
    import pathlib

    import regista

    src = pathlib.Path(regista.__file__).parent
    offenders = []
    for path in sorted(src.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for needle in (
            r"^[a-zA-Z0-9._-]+$",
            r"^[A-Za-z0-9._-]+$",
            "(?:human|agent|service):",
        ):
            if needle in text and path.name != "_principals.py":
                offenders.append(f"{path.name}: {needle}")
    assert offenders == [], (
        "a second copy of the principal-id grammar survives; `regista._principals` is "
        f"meant to be the only implementation: {offenders}"
    )


# ---------------------------------------------------------------------------
# Criterion 19 — end to end through the real enrolment path
# ---------------------------------------------------------------------------


@pytest.fixture
def project():
    name = f"test_p23_{uuid.uuid4().hex[:8]}"
    yield name
    drop_project_schema(DSN, name)


@pytest.fixture
def private_key_file(tmp_path):
    """A *copy* of the shared signing key file.

    ``provision_principal`` appends the minted public key to the key file it is given.
    Pointing it at the committed ``tests/test_keys.json`` mutates a tracked fixture and
    makes the next run fail with ``PRINCIPAL_KEY_ALREADY_EXISTS`` — observed, not theorised.
    """
    import shutil

    target = tmp_path / "keys.json"
    shutil.copy(KEY_PATH, target)
    return str(target)


def test_enroll_principal_refuses_a_bare_name_and_accepts_a_canonical_one(
    project, tmp_path, private_key_file
):
    """Criterion 19 through ``provision_principal`` — the function
    ``Regista.enroll_principal`` and both CLI verbs delegate to.

    **Adapted deliberately by P2.2 (WI-299).** Criterion 19's second clause reads
    "``enroll_principal("agent:...")`` succeeds". It cannot succeed yet: P2.2 made
    ``principal_keys`` a projection of signed trust-log events and refuses any write
    that is not driven by one (``TRUST-DOMAIN.md`` §5.9 rule 2), and
    ``provision_principal`` wrote it with no event. Real enrolment becomes a signed
    ``principal_key_enrolled`` event (§5.5) once P1.7 supplies the v6 append path;
    key provisioning is Gate 2, after Gate 1's trust bootstrap.

    What criterion 19 is *about* — the grammar inversion — is fully preserved and is
    what this test still pins: a bare legacy name is refused **by the grammar**
    (``PRINCIPAL_ID_NOT_CANONICAL``), and a canonical id **passes the grammar** and
    then fails only for the sanctioned downstream reason
    (``PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED``). The two failures are different
    codes on purpose: that is the whole assertion. If the canonical id ever came
    back with a grammar error, the inversion would have regressed.
    """
    from regista._provision import provision

    provision(DSN, [project])

    with pytest.raises(RegistaError) as exc:
        provision_principal(
            DSN, project, "mvmcc03-agent", hmac_key_path=private_key_file, dry_run=True
        )
    assert exc.value.code == ErrorCode.PRINCIPAL_ID_NOT_CANONICAL

    with pytest.raises(RegistaError) as canonical:
        provision_principal(
            DSN,
            project,
            "agent:mvmcc03",
            hmac_key_path=private_key_file,
            private_key_dir=str(tmp_path / "principals"),
        )
    # Past the grammar gate: refused for the projection reason, not the id.
    assert canonical.value.code == ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED
    assert canonical.value.code != ErrorCode.PRINCIPAL_ID_NOT_CANONICAL
    assert canonical.value.detail["principal_id"] == "agent:mvmcc03"
    assert canonical.value.detail["blocked_on"]

    # And the dry run — which writes nothing, so P2.2 does not refuse it — still
    # shows the canonical id being accepted end-to-end by the grammar.
    dry = provision_principal(
        DSN, project, "agent:mvmcc03", hmac_key_path=private_key_file, dry_run=True
    )
    assert dry.principal_id == "agent:mvmcc03"


def test_the_refusal_happens_before_any_key_material_is_generated(
    project, tmp_path, private_key_file
):
    """A refused enrolment must not leave a private key on disk. Ordering matters: the
    validator runs before ``store_private_key``."""
    from regista._provision import provision

    provision(DSN, [project])
    key_dir = tmp_path / "principals"
    key_dir.mkdir()
    with pytest.raises(RegistaError):
        provision_principal(
            DSN,
            project,
            "mvmcc03-agent",
            hmac_key_path=private_key_file,
            private_key_dir=str(key_dir),
        )
    assert list(key_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# §2.7 row 4 — the cutover-gated append check
# ---------------------------------------------------------------------------


def test_append_actor_id_gate_defaults_off():
    """Per project, from its cutover event onward — so the shared boundary validator
    cannot default to on, or every legacy read path that reuses it would start refusing."""
    from regista._contract import validate_actor_id, validate_mutation_params

    validate_actor_id("mvmcc03-agent")
    validate_mutation_params(actor_id="mvmcc03-agent", actor_kind="agent")


def test_append_actor_id_gate_enforces_the_grammar_when_on():
    from regista._contract import validate_actor_id, validate_mutation_params

    with pytest.raises(RegistaError) as exc:
        validate_actor_id("mvmcc03-agent", require_canonical=True)
    assert exc.value.code == ErrorCode.PRINCIPAL_ID_NOT_CANONICAL
    assert exc.value.detail["path"] == "actor_id"

    with pytest.raises(RegistaError):
        validate_mutation_params(
            actor_id="mvmcc03-agent", actor_kind="agent", require_canonical_actor_id=True
        )

    validate_actor_id("agent:mvmcc03", require_canonical=True)
    validate_mutation_params(
        actor_id="agent:mvmcc03", actor_kind="agent", require_canonical_actor_id=True
    )


def test_the_gate_still_applies_the_pre_existing_length_and_printability_rules():
    """The gate *adds* the grammar; it must not replace the boundary checks."""
    from regista._contract import MAX_ACTOR_ID_LENGTH, validate_actor_id

    with pytest.raises(RegistaError) as exc:
        validate_actor_id("x" * (MAX_ACTOR_ID_LENGTH + 1), require_canonical=True)
    assert exc.value.code == ErrorCode.INVALID_ARGUMENT


def test_key_acceptance_is_either_deleted_or_strict():
    """SEAM PINCH for P2.2 (§2.7 "principal_key_accepted — Yes, always").

    P2.3 does not validate inside ``_principal_keys``: §5.9 rule 2 / criterion 17 delete
    those mutators, and validating a doomed function is conflict without benefit. But
    "P2.2 will handle it" in a docstring is exactly the kind of promise that survives as a
    comment and dies as a control, so this test enforces the disjunction instead:

        every registration/acceptance entry point in ``_principal_keys`` is **either
        absent** (P2.2 deleted it, per criterion 17) **or calls**
        ``validate_principal_id``.

    The population is derived from the module rather than hardcoded, so a *successor*
    applier — ``accept_principal_key``, ``register_principal_key_applier``, whatever P2.2
    names it — is caught by the same rule. Passing today would be wrong: the test asserts
    the current state honestly, which is that no such function exists yet *and* none of
    the survivors are strict, so the disjunction is satisfied only by the deletion arm
    being pending. Read the assertion message before "fixing" it.
    """
    import inspect

    import regista._principal_keys as pk

    # Entry points that write into the acceptance surface. Matched by name shape so a
    # renamed successor is still in scope.
    #
    # WIDENED by P2.2: the successor appliers are named `_apply_*_projection`
    # (§5.9 rule 2), which the original prefix list did not reach — so they would have
    # escaped this pinch on a technicality. `_apply_` is added rather than left out,
    # and the enrolment/rotation appliers now call validate_principal_id.
    prefixes = ("register_", "accept_", "enrol", "enroll", "_apply_")
    entry_points = {
        name: obj
        for name, obj in vars(pk).items()
        if inspect.isfunction(obj)
        and obj.__module__ == pk.__name__
        and name.startswith(prefixes)
    }

    unguarded = []
    for name, func in entry_points.items():
        source = inspect.getsource(func)
        if "validate_principal_id" not in source:
            unguarded.append(name)

    # This list is the *current, known* debt. P2.2 must empty it — by deleting these
    # functions (criterion 17) or by making them call the validator. Any NEW name showing
    # up here fails immediately, which is the point of deriving the population.
    known_pending_deletion = {"register_principal_key", "register_principal_key_conn"}
    # §2.7 exempts nothing that *creates* a binding, but revocation acts on a row that
    # already exists: refusing to revoke a historically bare id would strand exactly
    # the keys most likely to need revoking. Named here rather than silently excluded.
    known_pending_deletion |= {"_apply_revocation_projection"}
    surprises = sorted(set(unguarded) - known_pending_deletion)
    assert surprises == [], (
        "new unguarded key-acceptance entry point(s) in regista._principal_keys: "
        f"{surprises}. TRUST-DOMAIN.md §2.7 puts principal_key_accepted in the "
        "always-strict column — call regista._principals.validate_principal_id, or delete "
        "the mutator per §5.9 rule 2 / criterion 17."
    )
    resolved = sorted(known_pending_deletion - set(unguarded) - set(entry_points))
    still_present_and_unguarded = sorted(known_pending_deletion & set(unguarded))
    assert resolved or still_present_and_unguarded, (
        "the known_pending_deletion set no longer describes reality — re-derive it"
    )


def test_every_v6_write_path_enforces_the_canonical_grammar():
    """TRIPWIRE for §2.7 row 4 (``append_event`` actor_id), covering P1.7's future writer.

    **Which form this is, and why.** The literal row-4 gate — ``require_canonical`` on
    ``_contract.validate_actor_id`` — is dormant: no ordinary v6 writer exists on this base
    (``check_legacy_append`` refuses every legacy append, and P1.7 has not landed). A test
    that scanned call sites of ``validate_mutation_params`` for a missing
    ``require_canonical_actor_id=True`` would therefore be **vacuous** — zero v6 writers
    call it, so it could not fire, and a tripwire that cannot fire is worse than a
    documented seam because it reads as coverage.

    So the population is derived from something that *is* real today: the modules that
    actually sign v6 envelopes (``_signing.sign_v6_envelope`` callers). Today that is
    exactly ``_genesis.py``, and it enforces the grammar through
    ``_validate_genesis_envelope`` → ``validate_v6_envelope`` →
    ``_v6_require_principal_id``. The assertion is therefore non-vacuous now — breaking
    ``_genesis`` reddens it — and it fires automatically the moment P1.7 adds a second v6
    writer that enforces by neither named mechanism.

    This is a source-level structural test, not a behavioural one; it cannot prove the
    enforcement runs on every code path inside a writer. The behavioural anchor for the one
    writer that exists is
    :func:`test_the_v6_genesis_writer_refuses_a_non_canonical_actor` below.
    """
    import ast
    import pathlib

    import regista

    src = pathlib.Path(regista.__file__).parent
    # The mechanisms §2.7 row 4 is satisfied by. Any one is sufficient; all of them are
    # *calls*, which is why function granularity works without a call-graph walk.
    accepted_calls = frozenset(
        {
            "validate_v6_envelope",  # v6 schema validation; strict by construction
            "_validate_genesis_envelope",
        }
    )
    accepted_kwargs = frozenset({"require_canonical_actor_id", "require_canonical"})

    def _called_names(node: ast.AST) -> set[str]:
        names = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func = child.func
                if isinstance(func, ast.Name):
                    names.add(func.id)
                elif isinstance(func, ast.Attribute):
                    names.add(func.attr)
        return names

    def _gates_on(node: ast.AST) -> bool:
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            for kw in child.keywords:
                if kw.arg in accepted_kwargs and (
                    isinstance(kw.value, ast.Constant) and kw.value.value is True
                ):
                    return True
        return False

    writers: list[str] = []
    for path in sorted(src.rglob("*.py")):
        if path.name in ("_signing.py", "_principals.py"):
            continue  # the signer itself and the grammar module are not write paths
        text = path.read_text(encoding="utf-8")
        if "sign_v6_envelope" not in text:
            continue
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            called = _called_names(node)
            if "sign_v6_envelope" not in called:
                continue
            where = f"{path.name}::{node.name}"
            writers.append(where)
            assert (called & accepted_calls) or _gates_on(node), (
                f"{where} signs a v6 envelope but enforces the canonical actor grammar by "
                f"none of {sorted(accepted_calls)} and passes no "
                f"{sorted(accepted_kwargs)}=True. TRUST-DOMAIN.md §2.7 row 4 requires "
                f"append_event actor_id validation from a project's cutover event onward, "
                f"and under the epoch reset every v6 store is v6-from-genesis — so the "
                f"gate is on from its first event. Either route the envelope through "
                f"validate_v6_envelope, or pass require_canonical_actor_id=True to "
                f"_contract.validate_mutation_params."
            )

    # Non-vacuity: if this ever finds nothing, the test has stopped testing.
    assert writers, "no v6 write path found — this tripwire has gone vacuous"
    assert "_genesis.py::append_v6_genesis" in writers


def test_the_v6_genesis_writer_refuses_a_non_canonical_actor():
    """The behavioural anchor for the tripwire above: the one v6 write path that exists
    today really does refuse a bare actor, at the envelope boundary, before any signing."""
    import copy
    import json
    import pathlib

    from regista._genesis import _validate_genesis_envelope

    vector = (
        pathlib.Path(__file__).parent / "vectors" / "v6" / "bootstrap-project-initialized.json"
    )
    case = json.loads(vector.read_text(encoding="utf-8"))
    envelope = case["input"].get("envelope") or case["input"].get(
        "envelope_declaration_order"
    )
    assert envelope is not None, "vector shape changed; re-point this test"
    # The shipped vector exercises the envelope schema, not the genesis-shape rules that
    # run after it, so its entity.id and project_instance_id differ. Align them here: this
    # test is about the actor grammar, and a positive control that trips a *later*
    # unrelated genesis rule would prove nothing about the grammar.
    envelope = copy.deepcopy(envelope)
    envelope["entity"]["id"] = envelope["project_instance_id"]

    # Positive control: with a canonical actor the whole genesis validation passes.
    _validate_genesis_envelope(copy.deepcopy(envelope))
    assert envelope["actor"]["principal_id"].startswith("agent:")

    for bad in ("mvmcc03-agent", "key:pk_1", "witness:abc"):
        mutated = copy.deepcopy(envelope)
        mutated["actor"]["principal_id"] = bad
        with pytest.raises(RegistaError) as exc:
            _validate_genesis_envelope(mutated)
        assert exc.value.code == ErrorCode.GENESIS_INVALID, bad
        # It failed on the *grammar*, not on some later genesis-shape rule.
        assert "canonical kind:subject grammar" in exc.value.message, bad


def test_v6_envelope_actor_is_unconditionally_canonical():
    """A v6 envelope is post-cutover by construction, so it needs no gate — and the check
    now delegates to the single grammar implementation rather than a local regex."""
    from regista._verification import V6EnvelopeError, _v6_require_principal_id

    _v6_require_principal_id("agent:mvmcc03")
    for bad in ("mvmcc03-agent", "key:pk_1", "witness:abc", "Human:x", "human:x-"):
        with pytest.raises(V6EnvelopeError) as exc:
            _v6_require_principal_id(bad)
        # The refusal names the section and carries the single grammar's reason string,
        # which is how we know it delegated rather than kept a local copy.
        assert "TRUST-DOMAIN.md §2.1" in str(exc.value), bad


# ---------------------------------------------------------------------------
# §2.7 last row — verification and replay NEVER validate
# ---------------------------------------------------------------------------


def _bare_name_v5_row():
    """A v5 event signed by the legacy bare actor ``mvmcc03-agent`` — the estate's real
    shape (49,651 such events in ``agent_provenance`` per the preflight)."""
    from regista._signing import sign_event
    from regista._testing import KeySet
    from regista._verification import EventRow

    key_entry = KeySet(KEY_PATH).active_key()
    event_id = uuid.uuid4()
    entity_id = uuid.uuid4()
    ts = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    payload = {"legacy": "bare actor"}
    signature, canonical_hash, envelope = sign_event(
        event_id=event_id,
        work_item_id=entity_id,
        actor_id="mvmcc03-agent",
        key_id=key_entry.key_id,
        event_seq=1,
        workflow_name="test_workflow",
        workflow_version=1,
        timestamp=ts,
        transition="start",
        payload=payload,
        key=key_entry.secret,
        on_behalf_of=None,
        entity_kind="work_item",
        hash_alg="sha-256",
        actor_kind="agent",
        actor_metadata={},
    )
    row = EventRow(
        event_id=event_id,
        work_item_id=entity_id,
        entity_kind="work_item",
        entity_id=entity_id,
        actor_id="mvmcc03-agent",
        actor_kind="agent",
        actor_metadata={},
        key_id=key_entry.key_id,
        event_seq=1,
        workflow_name="test_workflow",
        workflow_version=1,
        timestamp=ts,
        hash_alg="sha-256",
        on_behalf_of=None,
        transition="start",
        payload=payload,
        prev_event_hash=None,
        prev_global_event_hash=None,
        global_seq=1,
        canonical_envelope=envelope,
        signature=signature,
        payload_canonical_hash=canonical_hash,
        row_scheme_id="hmac-sha256",
    )
    return row, key_entry


def test_a_historical_bare_name_event_still_verifies():
    """§2.7: 'Verification, replay, bundle import, historical key lookup — **Never**.'

    The enrolment inversion must not retroactively invalidate 54,676 bare-actor events.
    """
    from regista._verification import (
        Applicability,
        StaticKeyResolver,
        TrustedKeySource,
        verify_event_strict,
    )

    row, key_entry = _bare_name_v5_row()
    result = verify_event_strict(
        row,
        keys=StaticKeyResolver(
            material=key_entry.secret,
            scheme_id="hmac-sha256",
            source=TrustedKeySource.KEYSET_FILE,
        ),
    )
    assert result.applicability is Applicability.FULLY_AUTHENTICATED
    assert result.ok is True
    assert result.reasons == ()
    # The grammar is *reported*, not enforced.
    assert result.actor_id_kind is None
    assert str(result.identity_consistency) == "actor_id_ungrammatical"


def test_a_historical_bare_name_event_still_replays(project):
    """Replay is in the 'Never' column too. A bare actor must not halt a rebuild.

    The append path is refused outright under the epoch reset (``GENESIS_REQUIRED``, and
    P1.7 has yet to land the ordinary v6 writer), so this test cannot *write* a bare-actor
    event to replay. What it can prove, and does, is the structural claim: neither the
    replay nor the verification module reaches the strict validator at all, so no rebuild
    can acquire a grammar gate by accident. The signed-event half is covered by
    ``test_a_historical_bare_name_event_still_verifies`` above, which runs the real
    verifier over a real bare-actor signature.
    """
    import pathlib

    from regista import Regista

    sub = Regista.create_project(DSN, project, KEY_PATH)
    try:
        workflow = pathlib.Path(__file__).parent / "test_workflow.yaml"
        sub.register_workflow_file(str(workflow))
        # A bare actor may still be registered for a role: §2.7 goes strict at *enrolment*
        # of a key, not at every mention of a legacy name.
        sub.register_actor_role("mvmcc03-agent", "agent")
    finally:
        sub.close()

    import regista._replay as replay_mod
    import regista._verification as verification_mod

    for mod in (replay_mod, verification_mod):
        source = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
        assert "validate_principal_id" not in source, (
            f"{mod.__name__} reaches the strict validator; §2.7's last row says "
            "verification and replay never validate the grammar"
        )
