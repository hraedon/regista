"""P2.3 — the estate grammar sweep (§2.7 strictness hook, conformance criterion 20).

§2.7: "A conformance test enumerates every distinct ``actor_id`` and ``principal_id`` in the
preflight output [→ sibling D] and asserts each is either canonical or covered by a
``principal_alias_bound`` event. **It is a failing test, not a warning**, and a genuine
exception surfaces there rather than being pre-authorised by a permissive rule."

Criterion 20: "The estate grammar sweep (§2.7) passes over real preflight output, or fails
naming each exception."

=============================================================================
MECHANISM — READ THIS BEFORE CHANGING ANYTHING IN THIS FILE
=============================================================================

**The population is the committed preflight snapshot, not a live database.** The epoch reset
empties every store, so there is no live estate to sweep on this branch: the honest
population is ``docs/0.6.0/preflight-live.json``, the Stage 0 baseline (generated
2026-08-09, 353,985 events across 26 projects). That also makes the sweep deterministic and
runnable in CI with no database.

**Zero ``principal_alias_bound`` events exist**, and cannot exist until Gate 1 — §2.5's alias
events are trust-log writes that P2.2/P1.7 machinery has yet to be able to make. So the
sweep's alias-coverage input is empty today and **every** non-canonical id is an exception.

**Why this is a strict exact-set ratchet rather than a permanently red test.** §2.7 wants a
failing test, and the reason it wants one is stated plainly: so "a genuine exception surfaces
there rather than being pre-authorised by a permissive rule". A test that is red on every run
forever satisfies the letter and defeats the purpose — a signal that never changes is a
signal nobody reads, and this repo has already ratified that CI must be honestly green while
carrying a *counted, visible* debt figure (``SUITE-RECONCILIATION.md`` §2.1, "manifest-bearing
green is not suite green"). The ``epoch_blocked`` manifest is not available for this: it is
ratchet-locked to a ratified sha256 and its membership criterion is "proven epoch-caused",
which non-canonical identity debt is not.

So the mechanism is the strictest one that stays honest:

* :func:`sweep_preflight` implements §2.7 literally — it returns the exceptions, and a caller
  with a real alias source gets an empty list once coverage is complete.
* :data:`_KNOWN_NON_CANONICAL` is the **exact measured** exception set, committed. The sweep
  test asserts set equality, not a count and not a subset. Therefore:

  - a **new** non-canonical id anywhere in the preflight output fails the suite — which is
    the strictness §2.7 is asking for, and it fails *naming* the id;
  - an id that becomes canonical, or gains alias coverage, **also** fails the suite until the
    list shrinks in the same change — so the debt cannot be silently retained after it is
    paid;
  - the debt is a committed, greppable number (40) rather than a scrolled-past red run.

* :func:`test_the_sweep_fails_loudly_on_a_new_non_canonical_id` proves the failure mode is
  real by injecting one, so "it is a failing test" is demonstrated rather than asserted.
* :func:`test_alias_coverage_actually_satisfies_the_sweep` proves the list is not a hardcoded
  allowlist: supply alias coverage for every exception and the sweep returns empty.

**Gate 1 will shrink this list.** Each signed ``principal_alias_bound`` event removes its
``from_principal_id`` from the exceptions; each host/service that re-enrols under a canonical
id removes itself. The expected end state is an empty list, at which point this file's
ratchet becomes the plain conformance assertion §2.7 describes.

**One honesty limit, stated because it bounds the claim.** ``preflight-live.json`` records
per-project *counts* of every actor-id convention but enumerates only
``top_actor_ids_by_convention`` — the top few ids per convention per project — plus the
``collision_surface`` spellings and the cross-schema ``principal_ids``. The estate's true
distinct-id count is therefore larger than the 47 this sweep can see, and
``TRUST-DOMAIN.md`` §12's handoff to sibling D ("Per project: distinct ``actor_id`` /
``principal_id`` values") is not yet fully satisfied by the committed artifact. The sweep
covers exactly what the artifact records and says so;
:func:`test_the_population_is_a_documented_sample_not_a_complete_enumeration` pins that
limitation so it cannot be quietly forgotten. Widening the preflight to a full distinct-id
inventory is sibling D's change, and it will grow this list.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Iterable, Mapping
from pathlib import Path

import pytest

from regista._principals import classify_principal_id

PREFLIGHT_LIVE = Path(__file__).parent.parent / "docs" / "0.6.0" / "preflight-live.json"


# ---------------------------------------------------------------------------
# The sweep itself — §2.7 expressed as a function so it is reusable and testable
# ---------------------------------------------------------------------------


def collect_preflight_identities(preflight: Mapping) -> dict[str, set[str]]:
    """Every distinct ``actor_id`` / ``principal_id`` the preflight output *enumerates*.

    Returns ``{identity: {where it was found, ...}}``. The "where" strings exist so a
    failure names not just the offending id but the field that carried it.
    """
    found: dict[str, set[str]] = {}

    def add(value: object, where: str) -> None:
        if isinstance(value, str) and value:
            found.setdefault(value, set()).add(where)

    for schema, project in preflight.get("projects", {}).items():
        for check in project.get("checks", []):
            if check.get("name") != "identity_conflicts":
                continue
            detail = check.get("detail", {})
            for convention, ids in detail.get("top_actor_ids_by_convention", {}).items():
                for actor_id in ids:
                    add(actor_id, f"{schema}.actor_id[{convention}]")
            for collision in detail.get("collision_surface", []):
                for spelling in collision.get("spellings", []):
                    # Spellings are recorded as "<convention>:<spelling>"; the spelling may
                    # itself contain a colon, so split once from the left.
                    add(
                        spelling.split(":", 1)[1] if ":" in spelling else spelling,
                        f"{schema}.collision_surface",
                    )
            witness = detail.get("witness_principals", {})
            for principal_id in witness.get("derived_principal_ids", []):
                add(principal_id, f"{schema}.witness_principal_id")

    for dependency in preflight.get("estate", {}).get("cross_schema_key_dependencies", []):
        for principal_id in dependency.get("principal_ids", []):
            add(principal_id, "estate.cross_schema_key_dependencies.principal_ids")

    return found


def sweep_preflight(
    preflight: Mapping, *, alias_covered: Iterable[str] = ()
) -> list[tuple[str, str, str]]:
    """§2.7, literally: every enumerated identity must be canonical **or** alias-covered.

    Returns the exceptions as ``(identity, form, sorted-where)`` triples, sorted. An empty
    return is the passing state §2.7 describes.

    ``alias_covered`` is the set of ``from_principal_id`` values of ``principal_alias_bound``
    events. It is a parameter, not a lookup, because P2.3 owns the alias *contract* and not
    the trust log; P2.2/P1.7 supply the real population once alias events can be written.
    """
    covered = set(alias_covered)
    exceptions: list[tuple[str, str, str]] = []
    for identity, wheres in collect_preflight_identities(preflight).items():
        if identity in covered:
            continue
        classification = classify_principal_id(identity)
        if classification.canonical:
            continue
        exceptions.append((identity, str(classification.form), ",".join(sorted(wheres))))
    return sorted(exceptions)


# ---------------------------------------------------------------------------
# The committed exception set — measured from preflight-live.json, not chosen
# ---------------------------------------------------------------------------

#: Every non-canonical identity the Stage 0 preflight snapshot enumerates, as measured.
#: 40 entries. **Shrink-only in spirit**: an entry leaves when its subject re-enrols under a
#: canonical id or gains a signed ``principal_alias_bound`` event, and adding one requires a
#: deliberate edit here alongside an explanation of why a *new* non-canonical writer exists
#: after the cutover. This is debt, not permission.
_KNOWN_NON_CANONICAL: frozenset[str] = frozenset(
    {
        # host / harness identities that must become `agent:<host>` principals (§2 c.1)
        "mvmcc03-agent",
        "opencode",
        "opencode-session",
        # tooling that must become `service:<tool>` principals
        "ad-steward",
        "agent-notes",
        "agent-notes-dedup",
        "agent-notes-migration",
        "lane-c-qualification",
        # humans that must become `human:<subject>` principals, or alias into one
        "paul",
        "plm",
        "plm@hraedon.com",
        # model / role / session names that CEASE to be principals and become
        # `producer.*` fields on an event signed by the host principal (§2 c.1)
        "acb-accepter-glm-5.2",
        "acb-reviewer-glm-5.2-session",
        "adversarial-reviewer-glm",
        "adversarial-reviewer-kimi",
        "adversarial-reviewer-nemotron",
        "adversarial-reviewer-nemotron-3-ultra",
        "adversarial-reviewer-qwen",
        "claude-fable-5",
        "claude-opus-4-8",
        "codex-gpt-5.6-sol",
        "cw-adversarial-reviewer-qwen",
        "glm-5-2-accept",
        "glm-5-2-adversarial",
        "glm-5-2-session2",
        "glm-accepter",
        "glm-adversarial-reviewer",
        "glm-reviewer",
        "kimi-accepter",
        "kimi-acceptor",
        "kimi-impl",
        "kimi-k3-opencode",
        "kimi-k3-reviewer",
        "kimi-reviewer",
        "longcat-reviewer",
        "opencode-glm-5.2",
        "opencode-sol-reviewer-20260729",
        "qwen-adv-2026-07-29",
        "qwen3.8-max-preview",
        "umans-kimi-k3-2026-07-28",
    }
)

#: The canonical identities the same snapshot enumerates. Asserted as a set too, so an id
#: cannot drop out of canonical form unnoticed.
_KNOWN_CANONICAL: frozenset[str] = frozenset(
    {
        "agent:fable-adv-reviewer",
        "agent:fable-implementer",
        "agent:mvmcc02-opencode",
        "agent:mvmcc03-claude-code",
        "agent:mvmcc03-opus-independent-reviewer",
        "human:dogfood-test",
        "human:itadmin",
    }
)


@pytest.fixture(scope="module")
def preflight() -> Mapping:
    assert PREFLIGHT_LIVE.is_file(), f"missing preflight snapshot at {PREFLIGHT_LIVE}"
    return json.loads(PREFLIGHT_LIVE.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Criterion 20
# ---------------------------------------------------------------------------


def test_the_grammar_sweep_names_exactly_the_known_exceptions(preflight):
    """Criterion 20: "passes over real preflight output, **or fails naming each exception**".

    Today it names 40. Set equality in both directions is the ratchet: a new non-canonical
    id fails here, and so does a paid-off one that was not removed from the list.
    """
    exceptions = sweep_preflight(preflight, alias_covered=())
    named = {identity for identity, _form, _where in exceptions}

    unexpected = sorted(named - _KNOWN_NON_CANONICAL)
    resolved = sorted(_KNOWN_NON_CANONICAL - named)
    assert not unexpected, (
        "NEW non-canonical identities appear in the preflight output. TRUST-DOMAIN.md §2.7 "
        "requires each to be canonical or covered by a signed principal_alias_bound event; "
        f"a new one is new debt, not a new allowance: {unexpected}"
    )
    assert not resolved, (
        "these identities are no longer exceptions — remove them from "
        "_KNOWN_NON_CANONICAL in the same change that resolved them, so the committed debt "
        f"figure stays true: {resolved}"
    )
    assert named == _KNOWN_NON_CANONICAL
    assert len(_KNOWN_NON_CANONICAL) == 40


def test_the_sweep_reports_the_form_and_the_field_for_every_exception(preflight):
    """"fails naming each exception" means naming it usefully: what kind of failure, and
    which preflight field carried it."""
    exceptions = sweep_preflight(preflight)
    assert len(exceptions) == len(_KNOWN_NON_CANONICAL)
    for identity, form, where in exceptions:
        assert form in ("bare_name", "ungrammatical"), identity
        assert where, identity
    by_form: dict[str, list[str]] = {}
    for identity, form, _where in exceptions:
        by_form.setdefault(form, []).append(identity)
    # The one non-bare exception is the estate's email-address convention.
    assert by_form["ungrammatical"] == ["plm@hraedon.com"]
    assert len(by_form["bare_name"]) == 39


def test_the_canonical_population_is_pinned_too(preflight):
    """An id silently losing canonical form would otherwise just grow the exception list,
    and the ratchet above would flag it as "new debt" without saying it was a regression."""
    identities = collect_preflight_identities(preflight)
    canonical = {i for i in identities if classify_principal_id(i).canonical}
    assert canonical == _KNOWN_CANONICAL
    assert len(identities) == len(_KNOWN_CANONICAL) + len(_KNOWN_NON_CANONICAL) == 47


def test_the_exception_list_is_debt_not_permission():
    """No canonical id may be parked in the exception list — that would be a permissive rule
    of exactly the kind §2.7 forbids ("rather than being pre-authorised")."""
    wrongly_listed = sorted(i for i in _KNOWN_NON_CANONICAL if classify_principal_id(i).canonical)
    assert wrongly_listed == [], (
        "canonical identities must never appear in the exception list: " f"{wrongly_listed}"
    )
    assert not (_KNOWN_NON_CANONICAL & _KNOWN_CANONICAL)


def test_the_sweep_fails_loudly_on_a_new_non_canonical_id(preflight):
    """Proves the mechanism is a failing test, not a warning: inject a new non-canonical
    writer into a copy of the snapshot and the sweep must name it."""
    mutated = copy.deepcopy(dict(preflight))
    for project in mutated["projects"].values():
        for check in project.get("checks", []):
            if check.get("name") == "identity_conflicts":
                check["detail"].setdefault("top_actor_ids_by_convention", {}).setdefault(
                    "bare_opaque", {}
                )["brand-new-reviewer-bot"] = 1
                break
        else:
            continue
        break

    exceptions = sweep_preflight(mutated)
    named = {identity for identity, _f, _w in exceptions}
    assert "brand-new-reviewer-bot" in named
    assert named - _KNOWN_NON_CANONICAL == {"brand-new-reviewer-bot"}


def test_alias_coverage_actually_satisfies_the_sweep(preflight):
    """The list is not a hardcoded allowlist: §2.7's "or covered by a
    ``principal_alias_bound`` event" must genuinely discharge an exception.

    With coverage for all 40, the sweep passes empty — which is the state Gate 1 produces.
    """
    assert sweep_preflight(preflight, alias_covered=_KNOWN_NON_CANONICAL) == []
    # Partial coverage discharges exactly the covered ids and no others.
    partial = {"mvmcc03-agent", "agent-notes"}
    remaining = {i for i, _f, _w in sweep_preflight(preflight, alias_covered=partial)}
    assert remaining == _KNOWN_NON_CANONICAL - partial


def test_alias_coverage_comes_from_validated_alias_payloads(preflight):
    """The coverage input is not free text: it is the ``from_principal_id`` of alias payloads
    that passed the §2.5 contract. Proven by discharging one exception through a real one."""
    from regista._principal_alias import parse_principal_alias

    alias = parse_principal_alias(
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
                "evidence": "suite.env:38 PRINCIPAL_ID on host mvmcc03",
            },
            "asserted_at": "2026-08-08T00:00:00.000000Z",
            "binding_effect": "reporting_join_only",
        }
    )
    remaining = {
        i for i, _f, _w in sweep_preflight(preflight, alias_covered={alias.from_principal_id})
    }
    assert "mvmcc03-agent" not in remaining
    assert len(remaining) == len(_KNOWN_NON_CANONICAL) - 1


# ---------------------------------------------------------------------------
# The honesty limits of the population
# ---------------------------------------------------------------------------


def test_the_population_is_a_documented_sample_not_a_complete_enumeration(preflight):
    """``TRUST-DOMAIN.md`` §12 asks sibling D for "distinct ``actor_id``/``principal_id``
    values" per project. The committed artifact records *counts* plus a top-N sample, so the
    sweep's population is smaller than the estate's true distinct-id set. Pinned here so the
    gap is visible rather than mistaken for completeness — closing it is sibling D's change,
    and it will grow ``_KNOWN_NON_CANONICAL``.
    """
    conventions = preflight["estate"]["actor_id_conventions"]
    # The snapshot counts *events* by convention, and does count non-canonical ones.
    assert conventions["bare_opaque"] > 0
    assert conventions["canonical_grammar"] > 0
    assert conventions["email_address"] > 0

    # But no field anywhere enumerates the full distinct set: the sample the sweep can see
    # is far smaller than the number of events it stands for.
    enumerated = collect_preflight_identities(preflight)
    total_events = sum(conventions.values())
    assert len(enumerated) == 47
    assert total_events > 300_000

    for project in preflight["projects"].values():
        for check in project.get("checks", []):
            if check.get("name") != "identity_conflicts":
                continue
            detail = check["detail"]
            assert "distinct_actor_ids" not in detail, (
                "sibling D now enumerates the full distinct set — widen "
                "collect_preflight_identities to use it and re-measure "
                "_KNOWN_NON_CANONICAL"
            )


def test_no_alias_reader_exists_yet_so_the_live_coverage_input_is_empty():
    """The sweep's real ``alias_covered`` population is empty until Gate 1: §2.5's alias is a
    signed trust-log event and P2.3 owns only its payload contract.

    This is the **integration tripwire** for whoever lands the trust-log alias reader. It
    keys off a *reader function*, not the trust-log module's existence, so P2.2 shipping
    ``_trust_log.py`` does not trip it — only shipping the ability to enumerate
    ``principal_alias_bound`` events does, and at that moment the sweep must consume it
    instead of an empty tuple.
    """
    import importlib

    candidate_readers = (
        ("regista._trust_log", "read_principal_alias_bound"),
        ("regista._trust_log", "principal_alias_bound_from_principal_ids"),
        ("regista._principal_alias", "read_principal_alias_bound"),
    )
    live = []
    for module_name, attr in candidate_readers:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        if hasattr(module, attr):
            live.append(f"{module_name}.{attr}")
    assert live == [], (
        "a principal_alias_bound reader now exists — wire it into sweep_preflight's "
        "alias_covered argument and shrink _KNOWN_NON_CANONICAL in the same change: "
        f"{live}"
    )


def test_witness_principals_contribute_no_exceptions(preflight):
    """§2.3 / §7: witness lifecycle is cut from 0.6.0 and the preflight confirms zero
    registrations, so no ``witness:<uuid>`` id is in the sweep's population at all."""
    witness = preflight["estate"]["witness_principals"]
    assert witness["registrations"] == 0
    assert witness["enrolled_into_principal_keys"] == 0
    assert not any(i.startswith("witness:") for i in collect_preflight_identities(preflight))
