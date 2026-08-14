"""Conformance vectors for reducer v1 (Gate 0, P0.2).

Kept out of the test module so the cross-interpreter sweep
(``tools/reducer_v1_sweep.py``) can import exactly the same cases without importing pytest —
the sweep runs under interpreters that have no dev dependencies installed.

Each vector is a `(name, envelopes, workflow_definitions)` triple. `envelopes` are canonical
signed bytes in chain order. They are written as JCS output so they are a fixed point: the bytes
here are the bytes a signer would have produced.

The vectors are chosen to hit every place two implementations, or two interpreter versions, can
disagree about the reduced state. A vector that cannot distinguish anything is not a vector.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from regista._jcs import canonicalize

WORKFLOW = {
    ("review", 1): {
        "transitions": [
            {"name": "start", "from_state": "open", "to_state": "in_progress"},
            {"name": "adversarial_pass", "from_state": "in_progress", "to_state": "reviewed"},
            {"name": "accept", "from_state": "reviewed", "to_state": "done"},
        ]
    }
}


def envelope(
    *,
    seq: int,
    transition: str,
    payload: dict[str, Any] | None = None,
    workflow: dict[str, Any] | None = None,
) -> bytes:
    """Build a v6-shaped envelope as canonical bytes.

    The 16-key shape matters: the reducer must read only `transition`, `entity_seq`, `payload`
    and `workflow`, and a full envelope is what proves it ignores the rest.
    """
    obj: dict[str, Any] = {
        "type": "regista.event",
        "version": 6,
        "project_instance_id": "0f6c9a1e-2b3c-4d5e-8f70-112233445566",
        "trust_domain_id": "11111111-2222-3333-4444-555555555555",
        "event_id": f"aaaaaaaa-bbbb-cccc-dddd-{seq:012d}",
        "entity": {"kind": "work_item", "id": "99999999-8888-7777-6666-555555555555"},
        "entity_seq": seq,
        "actor": {"principal_id": "agent:mvmcc03", "kind": "agent", "metadata": None},
        "signing": {
            "scheme_id": "ed25519",
            "key_id": "pk_1bf310ecef19e79a",
            "key_binding_event_hash": "sha256:" + "00" * 32,
        },
        "authorization": {"mode": "direct", "credentials": []},
        "producer": {
            "harness": "claude-code",
            "harness_version": "1.0.0",
            "model": "claude-opus-5",
            "model_lineage": "anthropic",
        },
        "workflow": workflow,
        "occurred_at": f"2026-08-09T12:00:{seq:02d}.000000Z",
        "transition": transition,
        "payload": payload,
        "chain": {
            "hash_algorithm": "sha-256",
            "previous_entity_event_hash": None if seq == 1 else "sha256:" + "11" * 32,
            "previous_project_event_hash": "sha256:" + "22" * 32,
        },
    }
    return canonicalize(obj)


WF_REF = {
    "name": "review",
    "version": 1,
    "definition_hash": "sha256:" + "33" * 32,
    "registration_event_hash": "sha256:" + "44" * 32,
}


def _basic() -> list[bytes]:
    return [
        envelope(
            seq=1,
            transition="created",
            payload={"initial_state": "open", "custom_fields": {"a": 1}},
        ),
        envelope(seq=2, transition="start", payload=None, workflow=WF_REF),
        envelope(
            seq=3,
            transition="adversarial_pass",
            payload={"custom_fields_update": {"b": "two"}},
            workflow=WF_REF,
        ),
    ]


VECTORS: list[tuple[str, list[bytes], dict[tuple[str, int], dict[str, Any]]]] = [
    # ---- baseline -------------------------------------------------------------------
    ("empty-prefix", [], {}),
    ("basic-workflow-walk", _basic(), WORKFLOW),
    (
        "created-only",
        [envelope(seq=1, transition="created", payload={"initial_state": "open"})],
        {},
    ),
    # ---- number handling: the ES6 serialization boundaries -------------------------
    (
        "float-boundaries",
        [
            envelope(
                seq=1,
                transition="created",
                payload={
                    "initial_state": "open",
                    "custom_fields": {
                        "just_under_2_53": float(2**53 - 1),
                        "int_just_under": 2**53 - 1,
                        "small": 1e-7,
                        "smaller": 1.5e-7,
                        "denormal": 5e-324,
                        "neg_zero": -0.0,
                        "tenth": 0.1,
                        "one_point_zero": 1.0,
                        "int_max_safe": 9007199254740991,
                        "int_min_safe": -9007199254740991,
                    },
                },
            )
        ],
        {},
    ),
    # ---- unicode: JCS sorts by UTF-16 code unit, not code point --------------------
    #
    # This is the vector that separates a correct JCS from a plausible one. Sorted by
    # code point, U+1F600 (😀) precedes nothing here; sorted by UTF-16 code unit its
    # surrogate pair (D83D DE00) sorts *before* U+FFFD (EF BF BD in UTF-8, FFFD in
    # UTF-16). A codepoint-sorting implementation emits different bytes.
    (
        "unicode-key-ordering",
        [
            envelope(
                seq=1,
                transition="created",
                payload={
                    "initial_state": "open",
                    "custom_fields": {
                        "\U0001f600": "astral",
                        "�": "replacement",
                        "\u00e9": "e-acute-precomposed",   # U+00E9
                        "e\u0301": "e-plus-combining",   # U+0065 U+0301 — NOT normalised
                        "": "empty key",
                        "a": "ascii",
                        "x\u0000y": "control character in a key",
                    },
                },
            )
        ],
        {},
    ),
    # ---- key insertion order must not survive into the digest ----------------------
    (
        "key-order-irrelevant-a",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "custom_fields": {"z": 1, "m": 2, "a": 3}},
            )
        ],
        {},
    ),
    (
        "key-order-irrelevant-b",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "custom_fields": {"a": 3, "z": 1, "m": 2}},
            )
        ],
        {},
    ),
    # ---- timestamps: the measured cross-version hazard -----------------------------
    (
        "timestamp-normalisation",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "not_before": "2026-08-09T12:00:00Z"},
            ),
            envelope(
                seq=2,
                transition="not_before_set",
                payload={"not_before": "2026-08-09T07:00:00-05:00"},
            ),
        ],
        {},
    ),
    (
        "timestamp-fraction-truncation",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "not_before": "2026-08-09T12:00:00.9999999Z"},
            )
        ],
        {},
    ),
    (
        "timestamp-offset-crosses-day",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "not_before": "2026-12-31T23:30:00-01:00"},
            )
        ],
        {},
    ),
    (
        "timestamp-leap-day",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "not_before": "2028-02-28T23:00:00-02:00"},
            )
        ],
        {},
    ),
    # ---- claim/lease churn: the field-set decision ----------------------------------
    (
        "claim-churn",
        [
            envelope(seq=1, transition="created", payload={"initial_state": "open"}),
            envelope(
                seq=2,
                transition="claim_acquired",
                payload={"actor_id": "agent:mvmcc02", "expires_at": "2026-08-09T13:00:00Z"},
            ),
            envelope(
                seq=3,
                transition="claim_heartbeat",
                payload={"expires_at": "2026-08-09T14:00:00Z", "coalesce_threshold": 0.5},
            ),
            envelope(seq=4, transition="claim_released", payload=None),
        ],
        {},
    ),
    # ---- deep nesting inside custom_fields -----------------------------------------
    (
        "nested-structures",
        [
            envelope(
                seq=1,
                transition="created",
                payload={
                    "initial_state": "open",
                    "custom_fields": {
                        "list": [1, 2.5, "three", None, True, False, [], {}],
                        "nested": {"b": {"d": [{"f": 1}], "c": None}, "a": [[[1]]]},
                    },
                },
            )
        ],
        {},
    ),
]


#: Inputs the reducer must **reject**. Fail-closed behaviour is part of the contract: a
#: reducer that substitutes a default here produces a digest that depends on which inputs the
#: local runtime happened to accept.
REJECT_VECTORS: list[tuple[str, list[bytes], dict[tuple[str, int], dict[str, Any]]]] = [
    (
        # The measured divergence: CPython 3.14 reads this as the following midnight,
        # CPython 3.12/3.13 and PyPy 3.11 raise. Either way it must not reach a digest.
        "hour-24-end-of-day",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "not_before": "2026-08-09T24:00:00Z"},
            )
        ],
        {},
    ),
    (
        "naive-timestamp-no-offset",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "not_before": "2026-08-09T12:00:00"},
            )
        ],
        {},
    ),
    (
        "bare-date",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "not_before": "2026-08-09"},
            )
        ],
        {},
    ),
    (
        "iso-week-date",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "not_before": "2026-W32-7T12:00:00Z"},
            )
        ],
        {},
    ),
    (
        "iso-basic-format",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "not_before": "20260809T120000Z"},
            )
        ],
        {},
    ),
    (
        "space-separated-timestamp",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "not_before": "2026-08-09 12:00:00+00:00"},
            )
        ],
        {},
    ),
    (
        "leap-second",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "not_before": "2026-12-31T23:59:60Z"},
            )
        ],
        {},
    ),
    (
        "impossible-day",
        [
            envelope(
                seq=1,
                transition="created",
                payload={"initial_state": "open", "not_before": "2026-02-30T12:00:00Z"},
            )
        ],
        {},
    ),
    (
        "unregistered-workflow",
        [
            envelope(seq=1, transition="created", payload={"initial_state": "open"}),
            envelope(seq=2, transition="start", payload=None, workflow=WF_REF),
        ],
        {},  # no definition supplied
    ),
    (
        "transition-not-valid-from-state",
        [
            envelope(seq=1, transition="created", payload={"initial_state": "open"}),
            envelope(seq=2, transition="accept", payload=None, workflow=WF_REF),
        ],
        WORKFLOW,
    ),
    (
        "workflow-transition-without-workflow-block",
        [
            envelope(seq=1, transition="created", payload={"initial_state": "open"}),
            envelope(seq=2, transition="start", payload=None),
        ],
        WORKFLOW,
    ),
    (
        "empty-transition",
        [envelope(seq=1, transition="", payload={"initial_state": "open"})],
        {},
    ),
]


#: Raw byte inputs that never reach the transition logic, so they cannot be built by
#: :func:`envelope`.
REJECT_RAW: list[tuple[str, bytes]] = [
    # The non-round-tripping band, found by P0.2. `1e16` is a legal JSON float and JCS
    # canonicalises it to the *integer literal* below, which re-parses as an int outside
    # JCS's safe integer domain and can never be canonicalised again. A signed event
    # carrying it has no computable subject digest. See `_reducer._check_number_domain`.
    (
        "float-1e16-as-canonical-integer",
        b'{"transition":"created","entity_seq":1,"payload":{"x":10000000000000000}}',
    ),
    (
        "float-2-to-53-as-canonical-integer",
        b'{"transition":"created","entity_seq":1,"payload":{"x":9007199254740992}}',
    ),
    (
        "int-above-safe-domain",
        b'{"transition":"created","entity_seq":1,"payload":{"x":9007199254740993}}',
    ),
    (
        "int-below-safe-domain",
        b'{"transition":"created","entity_seq":1,"payload":{"x":-9007199254740993}}',
    ),
    # Above 1e21 ES6 switches to exponential form, so these *do* round-trip — they are
    # rejected anyway, by the stricter |v| >= 2**53 rule. Recorded so the choice is visible.
    (
        "float-1e21-exponential-form",
        b'{"transition":"created","entity_seq":1,"payload":{"x":1e+21}}',
    ),
    (
        "float-nested-in-list",
        b'{"transition":"created","entity_seq":1,"payload":{"x":[1,[2,{"y":1e+16}]]}}',
    ),
    (
        "float-max-double",
        b'{"transition":"created","entity_seq":1,"payload":{"x":1.7976931348623157e+308}}',
    ),
    (
        "duplicate-object-key",
        b'{"transition":"created","transition":"escalated","entity_seq":1}',
    ),
    (
        "nan-constant",
        b'{"transition":"created","entity_seq":1,"payload":{"x":NaN}}',
    ),
    (
        "infinity-constant",
        b'{"transition":"created","entity_seq":1,"payload":{"x":Infinity}}',
    ),
    (
        "invalid-utf8",
        b'{"transition":"created","entity_seq":1,"payload":{"x":"\xff\xfe"}}',
    ),
    ("not-an-object", b'["created"]'),
    (
        "entity-seq-bool",
        b'{"transition":"created","entity_seq":true}',
    ),
    (
        "entity-seq-zero",
        b'{"transition":"created","entity_seq":0}',
    ),
]
