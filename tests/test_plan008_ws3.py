from __future__ import annotations

import pytest

from regista._vendor import rfc8785 as vendored

try:
    import rfc8785 as system
except ImportError:
    system = None  # type: ignore[assignment]

requires_system_rfc8785 = pytest.mark.skipif(
    system is None,
    reason="rfc8785 not installed (install with [vendor-check] extra)",
)

_CORPUS: list[object] = [
    None,
    True,
    False,
    0,
    1,
    -1,
    2**53 - 1,
    -(2**53) + 1,
    0.0,
    1.0,
    -1.0,
    0.1,
    -0.1,
    1e10,
    1e-10,
    1e100,
    1e-100,
    1.7976931348623157e308,
    2.2250738585072014e-308,
    "",
    "a",
    "hello world",
    " ",
    "\n",
    "\t",
    "\r\n",
    '"',
    "\\",
    "/",
    "\x00",
    "\x1f",
    "\u00e9",
    "\u00f1",
    "\u00fc",
    "\u2603",
    "\u2764",
    "\U0001f600",
    "\u4e16\u754c",
    "\u3053\u3093\u306b\u3061\u306f",
    "caf\u00e9",
    "na\u00efve",
    [],
    [1],
    [1, 2, 3],
    [1, "two", 3.0, None, True],
    [[]],
    [[1, 2], [3, 4]],
    {},
    {"a": 1},
    {"a": 1, "b": 2, "c": 3},
    {"z": 1, "a": 2, "m": 3},
    {"": None},
    {"key": "value"},
    {"nested": {"inner": {"deep": True}}},
    {"list": [1, {"a": 2}, [3]]},
    {"a": None, "b": True, "c": False, "d": 0, "e": "", "f": [], "g": {}},
    {" ": 1, "!": 2, "\n": 3},
    {
        "alpha": 1,
        "Alpha": 2,
        "ALPHA": 3,
        "\u00e9": 4,
        "\u00e8": 5,
        "\u00ea": 6,
    },
    {
        str(i): i for i in range(50)
    },
    {"a" * 1000: "b" * 1000},
    [0] * 100,
    {"type": "event", "data": {"seq": 42, "payload": {"x": [1, 2, 3]}}, "meta": None},
    {
        "escapes": "line1\nline2\ttab\"quote\\backslash\b",
        "unicode": "\u00e9\u00e8\u00ea\u00eb",
        "mixed": "abc\u00e9def\u00f1ghi",
    },
    {
        "bool_true": True,
        "bool_false": False,
        "null_val": None,
        "int_val": 42,
        "float_val": 3.14,
        "str_val": "hello",
    },
]


def _deep_nested(depth: int) -> object:
    obj: object = {"leaf": True}
    for _ in range(depth):
        obj = {"nested": obj}
    return obj


_CORPUS.append(_deep_nested(20))
_CORPUS.append({"deep_list": [[[{"x": 1}]]]})


@pytest.mark.parametrize("obj", _CORPUS)
@requires_system_rfc8785
def test_vendored_matches_system(obj: object) -> None:
    v = vendored.dumps(obj)
    s = system.dumps(obj)  # type: ignore[union-attr]
    assert v == s, f"divergence for {obj!r}: vendored={v!r} system={s!r}"


@pytest.mark.parametrize(
    "obj",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        2**53,
        -(2**53) - 1,
    ],
)
@requires_system_rfc8785
def test_error_cases_match(obj: object) -> None:
    v_err: type[Exception] | None = None
    s_err: type[Exception] | None = None
    try:
        vendored.dumps(obj)  # type: ignore[arg-type]
    except Exception as e:
        v_err = type(e)
    try:
        system.dumps(obj)  # type: ignore[union-attr,arg-type]
    except Exception as e:
        s_err = type(e)
    assert v_err is not None and s_err is not None
    assert v_err.__name__ == s_err.__name__


@requires_system_rfc8785
def test_unsupported_type_match() -> None:
    v_err: type[Exception] | None = None
    s_err: type[Exception] | None = None
    try:
        vendored.dumps({1, 2, 3})  # type: ignore[arg-type]
    except Exception as e:
        v_err = type(e)
    try:
        system.dumps({1, 2, 3})  # type: ignore[union-attr,arg-type]
    except Exception as e:
        s_err = type(e)
    assert v_err is not None and s_err is not None
    assert v_err.__name__ == s_err.__name__


@requires_system_rfc8785
def test_exported_names() -> None:
    assert hasattr(vendored, "dumps")
    assert hasattr(vendored, "dump")
    assert hasattr(vendored, "CanonicalizationError")
    assert hasattr(vendored, "IntegerDomainError")
    assert hasattr(vendored, "FloatDomainError")
