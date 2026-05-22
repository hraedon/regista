from __future__ import annotations

import pytest


class TestJCSFloatBoundary:
    def test_small_float_scientific(self):
        from substrate._jcs import canonicalize

        result = canonicalize({"val": 1e-7})
        assert result == b'{"val":1e-7}'

    def test_small_float_decimal(self):
        from substrate._jcs import canonicalize

        result = canonicalize({"val": 1e-6})
        assert result == b'{"val":0.000001}'

    def test_large_float_no_scientific(self):
        from substrate._jcs import canonicalize

        result = canonicalize({"val": 1e20})
        assert result == b'{"val":100000000000000000000}'

    def test_large_float_scientific(self):
        from substrate._jcs import canonicalize

        result = canonicalize({"val": 1e21})
        assert result == b'{"val":1e+21}'

    def test_float_precision_preserved(self):
        from substrate._jcs import canonicalize

        result = canonicalize({"val": 0.1 + 0.2})
        assert b"0.30000000000000004" in result

    def test_integer_one_point_oh_serialized_as_int(self):
        from substrate._jcs import canonicalize

        result = canonicalize({"val": 1.0})
        assert result == b'{"val":1}'

    def test_negative_zero_normalized(self):
        from substrate._jcs import canonicalize

        result = canonicalize({"val": -0.0})
        assert result == b'{"val":0}'
        assert canonicalize({"val": 0.0}) == canonicalize({"val": -0.0})


class TestJCSIntegerDomain:
    def test_safe_integer_passes(self):
        from substrate._jcs import canonicalize

        result = canonicalize({"val": 2**53 - 1})
        assert b"9007199254740991" in result

    def test_unsafe_integer_raises(self):
        from substrate._jcs import canonicalize
        from substrate._vendor.rfc8785 import IntegerDomainError

        with pytest.raises(IntegerDomainError):
            canonicalize({"val": 2**53})

    def test_large_power_raises(self):
        from substrate._jcs import canonicalize
        from substrate._vendor.rfc8785 import IntegerDomainError

        with pytest.raises(IntegerDomainError):
            canonicalize({"val": 2**64})


class TestJCSKeyOrdering:
    def test_ascii_keys_sorted(self):
        from substrate._jcs import canonicalize

        result = canonicalize({"c": 3, "a": 1, "b": 2})
        assert result == b'{"a":1,"b":2,"c":3}'

    def test_supplementary_char_key_utf16_order(self):
        from substrate._jcs import canonicalize

        result = canonicalize({"z": 2, "\U0001f600": 1})
        assert result.index(b'"z"') < result.index(b'"\xf0\x9f\x98\x80"')

    def test_nested_object_keys_sorted(self):
        from substrate._jcs import canonicalize

        result = canonicalize({"outer": {"z": 1, "a": 2}})
        assert result == b'{"outer":{"a":2,"z":1}}'


class TestJCSDeterminism:
    def test_same_input_same_output(self):
        from substrate._jcs import canonicalize

        obj = {"b": [1, 2], "a": {"y": 3, "x": 4}, "c": True}
        assert canonicalize(obj) == canonicalize(obj)

    def test_json_round_trip_stable(self):
        import json

        from substrate._jcs import canonicalize

        original = {"x": [1.0, 0.000001, True, None]}
        canonical1 = canonicalize(original)
        parsed = json.loads(canonical1)
        canonical2 = canonicalize(parsed)
        assert canonical1 == canonical2


class TestJCSNFCNote:
    def test_nfc_nfd_produce_different_bytes(self):
        from substrate._jcs import canonicalize

        nfc = canonicalize({"caf\u00e9": 1})
        nfd = canonicalize({"cafe\u0301": 1})
        assert nfc != nfd

    def test_nfc_round_trip_stable(self):
        import json

        from substrate._jcs import canonicalize

        nfc_input = {"caf\u00e9": 1}
        canonical1 = canonicalize(nfc_input)
        parsed = json.loads(canonical1)
        canonical2 = canonicalize(parsed)
        assert canonical1 == canonical2
