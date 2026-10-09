"""Offline regression: non-finite numeric syntax must fail closed at JSON edges.

No LightUp executor, network, target, or capability is imported or called.
"""
import json
import unittest


def read_finite_json_arguments(payload: str) -> object:
    """Reject JavaScript-style NaN/Infinity tokens (Python json accepts by default)."""
    def deny_constant(token: str):
        raise ValueError("non-finite JSON numeric constant")
    return json.loads(payload, parse_constant=deny_constant)


def write_finite_json_arguments(value: object) -> str:
    """Never serialize Python NaN or +/-Infinity as non-standard JSON."""
    return json.dumps(value, allow_nan=False)


class ToolNumericJsonBoundaryTests(unittest.TestCase):
    def test_standard_finite_json_roundtrip(self):
        for payload in ('{"number":0}', '{"number":-1.25}', '{"number":1e100}',
                        '{"number":1}', '{"number":null}', '{"number":true}'):
            with self.subTest(payload=payload):
                self.assertEqual(
                    read_finite_json_arguments(write_finite_json_arguments(
                        read_finite_json_arguments(payload))),
                    read_finite_json_arguments(payload))

    def test_nonfinite_tokens_rejected_at_any_depth(self):
        for token in ("NaN", "Infinity", "-Infinity"):
            for payload in (token, '{"number":' + token + '}',
                            '{"args":[0,{"nested":' + token + '}]}'):
                with self.subTest(payload=payload):
                    with self.assertRaises(ValueError):
                        read_finite_json_arguments(payload)

    def test_nonfinite_python_values_refused_during_serialization(self):
        for value in (float('nan'), float('inf'), float('-inf')):
            for envelope in (value, {"number": value}, [1, {"number": value}]):
                with self.subTest(envelope=repr(envelope)):
                    with self.assertRaises(ValueError):
                        write_finite_json_arguments(envelope)

    def test_string_literally_spelling_nan_not_parsed_as_number(self):
        self.assertEqual(read_finite_json_arguments('{"note":"NaN"}'), {"note": "NaN"})

    def test_duplicate_argument_keys_are_separate_admission_boundary(self):
        # JSON decoding normally keeps the final duplicate. This reference
        # must not be reused as a complete ToolCall argument validator.
        self.assertEqual(read_finite_json_arguments('{"x":1,"x":2}'), {"x": 2})


if __name__ == "__main__":
    unittest.main()
