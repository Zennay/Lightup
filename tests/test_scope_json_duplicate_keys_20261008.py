"""Offline acceptance tests: authorization JSON must reject ambiguous structure.

Reference parser only; NOT a production authorization decision or endpoint.
"""
import json
import math
import unittest


class AmbiguousAuthorizationJSON(ValueError):
    pass


def strict_reference_parse(payload):
    if type(payload) is not str:
        raise AmbiguousAuthorizationJSON("invalid input type")

    def reject_duplicate_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AmbiguousAuthorizationJSON("duplicate JSON member")
            result[key] = value
        return result

    def reject_constant(value):
        raise AmbiguousAuthorizationJSON("non-finite JSON number")

    try:
        document = json.loads(
            payload, object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise AmbiguousAuthorizationJSON("invalid JSON") from exc
    if type(document) is not dict:
        raise AmbiguousAuthorizationJSON("root must be object")
    return document


class AuthorizationJSONAmbiguityTests(unittest.TestCase):
    def test_duplicate_tenant_denied(self):
        with self.assertRaises(AmbiguousAuthorizationJSON):
            strict_reference_parse('{"tenant_id":"A","tenant_id":"B"}')

    def test_duplicate_nested_capability_denied(self):
        with self.assertRaises(AmbiguousAuthorizationJSON):
            strict_reference_parse('{"approval":{"capability":"read","capability":"execute"}}')

    def test_duplicate_across_escape_equivalence_denied(self):
        with self.assertRaises(AmbiguousAuthorizationJSON):
            strict_reference_parse('{"tenant_id":"A","tenant\\u005fid":"B"}')

    def test_duplicate_in_nested_array_denied(self):
        with self.assertRaises(AmbiguousAuthorizationJSON):
            strict_reference_parse('{"grants":[{"active":false,"active":true}]}')

    def test_nonfinite_nan_denied(self):
        with self.assertRaises(AmbiguousAuthorizationJSON):
            strict_reference_parse('{"risk":NaN}')

    def test_infinity_denied(self):
        with self.assertRaises(AmbiguousAuthorizationJSON):
            strict_reference_parse('{"risk":Infinity}')

    def test_root_array_denied(self):
        with self.assertRaises(AmbiguousAuthorizationJSON):
            strict_reference_parse('[{"tenant_id":"A"}]')

    def test_non_string_input_denied(self):
        for value in (None, b'{}', {}, ["{}"]):
            with self.subTest(value=value), self.assertRaises(AmbiguousAuthorizationJSON):
                strict_reference_parse(value)

    def test_trailing_document_denied(self):
        with self.assertRaises(AmbiguousAuthorizationJSON):
            strict_reference_parse('{} {}')

    def test_distinct_nested_keys_allowed_by_parser_only(self):
        document = strict_reference_parse(
            '{"tenant_id":"A","approval":{"tenant_id":"A"},"active":false}'
        )
        self.assertEqual(document["tenant_id"], "A")
        self.assertIs(document["active"], False)

    def test_empty_object_is_parsable_but_not_authorized(self):
        self.assertEqual(strict_reference_parse('{}'), {})


if __name__ == "__main__":
    unittest.main()
