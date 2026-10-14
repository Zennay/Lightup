"""Offline reference tests: ambiguous duplicate JSON keys must never authorize.

This parser is a standalone acceptance oracle, NOT the production grant parser.
No network/target IO, grant issuance or executor execution.
"""
import json
import unittest


class AmbiguousAuthorizationInput(ValueError):
    pass


def parse_authorization_envelope(raw):
    if type(raw) is not str:
        raise AmbiguousAuthorizationInput("input must be exact text")

    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AmbiguousAuthorizationInput("duplicate object key")
            result[key] = value
        return result

    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_keys,
                              parse_constant=lambda _: (_ for _ in ()).throw(
                                  AmbiguousAuthorizationInput("nonfinite constant")))
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise AmbiguousAuthorizationInput("invalid JSON") from exc
    if type(document) is not dict:
        raise AmbiguousAuthorizationInput("top-level object required")
    return document


class DuplicateKeyBoundaryTests(unittest.TestCase):
    def assert_denied(self, raw):
        with self.assertRaises(AmbiguousAuthorizationInput):
            parse_authorization_envelope(raw)

    def test_unambiguous_control(self):
        self.assertEqual(parse_authorization_envelope(
            '{"tenant":"a","grant":{"active":false},"scope":["read"]}'),
            {"tenant": "a", "grant": {"active": False}, "scope": ["read"]})

    def test_duplicate_tenant(self):
        self.assert_denied('{"tenant":"a","tenant":"b"}')

    def test_duplicate_allow_decision(self):
        self.assert_denied('{"allow":false,"allow":true}')

    def test_duplicate_nested_grant(self):
        self.assert_denied('{"grant":{"active":false,"active":true}}')

    def test_duplicate_in_array_member(self):
        self.assert_denied('{"grants":[{"tenant":"a","tenant":"b"}]}')

    def test_duplicate_revocation_epoch(self):
        self.assert_denied('{"revisions":{"epoch":1,"epoch":2}}')

    def test_duplicate_unicode_escaped_key(self):
        self.assert_denied('{"tenant":"a","t\\u0065nant":"b"}')

    def test_duplicate_escaped_forward_slash_key(self):
        self.assert_denied('{"a/b":1,"a\\/b":2}')

    def test_nonfinite_number(self):
        self.assert_denied('{"expires":NaN}')

    def test_top_level_array(self):
        self.assert_denied('[{"allow":true}]')

    def test_reject_nonstr_input(self):
        with self.assertRaises(AmbiguousAuthorizationInput):
            parse_authorization_envelope(b'{"tenant":"a"}')

    def test_duplicate_approval_claim(self):
        self.assert_denied('{"approval":{"approved":false,"approved":true}}')

    def test_duplicate_across_nested_array_object(self):
        self.assert_denied('{"scope":{"targets":[{"host":"a","host":"b"}]}}')

    def test_duplicate_unicode_escaped_full_key(self):
        self.assert_denied('{"tenant":"a","\\u0074enant":"b"}')

    def test_multiple_top_level_documents(self):
        self.assert_denied('{"allow":false} {"allow":true}')

    def test_positive_infinity_constant(self):
        self.assert_denied('{"expiry":Infinity}')

    def test_negative_infinity_constant(self):
        self.assert_denied('{"expiry":-Infinity}')

    def test_distinct_case_keys_do_not_alias_in_parser(self):
        result = parse_authorization_envelope('{"tenant":"a","Tenant":"b"}')
        self.assertEqual(len(result), 2)
        # Downstream authorization schema MUST reject unknown or differently-cased keys.


if __name__ == "__main__":
    unittest.main()
