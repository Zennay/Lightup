"""Offline contract: malformed Unicode must never turn into scope authority.

This is a reference test and does not grant permission or dispatch requests.
"""
import json
import unittest


def parse_strict_identity_envelope(raw: bytes):
    """Return an inert decoded object or None; not an authorization decision."""
    if type(raw) is not bytes or len(raw) > 4096:
        return None

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate member")
            result[key] = value
        return result

    try:
        parsed = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique_pairs)
        if type(parsed) is not dict:
            return None
        stack = [parsed]
        visited = 0
        while stack:
            node = stack.pop()
            visited += 1
            if visited > 128:
                return None
            if isinstance(node, dict):
                stack.extend(node.keys())
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
            elif isinstance(node, str):
                # json.loads accepts escaped unpaired surrogates, but these
                # cannot be losslessly represented as valid UTF-8 identity.
                if any(0xD800 <= ord(c) <= 0xDFFF for c in node):
                    return None
        return parsed
    except (ValueError, UnicodeError, RecursionError, TypeError):
        return None


class UnicodeSurrogateAuthorizationWireTests(unittest.TestCase):
    def test_unpaired_high_surrogate_denied(self):
        self.assertIsNone(parse_strict_identity_envelope(b'{"tenant":"\\ud800"}'))

    def test_unpaired_low_surrogate_denied(self):
        self.assertIsNone(parse_strict_identity_envelope(b'{"asset":"\\udfff"}'))

    def test_surrogate_in_nested_capability_denied(self):
        self.assertIsNone(parse_strict_identity_envelope(b'{"scope":[{"capability":"\\udc00"}]}'))

    def test_surrogate_in_property_name_denied(self):
        self.assertIsNone(parse_strict_identity_envelope(b'{"\\ud800":"tenant"}'))

    def test_valid_escaped_pair_is_decoded(self):
        parsed = parse_strict_identity_envelope(b'{"tenant":"\\ud83d\\ude00"}')
        self.assertEqual(parsed, {"tenant": "\U0001f600"})

    def test_raw_utf8_invalid_surrogate_denied(self):
        self.assertIsNone(parse_strict_identity_envelope(b'{"tenant":"\xed\xa0\x80"}'))

    def test_inert_result_is_not_consent(self):
        self.assertEqual(parse_strict_identity_envelope(b'{"LAB_ACTIVE":true}'),
                         {"LAB_ACTIVE": True})


if __name__ == "__main__":
    unittest.main()
