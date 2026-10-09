"""Offline non-authorizing reference: strict numeric parsing for grant revisions.

No production imports, IO, network, or capability dispatch.
"""
import json
import unittest


def _no_duplicate_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _reject_constant(token):
    raise ValueError("non-JSON numeric constant: " + token)


def reference_revision(envelope):
    if type(envelope) is not str or len(envelope) > 2048:
        return None
    try:
        data = json.loads(
            envelope,
            object_pairs_hook=_no_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (ValueError, TypeError, RecursionError):
        return None
    if type(data) is not dict or set(data) != {"tenant", "grant", "revision"}:
        return None
    if type(data["tenant"]) is not str or not data["tenant"].isascii():
        return None
    if type(data["grant"]) is not str or not data["grant"].isascii():
        return None
    if not (1 <= len(data["tenant"]) <= 80 and 1 <= len(data["grant"]) <= 80):
        return None
    revision = data["revision"]
    if type(revision) is not int or not (1 <= revision <= 2**53 - 1):
        return None
    return revision


class NumericGrantRevisionReferenceTests(unittest.TestCase):
    valid = '{"tenant":"tenant-a","grant":"grant-a","revision":7}'

    def test_positive_canonical_integer(self):
        self.assertEqual(reference_revision(self.valid), 7)

    def test_boolean_is_not_integer_revision(self):
        for value in ("true", "false"):
            with self.subTest(value=value):
                self.assertIsNone(reference_revision(self.valid.replace("7}", value + "}")))

    def test_fraction_and_exponent_are_not_integer_tokens(self):
        for value in ("7.0", "7e0", "7E+0", "7.5", "-0.0"):
            with self.subTest(value=value):
                self.assertIsNone(reference_revision(self.valid.replace("7}", value + "}")))

    def test_nonfinite_tokens_are_denied(self):
        for value in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value):
                self.assertIsNone(reference_revision(self.valid.replace("7}", value + "}")))

    def test_zero_negative_and_out_of_safe_range(self):
        for value in ("0", "-1", "9007199254740992", "9999999999999999999999"):
            with self.subTest(value=value):
                self.assertIsNone(reference_revision(self.valid.replace("7}", value + "}")))

    def test_duplicate_revision_rejected_regardless_of_order(self):
        for value in ('"revision":1,"revision":7', '"revision":7,"revision":1'):
            with self.subTest(value=value):
                self.assertIsNone(reference_revision('{"tenant":"tenant-a","grant":"grant-a",' + value + '}'))

    def test_duplicate_identity_rejected(self):
        self.assertIsNone(reference_revision('{"tenant":"tenant-a","tenant":"tenant-b","grant":"grant-a","revision":7}'))

    def test_extra_key_and_missing_revision(self):
        self.assertIsNone(reference_revision(self.valid[:-1] + ',"approved":true}'))
        self.assertIsNone(reference_revision('{"tenant":"tenant-a","grant":"grant-a"}'))

    def test_strings_arrays_and_null_rejected(self):
        for value in ('"7"', "[7]", "null", "{}", "[]"):
            with self.subTest(value=value):
                self.assertIsNone(reference_revision(self.valid.replace("7}", value + "}")))

    def test_invalid_outer_shape_and_type(self):
        for payload in (None, {}, [], b"{}", "[]", "null", "true", ""):
            with self.subTest(payload=payload):
                self.assertIsNone(reference_revision(payload))

    def test_oversize_envelope_denied(self):
        self.assertIsNone(reference_revision(self.valid + " " * 2048))

    def test_does_not_mutate_source(self):
        original = self.valid
        self.assertEqual(reference_revision(original), 7)
        self.assertEqual(original, self.valid)


if __name__ == "__main__":
    unittest.main()
