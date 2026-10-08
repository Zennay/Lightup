"""Offline reference contract: an authorization evidence envelope is untrusted JSON.

No production authorization or active capability is exercised by this module.
"""
import json
import math
import unittest


def parse_reference_evidence(raw):
    """Strict reference *shape* only; never issues or validates an actual grant."""
    if type(raw) is not str or len(raw.encode("utf-8")) > 8192:
        raise ValueError("invalid envelope")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def reject_constant(value):
        raise ValueError("non-finite JSON number")
    obj = json.loads(raw, object_pairs_hook=unique_pairs,
                     parse_constant=reject_constant)
    if type(obj) is not dict or set(obj) != {"grant_id", "revision", "evidence"}:
        raise ValueError("invalid envelope fields")
    if type(obj["grant_id"]) is not str or not obj["grant_id"] or len(obj["grant_id"]) > 128:
        raise ValueError("invalid grant id")
    if type(obj["revision"]) is not int or not (0 <= obj["revision"] <= 2**53 - 1):
        raise ValueError("invalid revision")
    if type(obj["evidence"]) is not dict or set(obj["evidence"]) != {"issuer", "approved"}:
        raise ValueError("invalid evidence fields")
    e = obj["evidence"]
    if type(e["issuer"]) is not str or not e["issuer"] or len(e["issuer"]) > 128:
        raise ValueError("invalid issuer")
    if type(e["approved"]) is not bool:
        raise ValueError("invalid approval boolean")
    return obj


class EvidenceJsonAmbiguityReferenceTests(unittest.TestCase):
    valid = '{"grant_id":"g-1","revision":3,"evidence":{"issuer":"human","approved":true}}'

    def test_canonical_shape_is_parsed_not_authorized(self):
        self.assertEqual(parse_reference_evidence(self.valid)["revision"], 3)

    def test_duplicate_top_level_grant_id_is_denied(self):
        raw = self.valid.replace('"grant_id":"g-1"', '"grant_id":"g-1","grant_id":"g-2"')
        with self.assertRaises(ValueError):
            parse_reference_evidence(raw)

    def test_nested_duplicate_approval_is_denied(self):
        raw = self.valid.replace('"approved":true', '"approved":true,"approved":false')
        with self.assertRaises(ValueError):
            parse_reference_evidence(raw)

    def test_nonfinite_json_numbers_are_denied(self):
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                parse_reference_evidence(self.valid.replace('"revision":3', '"revision":' + token))

    def test_python_truthiness_cannot_replace_boolean(self):
        for value in ("1", "0", '"true"', "null", "[]"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_reference_evidence(self.valid.replace('"approved":true', '"approved":' + value))

    def test_bool_revision_does_not_count_as_integer(self):
        with self.assertRaises(ValueError):
            parse_reference_evidence(self.valid.replace('"revision":3', '"revision":true'))

    def test_outer_and_nested_extra_fields_are_denied(self):
        for raw in (self.valid.replace('"revision":3', '"revision":3,"scope":"*"'),
                    self.valid.replace('"issuer":"human"', '"issuer":"human","role":"admin"')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_reference_evidence(raw)

    def test_envelope_type_and_size_are_bounded(self):
        for raw in (None, b"{}", self.valid + " " * 9000):
            with self.subTest(kind=type(raw).__name__), self.assertRaises(ValueError):
                parse_reference_evidence(raw)

    def test_reference_parser_does_not_mutate_input(self):
        raw = self.valid
        parsed = parse_reference_evidence(raw)
        parsed["evidence"]["approved"] = False
        self.assertEqual(raw, self.valid)
        self.assertTrue(parse_reference_evidence(raw)["evidence"]["approved"])


if __name__ == "__main__":
    unittest.main()
