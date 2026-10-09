"""Offline lexical acceptance reference for LightUp's uuid4 evidence IDs.

Source observation: src/lightup/state.py add_evidence() issues str(uuid4()).
These tests do not establish issuer provenance, tenant isolation or read authority.
"""
import re
import unittest
from uuid import uuid4

_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.ASCII,
)


def canonical_evidence_id(value):
    if type(value) is not str or len(value) != 36 or _PATTERN.fullmatch(value) is None:
        raise ValueError("noncanonical evidence identifier")
    return value


class EvidenceIdentifierReferenceTests(unittest.TestCase):
    VALID = "12345678-1234-4234-8234-123456789abc"

    def test_canonical_uuid4_accepted_without_normalization(self):
        self.assertEqual(canonical_evidence_id(self.VALID), self.VALID)

    def test_actual_uuid4_issuer_samples_roundtrip(self):
        # Standard-library issuer path used by StateStore.add_evidence.
        for _ in range(32):
            identifier = str(uuid4())
            self.assertEqual(canonical_evidence_id(identifier), identifier)

    def test_invalid_uuid_version_four_nibble_is_rejected(self):
        for nibble in "012356789abcdef":
            self.assertRejected(self.VALID[:14] + nibble + self.VALID[15:])

    def test_invalid_variant_nibble_is_rejected(self):
        for nibble in "01234567cdef":
            self.assertRejected(self.VALID[:19] + nibble + self.VALID[20:])

    def test_distinct_canonical_ids_remain_distinct(self):
        other = "12345678-1234-4234-8234-123456789abd"
        self.assertNotEqual(canonical_evidence_id(self.VALID),
                            canonical_evidence_id(other))

    def test_uppercase_uuid_alias_is_rejected(self):
        self.assertRejected(self.VALID.upper())

    def test_uuid_urn_braces_and_compact_aliases_rejected(self):
        for value in ("urn:uuid:" + self.VALID, "{" + self.VALID + "}",
                      self.VALID.replace("-", "")):
            self.assertRejected(value)

    def test_other_uuid_versions_rejected(self):
        for version in ("1", "3", "5", "7"):
            self.assertRejected(self.VALID[:14] + version + self.VALID[15:])

    def test_non_rfc4122_variant_rejected(self):
        for variant in ("0", "4", "7", "c", "f"):
            self.assertRejected(self.VALID[:19] + variant + self.VALID[20:])

    def test_unicode_confusables_rejected(self):
        self.assertRejected(self.VALID.replace("a", "а"))
        self.assertRejected(self.VALID.replace("1", "１"))

    def test_whitespace_and_controls_rejected(self):
        for value in (" " + self.VALID, self.VALID + "\n",
                      self.VALID + "\x00", self.VALID + "\u2028"):
            self.assertRejected(value)

    def test_wrong_length_and_separators_rejected(self):
        for value in (self.VALID[:-1], self.VALID + "0",
                      self.VALID.replace("-", "_"),
                      self.VALID.replace("-", "/")):
            self.assertRejected(value)

    def test_exact_builtin_string_required(self):
        class StrAlias(str):
            pass
        for value in (None, True, 42, self.VALID.encode(), StrAlias(self.VALID)):
            self.assertRejected(value)

    def test_rejected_input_not_mutated(self):
        value = self.VALID.upper()
        self.assertRejected(value)
        self.assertEqual(value, self.VALID.upper())

    def assertRejected(self, value):
        with self.subTest(value=repr(value)):
            with self.assertRaises(ValueError) as caught:
                canonical_evidence_id(value)
            self.assertEqual(str(caught.exception),
                             "noncanonical evidence identifier")


if __name__ == "__main__":
    unittest.main()
