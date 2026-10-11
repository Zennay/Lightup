"""Tests for opt-in UUID4 evidence selector admission; no production wiring.

These synthetic tests cannot prove tenant, grant, issuer or evidence integrity.
"""
import unittest
from uuid import UUID, uuid4

from lightup.evidence_id_admission import canonical_evidence_id


class EvidenceIdOptInAdmissionTests(unittest.TestCase):
    VALID = '12345678-1234-4234-8234-123456789abc'

    def test_real_uuid4_issuer_samples_preserve_exact_identity(self):
        for _ in range(256):
            issued = str(uuid4())
            self.assertEqual(canonical_evidence_id(issued), issued)
        self.assertEqual(canonical_evidence_id(self.VALID), self.VALID)

    def test_aliases_controls_confusables_and_non_strings_fail_closed(self):
        class Subclass(str):
            pass

        invalid = (
            None, True, 42, b'uuid', Subclass(self.VALID),
            self.VALID.upper(), self.VALID.replace('-', ''),
            'urn:uuid:' + self.VALID, '{' + self.VALID + '}',
            ' ' + self.VALID, self.VALID + '\n', self.VALID + '\x00',
            self.VALID.replace('a', '\u0430'), self.VALID.replace('1', '\uff11'),
            self.VALID.replace('-', '_'), self.VALID[:-1], self.VALID + '0',
            str(UUID(int=0)),
        )
        for value in invalid:
            with self.subTest(value=repr(value)):
                self.assertIsNone(canonical_evidence_id(value))

    def test_version_and_variant_nibbles_are_exact(self):
        for nibble in '012356789abcdef':
            with self.subTest(version=nibble):
                self.assertIsNone(canonical_evidence_id(
                    self.VALID[:14] + nibble + self.VALID[15:]))
        for nibble in '01234567cdef':
            with self.subTest(variant=nibble):
                self.assertIsNone(canonical_evidence_id(
                    self.VALID[:19] + nibble + self.VALID[20:]))

    def test_explicit_opt_in_gate_blocks_store_calls_before_lookup(self):
        class SpyStore:
            def __init__(self):
                self.calls = []

            def get_evidence(self, evidence_id):
                self.calls.append(evidence_id)
                return evidence_id

        store = SpyStore()

        def opt_in_lookup(value):
            admitted = canonical_evidence_id(value)
            if admitted is None:
                return None
            # Ordering demonstration only; caller still needs tenant authorization.
            return store.get_evidence(admitted)

        for invalid in (self.VALID.upper(), self.VALID.replace('-', ''),
                        None, True, ' ' + self.VALID):
            self.assertIsNone(opt_in_lookup(invalid))
        self.assertEqual(store.calls, [])
        self.assertEqual(opt_in_lookup(self.VALID), self.VALID)
        self.assertEqual(store.calls, [self.VALID])

    def test_distinct_valid_ids_are_not_conflated(self):
        other = self.VALID[:-1] + 'd'
        self.assertEqual(canonical_evidence_id(other), other)
        self.assertNotEqual(canonical_evidence_id(self.VALID),
                            canonical_evidence_id(other))


if __name__ == '__main__':
    unittest.main()
