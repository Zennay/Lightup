"""Additional expected-RED evidence decode canaries for legacy SQLite.

Branch-only test acceptance for #886/#885; the decoder source belongs to
other active owners. All data is disposable synthetic SQLite.
"""
from __future__ import annotations

import sys
import unittest

import test_finding_read_evidence_decode_failure as parent


class FindingEvidenceDecoderAdversarialW24(unittest.TestCase):
    setUp = parent.FindingReadEvidenceDecodeFailureAcceptanceTest.setUp
    _replace_evidence_json = parent.FindingReadEvidenceDecodeFailureAcceptanceTest._replace_evidence_json
    _raw_evidence_json = parent.FindingReadEvidenceDecodeFailureAcceptanceTest._raw_evidence_json
    _read = parent.FindingReadEvidenceDecodeFailureAcceptanceTest._read

    def test_deeply_nested_legacy_json_has_stable_evidence_error(self):
        # Deliberately bounded malformed historical payload, not an untrusted
        # oversized allocation: the standard decoder may raise RecursionError.
        depth = min(2048, max(1100, sys.getrecursionlimit() + 64))
        raw = "[" * depth + '"synthetic-evidence"' + "]" * depth
        self._replace_evidence_json(raw)
        with self.assertRaisesRegex(ValueError, "evidence"):
            self._read()
        self.assertEqual(self._raw_evidence_json(), raw)

    def test_other_top_level_json_forms_do_not_escape_as_evidence(self):
        for raw in (
            "true",
            "false",
            '{"reference":"synthetic-evidence"}',
            "1e99999",
        ):
            with self.subTest(raw=raw):
                self._replace_evidence_json(raw)
                with self.assertRaisesRegex(ValueError, "evidence"):
                    self._read()
                self.assertEqual(self._raw_evidence_json(), raw)

    def test_valid_synthetic_evidence_array_retains_canonical_behavior(self):
        raw = '["synthetic-evidence:alpha","synthetic-evidence:beta"]'
        self._replace_evidence_json(raw)
        result = self._read()
        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0].evidence_ids,
            ("synthetic-evidence:alpha", "synthetic-evidence:beta"),
        )
        self.assertEqual(self._raw_evidence_json(), raw)


if __name__ == "__main__":
    unittest.main()
