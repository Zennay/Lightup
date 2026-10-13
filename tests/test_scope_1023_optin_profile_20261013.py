"""#1023 W9 reproducible local profiler acceptance: diagnostic, NOT release proof."""
from __future__ import annotations

import io
import json
import tracemalloc
import unittest
from contextlib import redirect_stdout

from lightup.envelope_profile_optin_1023 import (
    MAX_DIAGNOSTIC_INPUT_BYTES, main, measure_synthetic_envelope,
    synthetic_profile_rows,
)


class OfflineShapeProfilerContract(unittest.TestCase):
    def test_valid_synthetic_shape_reports_positive_observation(self):
        report = measure_synthetic_envelope(b'{"value":true}')
        self.assertTrue(report.shape_eligible_only)
        self.assertEqual(report.size_bytes, len(b'{"value":true}'))
        self.assertGreaterEqual(report.elapsed_ns, 0)
        self.assertGreater(report.python_traced_peak_bytes, 0)
        self.assertFalse(tracemalloc.is_tracing())

    def test_over_nodes_reports_shape_denial_without_authority(self):
        raw = b'{"values":[1,2,3,4]}'
        report = measure_synthetic_envelope(raw, max_nodes=2)
        self.assertFalse(report.shape_eligible_only)
        self.assertEqual(report.nodes_limit, 2)
        self.assertGreater(report.python_traced_peak_bytes, 0)

    def test_over_bytes_reports_shape_denial_without_authority(self):
        raw = b'{"approved":true}'
        report = measure_synthetic_envelope(raw, max_bytes=len(raw)-1)
        self.assertFalse(report.shape_eligible_only)
        self.assertEqual(report.bytes_limit, len(raw)-1)

    def test_truncated_json_is_denied_without_network(self):
        report = measure_synthetic_envelope(b'{"tenant":"lab",')
        self.assertFalse(report.shape_eligible_only)
        self.assertGreaterEqual(report.elapsed_ns, 0)

    def test_disallows_non_exact_bytes_types(self):
        for value in (None, '{}', bytearray(b'{}'), memoryview(b'{}'), {}):
            with self.subTest(type=type(value).__name__):
                with self.assertRaises(TypeError):
                    measure_synthetic_envelope(value)

    def test_rejects_oversize_diagnostic_even_if_gate_budget_is_huge(self):
        raw = b'x' * (MAX_DIAGNOSTIC_INPUT_BYTES + 1)
        with self.assertRaises(ValueError):
            measure_synthetic_envelope(raw, max_bytes=len(raw)+1)

    def test_respects_ambient_tracemalloc_without_stopping_it(self):
        self.assertFalse(tracemalloc.is_tracing())
        tracemalloc.start()
        try:
            with self.assertRaises(RuntimeError):
                measure_synthetic_envelope(b'{}')
            self.assertTrue(tracemalloc.is_tracing())
        finally:
            tracemalloc.stop()

    def test_repeatable_synthetic_cases_exclude_real_user_data(self):
        rows = synthetic_profile_rows()
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(isinstance(row["size_bytes"], int) for row in rows))
        self.assertEqual([row["shape_eligible_only"] for row in rows],
                         [True, True, False, False, True])
        self.assertFalse(tracemalloc.is_tracing())

    def test_cli_emits_only_synthetic_metrics_and_no_authority(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(main(), 0)
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["mode"], "synthetic-offline-non-authorizing")
        self.assertFalse(data["metrics_are_release_proof"])
        self.assertEqual(len(data["rows"]), 5)
        self.assertNotIn("target", stdout.getvalue().lower())
        self.assertNotIn("authorization_grant", stdout.getvalue().lower())

    def test_unchanged_byte_input_after_measurement(self):
        raw = b'{"unicode":"\\ud83d\\ude00","ok":true}'
        original = raw[:]
        report = measure_synthetic_envelope(raw)
        self.assertTrue(report.shape_eligible_only)
        self.assertEqual(raw, original)


if __name__ == "__main__":
    unittest.main()
