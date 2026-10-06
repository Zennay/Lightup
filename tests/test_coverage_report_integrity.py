import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.coverage import CoverageReport, CoverageStatus


class CoverageReportIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.canonical = CoverageReport.build().statuses

    def test_canonical_direct_construction_is_valid(self):
        report = CoverageReport(self.canonical)

        self.assertEqual(report.statuses, self.canonical)
        self.assertEqual(
            report.counts()[CoverageStatus.UNKNOWN.value],
            len(self.canonical),
        )

    def test_unknown_capability_is_rejected(self):
        forged = self.canonical[:-1] + (("unknown-capability", CoverageStatus.UNKNOWN),)

        with self.assertRaisesRegex(ValueError, "unknown capability ids"):
            CoverageReport(forged)

    def test_duplicate_capability_is_rejected(self):
        forged = self.canonical[:-1] + (self.canonical[0],)

        with self.assertRaisesRegex(ValueError, "must be unique"):
            CoverageReport(forged)

    def test_missing_capability_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing capability ids"):
            CoverageReport(self.canonical[:-1])

    def test_raw_string_status_is_rejected(self):
        capability_id, _status = self.canonical[0]
        forged = ((capability_id, "assessed"),) + self.canonical[1:]

        with self.assertRaisesRegex(TypeError, "CoverageStatus"):
            CoverageReport(forged)  # type: ignore[arg-type]

    def test_noncanonical_order_is_rejected(self):
        forged = (self.canonical[1], self.canonical[0]) + self.canonical[2:]

        with self.assertRaisesRegex(ValueError, "canonical registry order"):
            CoverageReport(forged)

    def test_build_rejects_raw_string_status(self):
        with self.assertRaisesRegex(TypeError, "CoverageStatus"):
            CoverageReport.build({"web-baseline": "assessed"})  # type: ignore[dict-item]

    def test_mutable_status_container_is_rejected(self):
        with self.assertRaisesRegex(TypeError, "immutable tuple"):
            CoverageReport(list(self.canonical))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
