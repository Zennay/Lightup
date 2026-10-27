from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.advisories import (
    Advisory,
    AdvisoryDatabase,
    Component,
    compare_versions,
    cvss3_base_score,
    normalize_package,
    parse_version,
    severity_for_score,
)
from lightup.models import Severity


class VersionOrderingTest(unittest.TestCase):
    def test_numeric_ordering(self):
        self.assertEqual(compare_versions("1.2", "1.10"), -1)
        self.assertEqual(compare_versions("2.0", "2.0.0"), 0)
        self.assertEqual(compare_versions("1.0.1", "1.0"), 1)

    def test_prerelease_sorts_below_release(self):
        self.assertEqual(compare_versions("1.0rc1", "1.0"), -1)
        self.assertEqual(compare_versions("2.0.0-beta.1", "2.0.0"), -1)
        self.assertEqual(compare_versions("1.0a1", "1.0b1"), -1)

    def test_postrelease_sorts_above_release(self):
        self.assertEqual(compare_versions("1.0.post1", "1.0"), 1)
        self.assertEqual(compare_versions("1.0-1", "1.0"), 1)

    def test_v_prefix_and_build_metadata_ignored(self):
        self.assertEqual(compare_versions("v3.4", "3.4.0"), 0)
        self.assertEqual(compare_versions("1.0+build5", "1.0"), 0)

    def test_unparseable_raises(self):
        with self.assertRaises(ValueError):
            parse_version("not-a-version")


class CvssTest(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(
            cvss3_base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"), 3.1)

    def test_rejects_non_v3(self):
        with self.assertRaises(ValueError):
            cvss3_base_score("CVSS:2.0/AV:N")
        with self.assertRaises(ValueError):
            cvss3_base_score("CVSS:3.1/AV:N/AC:L")  # incomplete

    def test_severity_bands(self):
        self.assertEqual(severity_for_score(9.8), Severity.CRITICAL)
        self.assertEqual(severity_for_score(7.0), Severity.HIGH)
        self.assertEqual(severity_for_score(4.0), Severity.MEDIUM)
        self.assertEqual(severity_for_score(0.1), Severity.LOW)
        self.assertEqual(severity_for_score(0.0), Severity.INFO)


class NormalizeTest(unittest.TestCase):
    def test_pypi_normalization(self):
        self.assertEqual(normalize_package("PyPI", "Flask_SQLAlchemy"),
                         ("PyPI", "flask-sqlalchemy"))
        self.assertEqual(normalize_package("pypi", "Demo.Lib"), ("PyPI", "demo-lib"))

    def test_npm_lowercased(self):
        self.assertEqual(normalize_package("npm", "Left-Pad"), ("npm", "left-pad"))


def _osv(advisory_id, name, introduced, fixed, ecosystem="PyPI", alias="CVE-2021-0001"):
    return {
        "id": advisory_id,
        "aliases": [alias],
        "summary": "x",
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"package": {"ecosystem": ecosystem, "name": name},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": introduced}, {"fixed": fixed}]}]}],
    }


class AdvisoryMatchingTest(unittest.TestCase):
    def setUp(self):
        self.db = AdvisoryDatabase.from_records([
            _osv("GHSA-aaaa", "demo-lib", "0", "2.0.1"),
            _osv("GHSA-bbbb", "left-pad", "1.0.0", "1.3.0", ecosystem="npm",
                 alias="CVE-2022-0002"),
        ])

    def test_vulnerable_version_matches(self):
        matches = self.db.match(Component("PyPI", "Demo_Lib", "1.5.0"))
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].advisory.advisory_id, "GHSA-aaaa")
        self.assertEqual(matches[0].recommended_version, "2.0.1")
        self.assertEqual(matches[0].advisory.severity(), Severity.CRITICAL)

    def test_fixed_version_not_matched(self):
        self.assertEqual(self.db.match(Component("PyPI", "demo-lib", "2.0.1")), [])
        self.assertEqual(self.db.match(Component("PyPI", "demo-lib", "2.1.0")), [])

    def test_version_below_introduced_not_matched(self):
        self.assertEqual(self.db.match(Component("npm", "left-pad", "0.9.0")), [])

    def test_unknown_package_not_matched(self):
        self.assertEqual(self.db.match(Component("PyPI", "unrelated", "1.0")), [])

    def test_unparseable_version_is_skipped_not_crash(self):
        self.assertEqual(self.db.match(Component("PyPI", "demo-lib", "weird")), [])

    def test_kev_flagging(self):
        flagged = self.db.apply_kev({"vulnerabilities": [{"cveID": "CVE-2021-0001"}]})
        self.assertEqual(flagged, 1)
        match = self.db.match(Component("PyPI", "demo-lib", "1.0"))[0]
        self.assertTrue(match.advisory.known_exploited)

    def test_from_osv_rejects_missing_id(self):
        with self.assertRaises(ValueError):
            Advisory.from_osv({"summary": "no id"})

    def test_malformed_records_counted_not_fatal(self):
        db = AdvisoryDatabase.from_records([{"no": "id"}, _osv("GHSA-ok", "x", "0", "1.0")])
        self.assertEqual(len(db), 1)
        self.assertEqual(db.skipped_records, 1)

    def test_git_ranges_are_skipped(self):
        record = {"id": "GHSA-git", "aliases": [], "summary": "x",
                  "affected": [{"package": {"ecosystem": "PyPI", "name": "p"},
                                "ranges": [{"type": "GIT",
                                            "events": [{"introduced": "0"}]}]}]}
        db = AdvisoryDatabase.from_records([record])
        self.assertEqual(db.match(Component("PyPI", "p", "1.0")), [])


if __name__ == "__main__":
    unittest.main()
