from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Finding, Severity
from lightup.prioritization import KNOWN_EXPLOITED_BONUS, prioritize, score_finding


def _finding(fid, severity, check_id, target="http://127.0.0.1/", **meta):
    meta["check_id"] = check_id
    return Finding(fid, f"title-{fid}", severity, target, remediation="fix", metadata=meta)


class ScoringTest(unittest.TestCase):
    def test_severity_drives_base_score(self):
        crit = score_finding(_finding("a", Severity.CRITICAL, "x"))
        low = score_finding(_finding("b", Severity.LOW, "y"))
        self.assertGreater(crit.score, low.score)

    def test_known_exploited_bonus(self):
        plain = score_finding(_finding("a", Severity.MEDIUM, "x"))
        kev = score_finding(_finding("b", Severity.MEDIUM, "x", known_exploited=True))
        self.assertEqual(kev.score - plain.score, KNOWN_EXPLOITED_BONUS)

    def test_fix_first_ordering_is_stable(self):
        findings = [
            _finding("low", Severity.LOW, "a"),
            _finding("critical", Severity.CRITICAL, "b"),
            _finding("medium-kev", Severity.MEDIUM, "c", known_exploited=True),
        ]
        order = [s.finding.finding_id for s in prioritize(findings).fix_first]
        self.assertEqual(order[0], "medium-kev")  # 12 + 30 = 42 beats critical's 40
        self.assertEqual(order[-1], "low")


class ChainDetectionTest(unittest.TestCase):
    def test_scm_plus_dotenv_chain(self):
        findings = [
            _finding("a", Severity.HIGH, "exposed-scm-metadata"),
            _finding("b", Severity.CRITICAL, "exposed-dotenv"),
        ]
        report = prioritize(findings)
        self.assertEqual([c.chain_id for c in report.chains], ["scm-plus-secret-disclosure"])
        self.assertEqual(report.chains[0].severity, Severity.CRITICAL)

    def test_chain_requires_all_members_on_same_asset(self):
        findings = [
            _finding("a", Severity.HIGH, "exposed-scm-metadata", target="http://h1/"),
            _finding("b", Severity.CRITICAL, "exposed-dotenv", target="http://h2/"),
        ]
        self.assertEqual(prioritize(findings).chains, [])

    def test_vuln_dependency_chain_requires_advisory_metadata(self):
        without = [_finding("a", Severity.MEDIUM, "stack-trace-disclosure")]
        self.assertEqual(prioritize(without).chains, [])
        with_dep = [
            _finding("a", Severity.MEDIUM, "stack-trace-disclosure"),
            Finding("b", "vuln", Severity.HIGH, "http://127.0.0.1/", remediation="x",
                    metadata={"check_id": "vulnerable-dependency:V-1", "advisory_id": "V-1"}),
        ]
        chains = prioritize(with_dep).chains
        self.assertIn("vuln-dependency-plus-stack-trace", [c.chain_id for c in chains])

    def test_no_findings_no_chains(self):
        report = prioritize([])
        self.assertEqual(report.chains, [])
        self.assertEqual(report.to_dict()["summary"]["total_findings"], 0)


if __name__ == "__main__":
    unittest.main()
