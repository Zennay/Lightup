"""Offline language/report contract; no live effects or real-target fixtures."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_release_dependency_inventory_20261015 import GATES
from scope_release_dependency_nl_20261015 import EXPLANATIONS, summarize

SCRIPT = ROOT / "scripts" / "scope_release_dependency_nl_20261015.py"


def packet(status="MISSING"):
    return json.dumps({"schema": 1, "checks": {x: status for x in GATES}}).encode()


class ReleaseSummaryTests(unittest.TestCase):
    def run_cli(self, raw):
        proc = subprocess.run([sys.executable, str(SCRIPT)], input=raw, capture_output=True, timeout=5)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, b"")
        self.assertNotIn(b"# LightUp scope-vrijgave: TOEGESTAAN", proc.stdout)
        return proc.stdout.decode("utf-8")

    def test_empty_and_complete_are_both_hold(self):
        for payload in [packet(), packet("SELF_REPORTED")]:
            report = self.run_cli(payload)
            self.assertIn("Vrijgave: NEE", report)
            self.assertIn("NIET TOEGESTAAN", report)

    def test_self_reports_never_hide_independent_checks(self):
        report = summarize(packet("SELF_REPORTED"))
        self.assertIn("9 van 9", report)
        for _, (label, _) in EXPLANATIONS.items():
            self.assertIn(label, report)

    def test_exact_nine_owned_gates(self):
        self.assertEqual(set(EXPLANATIONS), set(GATES))
        self.assertEqual(len(EXPLANATIONS), 9)

    def test_output_does_not_reveal_extra_claim(self):
        secret = "FAKE_PRIVATE_APPROVAL_REFERENCE_12345"
        payload = json.dumps({"schema":1,"checks":{x:"MISSING" for x in GATES},"secret":secret}).encode()
        output = self.run_cli(payload)
        self.assertNotIn(secret, output)
        self.assertIn("ongeldig of onvolledig", output)

    def test_malformed_all_same_generic_report(self):
        baseline = self.run_cli(b"bad")
        for payload in [b"", b"null", b"[]", b"\xff", b"{" + b" "*8500]:
            self.assertEqual(self.run_cli(payload), baseline)

    def test_order_does_not_depend_on_input(self):
        data = {x:"BLOCKED" for x in reversed(GATES)}
        obj = json.dumps({"schema":1,"checks":data}).encode()
        self.assertEqual(self.run_cli(obj), self.run_cli(packet("BLOCKED")))

    def test_no_raw_json_or_original_hostnames(self):
        report = self.run_cli(packet())
        self.assertNotIn('"schema"', report)
        self.assertNotIn('"checks"', report)
        self.assertNotIn("127.0.0.1", report)

    def test_no_possible_positive_review_wording(self):
        report = self.run_cli(packet("SELF_REPORTED"))
        self.assertNotIn("vrijgegeven", report.lower())
        self.assertNotIn("goedgekeurd", report.lower())
        self.assertIn("geen verifieerbaar bewijs", report)


if __name__ == "__main__":
    unittest.main()
