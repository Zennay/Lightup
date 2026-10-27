"""Full offline report stays non-authorizing and shows conflict groups."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_issue_ownership_triage_20261015 import triage
from scope_issue_ownership_audit_20261015 import InvalidSnapshot


def example():
    return {"issues": [
        {"number": 111, "open": True, "lane": "scope-authorization"},
        {"number": 112, "open": True, "lane": "scope-authorization"}],
        "prs": [
            {"number": 211, "open": True, "draft": True,
             "issues": [111], "paths": ["tests/one.py"]},
            {"number": 212, "open": True, "draft": True,
             "issues": [111], "paths": ["tests/two.py"]},
            {"number": 213, "open": True, "draft": True,
             "issues": [112], "paths": ["tests/two.py"]},
        ]}


def check(doc):
    return triage(json.dumps(doc).encode())


class OfflineTriageTests(unittest.TestCase):
    def test_joins_transitive_group(self):
        report = check(example())
        self.assertIn("Groep 1", report)
        self.assertIn("PR #211, #212, #213", report)

    def test_both_conflict_cause_types_visible(self):
        report = check(example())
        self.assertIn("Dubbele issueclaim: #111", report)
        self.assertIn("Exact gedeeld bestand: `tests/two.py`", report)

    def test_reports_non_authority(self):
        report = check(example())
        self.assertIn("HOLD", report)
        self.assertIn("Dekking: **onbevestigd**", report)
        self.assertIn("Geen toestemming om te scannen", report)

    def test_no_conflicts_does_not_mean_free(self):
        doc = example()
        doc["prs"] = doc["prs"][:1]
        report = check(doc)
        self.assertIn("actieve workers kunnen ontbreken", report)
        self.assertIn("geen vrije taken", report)

    def test_multiple_groups(self):
        doc = example()
        doc["issues"].append({"number": 113, "open": True, "lane": "scope-authorization"})
        doc["prs"].extend([
            {"number": 214, "open": True, "draft": False, "issues": [113], "paths": ["tests/three.py"]},
            {"number": 215, "open": True, "draft": False, "issues": [113], "paths": ["tests/four.py"]},
        ])
        report = check(doc)
        self.assertIn("Groep 1", report)
        self.assertIn("Groep 2", report)

    def test_markdown_escape_of_untrusted_path(self):
        doc = example()
        doc["prs"][1]["paths"] = ["tests/<script>.py"]
        doc["prs"][2]["paths"] = ["tests/<script>.py"]
        report = check(doc)
        self.assertNotIn("<script>", report)
        self.assertIn("tests/", report)

    def test_corrupt_json_is_rejected(self):
        with self.assertRaises(InvalidSnapshot):
            triage(b'{"issues":[],"prs":[],"prs":[]}')

    def test_cli_invalid_returns_private_hold(self):
        cmd = [sys.executable, str(ROOT / "scripts" / "scope_issue_ownership_triage_20261015.py")]
        p = subprocess.run(cmd, input=b'{"secret":"client-example"}', capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(b"client-example", p.stdout)
        self.assertIn(b"HOLD", p.stdout)
        self.assertNotIn(b"Traceback", p.stderr)

    def test_cli_valid_always_exits_two(self):
        cmd = [sys.executable, str(ROOT / "scripts" / "scope_issue_ownership_triage_20261015.py")]
        p = subprocess.run(cmd, input=json.dumps(example()).encode(), capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertIn(b"Groep 1", p.stdout)


if __name__ == "__main__":
    unittest.main()
