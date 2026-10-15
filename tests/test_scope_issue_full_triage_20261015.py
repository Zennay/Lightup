"""End-user Dutch report for offline, untrusted, rename-aware worker snapshots."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_issue_full_triage_20261015 import render_report
from scope_issue_ownership_audit_20261015 import InvalidSnapshot


def example():
    return {
        "snapshot": {
            "issues": [{"number": 111, "open": True, "lane": "scope-authorization"},
                       {"number": 112, "open": True, "lane": "scope-authorization"}],
            "prs": [
                {"number": 211, "open": True, "draft": True,
                 "issues": [111], "paths": ["src/new.py"]},
                {"number": 212, "open": True, "draft": True,
                 "issues": [112], "paths": ["src/old.py"]},
            ]},
        "pagination": {
            "issues": [{"page": 1, "numbers": [111, 112], "has_next": False}],
            "prs": [{"page": 1, "numbers": [211, 212], "has_next": False}],
        },
        "pr_file_pages": [
            {"pr": 211, "pages": [{"page": 1, "paths": ["src/new.py"], "has_next": False}]},
            {"pr": 212, "pages": [{"page": 1, "paths": ["src/old.py"], "has_next": False}]},
        ],
        "pr_change_pages": [
            {"pr": 211, "pages": [{"page": 1, "has_next": False,
                                  "changes": [{"filename": "src/new.py", "status": "renamed",
                                               "previous_filename": "src/old.py"}]}]},
            {"pr": 212, "pages": [{"page": 1, "has_next": False,
                                  "changes": [{"filename": "src/old.py", "status": "modified",
                                               "previous_filename": None}]}]},
        ],
    }


def checked(doc):
    return render_report(json.dumps(doc).encode())


class FullTriageTests(unittest.TestCase):
    def test_reports_indirect_rename_conflict(self):
        txt = checked(example())
        self.assertIn("PR #211, #212", txt)
        self.assertIn("src/old.py", txt)

    def test_report_always_warns_unverified_source(self):
        self.assertIn("niet geverifieerd", checked(example()))

    def test_disclaims_activation_and_merge(self):
        txt = checked(example())
        self.assertIn("Status: HOLD", txt)
        self.assertIn("Geen merge, deploy", txt)

    def test_no_conflict_cannot_mean_available(self):
        d = example()
        d["pr_change_pages"][0]["pages"][0]["changes"][0] = {
            "filename": "src/new.py", "status": "modified", "previous_filename": None}
        self.assertIn("Dit bewijst niet dat een issue", checked(d))

    def test_missing_file_page_triggers_big_warning(self):
        d = example()
        d["pr_file_pages"].pop()
        txt = checked(d)
        self.assertIn("niet alle PR-bestanden", txt)

    def test_missing_change_page_triggers_big_warning(self):
        d = example()
        d["pr_change_pages"].pop()
        self.assertIn("niet alle PR-bestanden", checked(d))

    def test_known_collision_survives_partial_export(self):
        d = example()
        d["pr_change_pages"][1]["pages"][0]["has_next"] = True
        txt = checked(d)
        self.assertIn("src/old.py", txt)
        self.assertIn("WAARSCHUWING", txt)

    def test_html_path_is_not_rendered_raw(self):
        d = example()
        d["snapshot"]["prs"][0]["paths"] = ["src/<b>new.py"]
        d["pr_file_pages"][0]["pages"][0]["paths"] = ["src/<b>new.py"]
        d["pr_change_pages"][0]["pages"][0]["changes"][0]["filename"] = "src/<b>new.py"
        self.assertNotIn("<b>", checked(d))

    def test_invalid_receipt_rejected(self):
        with self.assertRaises(InvalidSnapshot):
            render_report(b'{"scope":"someone else"}')

    def test_cli_valid_exits_hold(self):
        script = ROOT / "scripts" / "scope_issue_full_triage_20261015.py"
        p = subprocess.run([sys.executable, str(script)],
                           input=json.dumps(example()).encode(), capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertIn("Status: HOLD", p.stdout.decode())
        self.assertIn("src/old.py", p.stdout.decode())

    def test_cli_invalid_is_generic(self):
        script = ROOT / "scripts" / "scope_issue_full_triage_20261015.py"
        p = subprocess.run([sys.executable, str(script)],
                           input=b'{"secret":"fake-client-private"}', capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(b"fake-client-private", p.stdout)
        self.assertNotIn(b"Traceback", p.stderr)


if __name__ == "__main__":
    unittest.main()
