"""Nederlandstalige synthese van ruwe GitHub-export voor scope-review."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
from test_scope_issue_github_rest_import_20261015 import fixture
from scope_issue_github_rest_report_20261015 import render
from scope_issue_ownership_audit_20261015 import InvalidSnapshot


def show(document):
    return render(json.dumps(document).encode("utf-8"))


class GitHubRestReportTests(unittest.TestCase):
    def test_complete_synthetic_export_warns_about_source(self):
        text = show(fixture())
        self.assertIn("niet geauthenticeerde", text)
        self.assertIn("De actuele GitHub-/Notion-eigenaar", text)

    def test_rename_collision_group(self):
        text = show(fixture())
        self.assertIn("Conflictgroep 1: PR #201, #202", text)
        self.assertIn("src/old.py", text)

    def test_incomplete_pr_pages_prominent_warning(self):
        doc = fixture()
        doc["pr_pages"][0]["has_next"] = True
        self.assertIn("WAARSCHUWING: export is aantoonbaar onvolledig", show(doc))

    def test_missing_file_pages_prominent_warning(self):
        doc = fixture()
        doc["file_pages"].pop()
        self.assertIn("WAARSCHUWING: export is aantoonbaar onvolledig", show(doc))

    def test_missing_claim_is_visible_without_owner_assertion(self):
        doc = fixture()
        doc["claims"].pop()
        text = show(doc)
        self.assertIn("PR #202: claim niet aangeleverd", text)
        self.assertIn("geen conclusie over beschikbaarheid", text)

    def test_fork_is_review_only(self):
        doc = fixture()
        doc["pr_pages"][0]["records"][0]["head"]["repo"]["full_name"] = "Another/Repo"
        text = show(doc)
        self.assertIn("Fork-PR's vereisen aparte eigenaarscontrole", text)
        self.assertIn("niet automatisch overnemen", text)

    def test_no_collision_never_claims_free_issues(self):
        doc = fixture()
        doc["file_pages"][0]["records"][0] = {
            "filename": "src/new.py", "status": "modified"}
        text = show(doc)
        self.assertIn("Dit betekent **niet**", text)
        self.assertIn("Geen scan, echte operatorgrant", text)

    def test_dangerous_html_filename_is_escaped(self):
        doc = fixture()
        doc["file_pages"][0]["records"][0]["previous_filename"] = "src/<script>.py"
        doc["file_pages"][1]["records"][0]["filename"] = "src/<script>.py"
        text = show(doc)
        self.assertIn("Conflictgroep 1", text)
        self.assertNotIn("<script>", text)

    def test_markdown_escaping_on_untrusted_file(self):
        doc = fixture()
        doc["file_pages"][0]["records"][0]["previous_filename"] = "src/a`|b.py"
        doc["file_pages"][1]["records"][0]["filename"] = "src/a`|b.py"
        text = show(doc)
        self.assertNotIn("a`|b.py", text)

    def test_bad_snapshot_rejected(self):
        with self.assertRaises(InvalidSnapshot):
            render(b'{"fake_secret":"not-real"}')

    def test_valid_cli_returns_two_hold(self):
        script = ROOT / "scripts" / "scope_issue_github_rest_report_20261015.py"
        p = subprocess.run([sys.executable, str(script)], input=json.dumps(fixture()).encode(),
                           capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertIn("**Status: HOLD", p.stdout.decode("utf-8"))
        self.assertNotIn(b"Traceback", p.stderr)

    def test_invalid_cli_redacts_input(self):
        script = ROOT / "scripts" / "scope_issue_github_rest_report_20261015.py"
        p = subprocess.run([sys.executable, str(script)],
                           input=b'{"fake_secret":"MY_FAKE_CLIENT"}',
                           capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(b"MY_FAKE_CLIENT", p.stdout)
        self.assertIn(b"HOLD", p.stdout)


if __name__ == "__main__":
    unittest.main()
