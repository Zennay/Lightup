"""Dutch pinned-snapshot triage MUST remain legible, safe, and HOLD-only."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_issue_pinned_triage_20261015 import render_pinned
from scope_issue_ownership_audit_20261015 import InvalidSnapshot

SHA = "b" * 40
OTHER = "c" * 40


def packet():
    return {
        "snapshot": {
            "issues": [{"number": 101, "open": True, "lane": "scope-authorization"}],
            "prs": [
                {"number": 201, "open": True, "draft": True, "issues": [101],
                 "paths": ["docs/new.md"]},
                {"number": 202, "open": True, "draft": True, "issues": [101],
                 "paths": ["docs/old.md"]},
            ],
        },
        "pagination": {
            "issues": [{"page": 1, "numbers": [101], "has_next": False}],
            "prs": [{"page": 1, "numbers": [201, 202], "has_next": False}],
        },
        "pr_file_pages": [
            {"pr": 201, "pages": [{"page": 1, "paths": ["docs/new.md"], "has_next": False}]},
            {"pr": 202, "pages": [{"page": 1, "paths": ["docs/old.md"], "has_next": False}]},
        ],
        "pr_change_pages": [
            {"pr": 201, "pages": [{"page": 1, "has_next": False, "changes": [
                {"filename": "docs/new.md", "status": "renamed",
                 "previous_filename": "docs/old.md"}]}]},
            {"pr": 202, "pages": [{"page": 1, "has_next": False, "changes": [
                {"filename": "docs/old.md", "status": "modified",
                 "previous_filename": None}]}]},
        ],
        "pr_head_receipts": [
            {"pr": 201, "start_head": SHA, "file_page_heads": [SHA],
             "change_page_heads": [SHA], "end_head": SHA},
            {"pr": 202, "start_head": OTHER, "file_page_heads": [OTHER],
             "change_page_heads": [OTHER], "end_head": OTHER},
        ],
    }


def check(doc):
    return render_pinned(json.dumps(doc).encode("utf-8"))


class PinnedTriageTests(unittest.TestCase):
    def test_renders_transitive_rename_group_for_consistent_heads(self):
        s = check(packet())
        self.assertIn("Groep 1: PR #201, #202", s)
        self.assertIn("docs/old.md", s)

    def test_shows_duplicate_issue(self):
        self.assertIn("Dubbele claim op issue #101", check(packet()))

    def test_warns_source_not_verified(self):
        self.assertIn("niet** geverifieerd", check(packet()))

    def test_contains_unconditional_no_grant_disclaimer(self):
        s = check(packet())
        self.assertIn("HOLD", s)
        self.assertIn("Geen scan, runtimegrant, merge, deployment", s)

    def test_changed_end_head_suppresses_conflict_group(self):
        d = packet()
        d["pr_head_receipts"][0]["end_head"] = OTHER
        s = check(d)
        self.assertIn("versie veranderd", s)
        self.assertIn("Geen betrouwbare conflictgroeplijst", s)
        self.assertNotIn("Groep 1:", s)

    def test_mixed_file_page_suppresses_conflict_group(self):
        d = packet()
        d["pr_head_receipts"][0]["file_page_heads"] = [OTHER]
        self.assertNotIn("Groep 1:", check(d))

    def test_missing_pr_head_evidence_warns_and_suppresses(self):
        d = packet()
        d["pr_head_receipts"].pop()
        s = check(d)
        self.assertIn("geen commitversie vastgelegd", s)
        self.assertIn("Geen betrouwbare conflictgroeplijst", s)

    def test_missing_pr_file_evidence_suppresses(self):
        d = packet()
        d["pr_file_pages"].pop()
        self.assertIn("Geen betrouwbare conflictgroeplijst", check(d))

    def test_no_observed_conflicts_is_not_free(self):
        d = packet()
        d["snapshot"]["prs"][1]["issues"] = []
        d["pr_change_pages"][0]["pages"][0]["changes"][0] = {
            "filename": "docs/new.md", "status": "modified",
            "previous_filename": None}
        s = check(d)
        self.assertIn("Dit bewijst niet", s)
        self.assertNotIn("Groep 1:", s)

    def test_html_like_path_never_renders_active_html(self):
        d = packet()
        d["snapshot"]["prs"][1]["paths"] = ["docs/<script>.md"]
        d["pr_file_pages"][1]["pages"][0]["paths"] = ["docs/<script>.md"]
        d["pr_change_pages"][1]["pages"][0]["changes"][0]["filename"] = "docs/<script>.md"
        d["pr_change_pages"][0]["pages"][0]["changes"][0]["previous_filename"] = "docs/<script>.md"
        self.assertNotIn("<script>", check(d))

    def test_invalid_json_rejected(self):
        with self.assertRaises(InvalidSnapshot):
            render_pinned(b'{"secret":"private"}')

    def test_good_cli_always_returns_hold_exit_two(self):
        script = ROOT / "scripts" / "scope_issue_pinned_triage_20261015.py"
        p = subprocess.run([sys.executable, str(script)],
                           input=json.dumps(packet()).encode(), capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertIn("**HOLD", p.stdout.decode("utf-8"))
        self.assertNotIn(b"Traceback", p.stderr)

    def test_bad_cli_no_private_data_echo(self):
        script = ROOT / "scripts" / "scope_issue_pinned_triage_20261015.py"
        p = subprocess.run([sys.executable, str(script)],
                           input=b'{"private_tenant":"not_real_example"}',
                           capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(b"not_real_example", p.stdout)
        self.assertIn(b"HOLD", p.stdout)
        self.assertNotIn(b"Traceback", p.stderr)


if __name__ == "__main__":
    unittest.main()
