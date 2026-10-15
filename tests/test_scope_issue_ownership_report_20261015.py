import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from scope_issue_ownership_audit_20261015 import audit
from scope_issue_ownership_report_20261015 import render


class OfflineScopeOwnershipReportTests(unittest.TestCase):
    def fixture(self, path='tests/a.py'):
        return {'issues': [
            {'number': 12, 'open': True, 'lane': 'scope-authorization'},
            {'number': 14, 'open': True, 'lane': 'scope-authorization'},
        ], 'prs': [
            {'number': 30, 'open': True, 'draft': True, 'issues': [12], 'paths': [path]},
            {'number': 31, 'open': True, 'draft': True, 'issues': [12], 'paths': [path]},
        ]}

    def test_shows_unclaimed_issue(self):
        report = render(audit(json.dumps(self.fixture()).encode()))
        self.assertIn('Issue #14', report)

    def test_shows_double_claim(self):
        report = render(audit(json.dumps(self.fixture()).encode()))
        self.assertIn('Issue #12 claimt PR #30, #31', report)

    def test_shows_path_conflict(self):
        report = render(audit(json.dumps(self.fixture()).encode()))
        self.assertIn('tests/a.py', report)
        self.assertIn('PR #30, #31', report)

    def test_never_claims_permission(self):
        report = render(audit(json.dumps(self.fixture()).encode()))
        self.assertIn('Status: HOLD', report)
        self.assertIn('Geen uitvoerings-', report)

    def test_untrusted_pass_is_refused(self):
        valid = audit(json.dumps(self.fixture()).encode())
        valid['can_release'] = True
        with self.assertRaises(ValueError):
            render(valid)

    def test_markdown_control_characters_escaped(self):
        report = render(audit(json.dumps(self.fixture('tests/a`|<script>.py')).encode()))
        self.assertNotIn('<script>', report)
        self.assertNotIn('a`|', report)

    def test_missing_key_denied(self):
        with self.assertRaises(KeyError):
            render({'status': 'HOLD', **dict.fromkeys((
                'can_authorize', 'can_scan', 'can_merge', 'can_deploy', 'can_release'), False)})

    def test_cli_bad_json_holds_privately(self):
        script = ROOT / 'scripts' / 'scope_issue_ownership_report_20261015.py'
        process = subprocess.run([sys.executable, str(script)], input=b'not json',
                                 capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 2)
        self.assertIn('**HOLD', process.stdout.decode())
        self.assertNotIn('Traceback', process.stderr.decode())

    def test_cli_good_json_still_returns_hold(self):
        script = ROOT / 'scripts' / 'scope_issue_ownership_report_20261015.py'
        process = subprocess.run([sys.executable, str(script)],
                                 input=json.dumps(self.fixture()).encode(),
                                 capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 2)
        self.assertIn('Issue #14', process.stdout.decode())


if __name__ == '__main__':
    unittest.main()
