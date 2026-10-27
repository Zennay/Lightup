"""Pure offline ownership-audit contracts. No GitHub API or live targets."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from scope_issue_ownership_audit_20261015 import InvalidSnapshot, audit


def base():
    return {'issues': [
        {'number': 101, 'open': True, 'lane': 'scope-authorization'},
        {'number': 102, 'open': True, 'lane': 'scope-authorization'},
        {'number': 103, 'open': False, 'lane': 'scope-authorization'}],
        'prs': [{'number': 201, 'open': True, 'draft': True, 'issues': [101],
                 'paths': ['tests/a.py', 'docs/a.md']}]}


def run(doc):
    return audit(json.dumps(doc).encode('utf-8'))


class OfflineScopeOwnershipTests(unittest.TestCase):
    def test_unclaimed_and_claimed(self):
        result = run(base())
        self.assertEqual(result['unclaimed_open_issues'], [102])
        self.assertEqual(result['claimed_open_issues'], [101])
        self.assertEqual(result['open_draft_prs'], [201])

    def test_every_permission_flag_false(self):
        result = run(base())
        self.assertEqual(result['status'], 'HOLD')
        self.assertFalse(any(result[field] for field in (
            'can_authorize', 'can_scan', 'can_merge', 'can_deploy', 'can_release')))

    def test_duplicate_issue_claims(self):
        doc = base()
        doc['prs'].append({'number': 202, 'open': True, 'draft': True,
                           'issues': [101], 'paths': ['tests/b.py']})
        self.assertEqual(run(doc)['duplicate_issue_claims'], [{'issue': 101, 'prs': [201, 202]}])

    def test_same_file_collisions(self):
        doc = base()
        doc['prs'].append({'number': 202, 'open': True, 'draft': False,
                           'issues': [102], 'paths': ['tests/a.py']})
        self.assertEqual(run(doc)['exact_path_collisions'], [{'path': 'tests/a.py', 'prs': [201, 202]}])

    def test_closed_prs_claim_nothing(self):
        doc = base()
        doc['prs'][0]['open'] = False
        self.assertEqual(run(doc)['unclaimed_open_issues'], [101, 102])

    def test_closed_issue_claim_remains_suspicious(self):
        doc = base()
        doc['prs'][0]['issues'] = [103]
        self.assertEqual(run(doc)['unknown_or_closed_issue_claims'], [{'issue': 103, 'prs': [201]}])

    def test_unlisted_issue_claim_remains_suspicious(self):
        doc = base()
        doc['prs'][0]['issues'] = [999]
        self.assertEqual(run(doc)['unknown_or_closed_issue_claims'], [{'issue': 999, 'prs': [201]}])

    def test_duplicate_json_keys_denied(self):
        with self.assertRaises(InvalidSnapshot):
            audit(b'{"issues":[],"issues":[],"prs":[]}')

    def test_non_utf8_denied(self):
        with self.assertRaises(InvalidSnapshot):
            audit(b'\xff')

    def test_oversized_denied(self):
        with self.assertRaises(InvalidSnapshot):
            audit(b' ' * (512 * 1024 + 1))

    def test_boolean_number_confusion_denied(self):
        doc = base()
        doc['prs'][0]['number'] = True
        with self.assertRaises(InvalidSnapshot):
            run(doc)

    def test_nonboolean_status_denied(self):
        doc = base()
        doc['issues'][0]['open'] = 1
        with self.assertRaises(InvalidSnapshot):
            run(doc)

    def test_cross_lane_issue_denied(self):
        doc = base()
        doc['issues'][0]['lane'] = 'evidence-remediation'
        with self.assertRaises(InvalidSnapshot):
            run(doc)

    def test_unsafe_path_denied(self):
        for bad in ('../secret', '/absolute', 'tests//a.py', 'tests/./a.py',
                    '.git/config', 'tests\\a.py', 'tests/../a.py', ''):
            with self.subTest(bad=bad):
                doc = base()
                doc['prs'][0]['paths'] = [bad]
                with self.assertRaises(InvalidSnapshot):
                    run(doc)

    def test_duplicate_issue_denied(self):
        doc = base()
        doc['issues'].append(doc['issues'][0].copy())
        with self.assertRaises(InvalidSnapshot):
            run(doc)

    def test_duplicate_path_denied(self):
        doc = base()
        doc['prs'][0]['paths'] = ['tests/a.py', 'tests/a.py']
        with self.assertRaises(InvalidSnapshot):
            run(doc)

    def test_unknown_fields_denied(self):
        doc = base()
        doc['prs'][0]['release'] = True
        with self.assertRaises(InvalidSnapshot):
            run(doc)

    def test_cli_outputs_generic_hold(self):
        path = ROOT / 'scripts' / 'scope_issue_ownership_audit_20261015.py'
        process = subprocess.run([sys.executable, str(path)], input=b'{invalid',
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(process.returncode, 2)
        result = json.loads(process.stdout)
        self.assertEqual(result['status'], 'HOLD')
        self.assertFalse(result['can_release'])
        self.assertNotIn('Traceback', process.stderr.decode())

    def test_cli_on_good_input_still_hold(self):
        path = ROOT / 'scripts' / 'scope_issue_ownership_audit_20261015.py'
        process = subprocess.run([sys.executable, str(path)], input=json.dumps(base()).encode(),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(json.loads(process.stdout)['unclaimed_open_issues'], [102])


if __name__ == '__main__':
    unittest.main()
