"""Two admitted synthetic ZIPs; human-only delta, never automatic remediation."""
from __future__ import annotations
import csv
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from lightup import lab_score_calibration as app
from lightup.lab_score_portable_html_safety import admit_inert_html


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        status = app.main([str(x) for x in args])
    return status, out.getvalue(), err.getvalue()


class TwoTransportHumanComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        a,b,c,d = (cls.root/x for x in ('a','b','c','d'))
        for source in (a,b,c):
            if not app.run_lab_score_calibration(source)['passed']:
                raise AssertionError('synthetic source failed')
        shutil.copytree(a,d)
        hroom,hzip = cls.root/'hold-room',cls.root/'hold-zip'
        proom,pzip = cls.root/'pass-room',cls.root/'pass-zip'
        assert run('--compare-history',a,b,c,d,'--format','html',
                   '--html-output-dir',hroom)[0]==2
        assert run('--compare-history',a,b,c,d,'--format','html',
                   '--verify-html-output-dir',hroom,
                   '--portable-review-output-dir',hzip)[0]==2
        assert run('--compare-history',b,c,'--format','html',
                   '--html-output-dir',proom)[0]==0
        assert run('--compare-history',b,c,'--format','html',
                   '--verify-html-output-dir',proom,
                   '--portable-review-output-dir',pzip)[0]==0
        cls.hold=hzip/'LightUp-SYNTHETIC-OFFLINE-REVIEW.zip'
        cls.passing=pzip/'LightUp-SYNTHETIC-OFFLINE-REVIEW.zip'

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_count_delta_never_closes_old_hold(self):
        status,out,err=run('--compare-portable-reviews',
                           self.hold,self.passing,'--format','json')
        self.assertEqual((status,err),(2,''))
        item=json.loads(out)
        self.assertEqual(item['review_status'],'HOLD')
        self.assertTrue(item['baseline_hold_preserved'])
        self.assertEqual(item['baseline']['original_archives'],4)
        self.assertEqual(item['candidate']['original_archives'],2)
        self.assertEqual(item['baseline']['hold_pairs'],1)
        self.assertEqual(item['candidate']['hold_pairs'],0)
        self.assertEqual(item['count_change_candidate_minus_baseline']['hold_pairs'],-1)
        self.assertEqual(item['count_change_candidate_minus_baseline']['original_pairs'],-5)
        for k in ('original_source_authenticated','same_originals_proven',
                  'remediation_verified','authorization_granted',
                  'external_targets_contacted','deployment'):
            self.assertIs(item[k],False)
        self.assertNotIn(str(self.root),out)

    def test_outputs_safe_inert_and_source_free(self):
        for fmt in ('text','csv','html'):
            with self.subTest(fmt=fmt):
                status,out,err=run('--compare-portable-reviews',
                                   self.hold,self.passing,'--format',fmt)
                self.assertEqual((status,err),(2,''))
                self.assertNotIn(str(self.root),out)
                if fmt=='html':
                    admit_inert_html(out.encode())
                    self.assertIn('GLOBAL STATUS HOLD',out)
                    self.assertNotIn('<script',out)
                if fmt=='csv':
                    rows=list(csv.DictReader(io.StringIO(out)))
                    self.assertEqual(len(rows),5)
                    self.assertTrue(all(row['authorization_granted']=='false'
                                        and row['remediation_verified']=='false'
                                        for row in rows))
                if fmt=='text':
                    self.assertIn('Original HOLD preserved',out)

    def test_invalid_or_same_source_no_partial_output(self):
        for a,b in ((self.hold,self.hold),
                    (self.root/'missing.zip',self.passing)):
            status,out,err=run('--compare-portable-reviews',
                               a,b,'--format','json')
            self.assertEqual((status,out),(2,''))
            self.assertIn('not verified',err)
