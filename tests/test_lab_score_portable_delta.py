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

    def test_atomic_five_file_human_comparison_pub_and_read_only_verify(self):
        import hashlib
        from lightup.lab_score_review_delta import verify_private_comparison
        directory=self.root/'source-free-comparison-room'
        code,out,err=run('--compare-portable-reviews',self.hold,self.passing,
                         '--comparison-output-dir',directory)
        self.assertEqual((code,err),(2,''))
        self.assertIn('five private files saved',out)
        expected={'comparison.json','comparison.txt','comparison.csv',
                  'comparison.html','manifest.json'}
        self.assertEqual({p.name for p in directory.iterdir()},expected)
        self.assertEqual(directory.stat().st_mode&0o777,0o700)
        self.assertTrue(all(p.stat().st_mode&0o777==0o600
                            for p in directory.iterdir()))
        stored={p.name:p.read_bytes() for p in directory.iterdir()}
        manifest=json.loads(stored['manifest.json'])
        self.assertEqual(set(manifest['file_sha256']),expected-{'manifest.json'})
        for name,digest in manifest['file_sha256'].items():
            self.assertEqual(hashlib.sha256(stored[name]).hexdigest(),digest)
        self.assertFalse(manifest['authorization_granted'])
        self.assertFalse(manifest['remediation_verified'])
        code,out,err=run('--verify-comparison-workroom',self.hold,self.passing,
                         '--comparison-output-dir',directory)
        self.assertEqual((code,err),(2,''))
        self.assertIn('five saved files reverified',out)
        self.assertEqual(verify_private_comparison(self.hold,self.passing,directory)
                         ['review_status'],'HOLD')
        self.assertEqual(stored,{p.name:p.read_bytes() for p in directory.iterdir()})
        code,out,err=run('--compare-portable-reviews',self.hold,self.passing,
                         '--comparison-output-dir',directory)
        self.assertEqual((code,out),(2,''))
        self.assertIn('not verified',err)
        (directory/'comparison.html').write_text('tampered')
        code,out,err=run('--verify-comparison-workroom',self.hold,self.passing,
                         '--comparison-output-dir',directory)
        self.assertEqual((code,out),(2,''))
        self.assertIn('not verified',err)

    def test_reject_bad_originals_without_creating_a_private_comparison_room(self):
        dest=self.root/'must-not-be-created'
        code,out,err=run('--compare-portable-reviews',self.hold,self.hold,
                         '--comparison-output-dir',dest)
        self.assertEqual((code,out),(2,''))
        self.assertIn('not verified',err)
        self.assertFalse(dest.exists())
