"""Two admitted synthetic ZIPs; human-only delta, never automatic remediation."""
from __future__ import annotations
import gc
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
    # Keep warnings from previously discarded test DBs outside CLI stderr capture.
    gc.collect()
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

    def test_source_local_human_hold_focus_direct_saved_and_fail_closed(self):
        from lightup.lab_score_review_delta import compare_portable_review_transports
        from lightup.lab_score_review_actions import build_review_actions
        from lightup.lab_score_portable_html_safety import admit_inert_html
        comparison = compare_portable_review_transports(str(self.hold), str(self.passing))
        actions = build_review_actions(comparison, str(self.hold), str(self.passing))
        row = next(a for a in actions["actions"][:-1] if a["transport"] == "baseline")
        selector = ("baseline", str(row["anonymous_previous"]),
                    str(row["anonymous_current"]))
        room = self.root / "source-local-focus-room"
        status, out, err = run("--compare-portable-reviews", self.hold,
                               self.passing, "--comparison-output-dir", room,
                               "--include-actions", "--include-briefs")
        self.assertEqual((status, err), (2, ""))
        before = {p.name: p.read_bytes() for p in room.iterdir()}
        for fmt in ("actions-focus-json", "actions-focus-text", "actions-focus-html"):
            direct = run("--compare-portable-reviews", self.hold, self.passing,
                         "--format", fmt, "--focus-action", *selector)
            saved = run("--verify-comparison-workroom", self.hold, self.passing,
                        "--comparison-output-dir", room, "--export-comparison",
                        "--format", fmt, "--focus-action", *selector)
            self.assertEqual(direct, saved)
            self.assertEqual((direct[0], direct[2]), (2, ""))
            self.assertIn("HOLD", direct[1])
            self.assertNotIn(str(self.root), direct[1])
            if fmt.endswith("json"):
                data = json.loads(direct[1])
                self.assertTrue(data["other_original_pairs_hidden"])
                self.assertFalse(data["authorization_granted"])
                self.assertFalse(data["remediation_verified"])
                self.assertEqual(data["source"], "baseline")
            if fmt.endswith("html"):
                admit_inert_html(direct[1].encode())
        self.assertEqual(before, {p.name: p.read_bytes() for p in room.iterdir()})
        for invalid in (("candidate", *selector[1:]),
                        ("baseline", "01", selector[2]),
                        ("baseline", "1", "1"),
                        ("baseline", "-1", "2")):
            status, out, err = run("--compare-portable-reviews", self.hold,
                                   self.passing, "--format", "actions-focus-json",
                                   "--focus-action", *invalid)
            self.assertEqual((status, out), (2, ""))
            self.assertIn("not verified", err)
        (room / "actions.csv").write_text("tampered unrelated saved HUMAN row")
        status, out, err = run("--verify-comparison-workroom", self.hold, self.passing,
                               "--comparison-output-dir", room, "--export-comparison",
                               "--format", "actions-focus-json", "--focus-action", *selector)
        self.assertEqual((status, out), (2, ""))
        self.assertIn("not verified", err)

    def test_private_source_local_focus_room_publish_verify_and_tamper(self):
        import stat
        from lightup.lab_score_review_delta import compare_portable_review_transports
        from lightup.lab_score_review_actions import build_review_actions
        room = self.root / "four-file-focus"
        actions = build_review_actions(
            compare_portable_review_transports(str(self.hold), str(self.passing)),
            str(self.hold), str(self.passing))
        row = next(x for x in actions["actions"][:-1] if x["transport"] == "baseline")
        pair = ("baseline", str(row["anonymous_previous"]), str(row["anonymous_current"]))
        opts = ["--focus-room-dir", room, "--focus-action", *pair]
        status, out, err = run("--publish-action-focus", self.hold, self.passing, *opts)
        self.assertEqual((status, err), (2, ""))
        self.assertIn("four private files verified", out)
        self.assertEqual(stat.S_IMODE(room.stat().st_mode), 0o700)
        originals = {p.name: p.read_bytes() for p in room.iterdir()}
        self.assertEqual(set(originals), {"focus.json", "focus.txt", "focus.html", "manifest.json"})
        for p in room.iterdir():
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        for fmt, filename in (("actions-focus-json", "focus.json"),
                              ("actions-focus-text", "focus.txt"),
                              ("actions-focus-html", "focus.html")):
            saved = run("--verify-action-focus", self.hold, self.passing,
                        *opts, "--format", fmt)
            direct = run("--compare-portable-reviews", self.hold, self.passing,
                         "--focus-action", *pair, "--format", fmt)
            self.assertEqual(saved, direct)
            self.assertEqual((saved[0], saved[2]), (2, ""))
            self.assertEqual(saved[1].encode(), originals[filename])
        self.assertEqual(originals, {p.name: p.read_bytes() for p in room.iterdir()})
        status, out, err = run("--publish-action-focus", self.hold, self.passing, *opts)
        self.assertEqual((status, out), (2, ""))
        (room / "focus.txt").write_text("forged APPROVED")
        for fmt in ("actions-focus-json", "actions-focus-html"):
            status, out, err = run("--verify-action-focus", self.hold, self.passing,
                                   *opts, "--format", fmt)
            self.assertEqual((status, out), (2, ""))
            self.assertIn("not verified", err)
            self.assertNotIn("APPROVED", err)

    def test_private_source_local_focus_rejects_invalid_pair_without_writes(self):
        room = self.root / "invalid-focus"
        for pair in (("candidate", "1", "4"), ("baseline", "01", "4"),
                     ("baseline", "1", "1"), ("baseline", "1", "9")):
            status, out, err = run("--publish-action-focus", self.hold, self.passing,
                                   "--focus-room-dir", room, "--focus-action", *pair)
            self.assertEqual((status, out), (2, ""))
            self.assertFalse(room.exists())
            self.assertIn("not verified", err)

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

    def test_verified_five_file_workroom_reexports_all_original_outputs(self):
        """Source ZIPs -> private room -> four byte-exact recipient views."""
        from lightup.lab_score_portable_html_safety import admit_inert_html
        room=self.root/'immutable-private-four-views'
        code,out,err=run('--compare-portable-reviews',self.hold,self.passing,
                         '--comparison-output-dir',room)
        self.assertEqual((code,err),(2,''))
        original={p.name:p.read_bytes() for p in room.iterdir()}
        for fmt,name in (('text','comparison.txt'),('json','comparison.json'),
                         ('csv','comparison.csv'),('html','comparison.html')):
            with self.subTest(fmt=fmt):
                code,out,err=run('--verify-comparison-workroom',self.hold,self.passing,
                                 '--comparison-output-dir',room,
                                 '--export-comparison','--format',fmt)
                self.assertEqual((code,err),(2,''))
                self.assertEqual(out.encode('utf-8'),original[name])
                self.assertNotIn(str(self.root),out)
                if fmt=='html':
                    admit_inert_html(out.encode('utf-8'))
                    self.assertIn('GLOBAL STATUS HOLD',out)
                if fmt=='json':
                    receipt=json.loads(out)
                    self.assertEqual(receipt['review_status'],'HOLD')
                    self.assertFalse(receipt['authorization_granted'])
        self.assertEqual(original,{p.name:p.read_bytes() for p in room.iterdir()})
        (room/'comparison.txt').write_text('changed non-requested saved member')
        for fmt in ('text','json','csv','html'):
            with self.subTest(tamper=fmt):
                code,out,err=run('--verify-comparison-workroom',self.hold,self.passing,
                                 '--comparison-output-dir',room,
                                 '--export-comparison','--format',fmt)
                self.assertEqual((code,out),(2,''))
                self.assertIn('not verified',err)

    def test_saved_eight_file_action_roundtrip_and_fail_closed(self):
        room=self.root/'private-eight-actions'
        code,out,err=run('--compare-portable-reviews',self.hold,self.passing,
                         '--comparison-output-dir',room,'--include-actions')
        self.assertEqual((code,err),(2,''))
        self.assertIn('eight private files',out)
        saved={p.name:p.read_bytes() for p in room.iterdir()}
        self.assertEqual(len(saved),8)
        self.assertEqual(json.loads(saved['manifest.json'])['schema'],
            'lightup.lab-score-human-two-transport-workroom.v2')
        self.assertEqual(room.stat().st_mode&0o777,0o700)
        self.assertTrue(all(p.stat().st_mode&0o777==0o600 for p in room.iterdir()))
        for fmt,name in (('actions-json','actions.json'),('actions-csv','actions.csv'),
                         ('actions-html','actions.html'),('csv','comparison.csv')):
            code,out,err=run('--verify-comparison-workroom',self.hold,self.passing,
                             '--comparison-output-dir',room,'--export-comparison',
                             '--format',fmt)
            self.assertEqual((code,err),(2,''))
            self.assertEqual(out.encode(),saved[name])
        admit_inert_html(saved['actions.html'])
        self.assertEqual(json.loads(saved['actions.json'])['hold_action_rows'],1)
        self.assertEqual(saved,{p.name:p.read_bytes() for p in room.iterdir()})
        (room/'actions.csv').write_text('tampered non-requested file')
        for fmt in ('actions-json','json','html'):
            code,out,err=run('--verify-comparison-workroom',self.hold,self.passing,
                             '--comparison-output-dir',room,'--export-comparison',
                             '--format',fmt)
            self.assertEqual((code,out),(2,''))
            self.assertIn('not verified',err)

    def test_include_actions_requires_private_publish_dir(self):
        with self.assertRaises(SystemExit):
            run('--compare-portable-reviews',self.hold,self.passing,'--include-actions')
        with self.assertRaises(SystemExit):
            run('--verify-comparison-workroom',self.hold,self.passing,
                '--comparison-output-dir',self.root/'missing','--include-actions')

    def test_human_source_briefs_direct_saved_and_holding_original(self):
        room=self.root/'action-brief-room'
        code,out,err=run('--compare-portable-reviews',self.hold,self.passing,
                         '--comparison-output-dir',room,'--include-actions')
        self.assertEqual((code,err),(2,''))
        before={p.name:p.read_bytes() for p in room.iterdir()}
        for fmt in ('actions-brief-markdown','actions-brief-html'):
            direct=run('--compare-portable-reviews',self.hold,self.passing,
                       '--format',fmt)
            saved=run('--verify-comparison-workroom',self.hold,self.passing,
                      '--comparison-output-dir',room,'--export-comparison',
                      '--format',fmt)
            self.assertEqual(direct,saved)
            self.assertEqual((direct[0],direct[2]),(2,''))
            self.assertIn('NOT_VERIFIED',direct[1])
            self.assertIn('GLOBAL STATUS HOLD',direct[1])
            self.assertIn('Baseline',direct[1])
            self.assertIn('Candidate',direct[1])
            self.assertNotIn(str(self.root),direct[1])
            if fmt.endswith('html'):
                admit_inert_html(direct[1].encode())
                for dest in ('baseline','candidate','independent'):
                    self.assertIn("id='"+dest+"'",direct[1])
            else:
                self.assertIn('Anonymous pair',direct[1])
                self.assertIn('- [ ]',direct[1])
        self.assertEqual(before,{p.name:p.read_bytes() for p in room.iterdir()})
        (room/'actions.csv').write_text('forged approval not selected')
        for fmt in ('actions-brief-markdown','actions-brief-html'):
            status,output,error=run('--verify-comparison-workroom',
                    self.hold,self.passing,'--comparison-output-dir',room,
                    '--export-comparison','--format',fmt)
            self.assertEqual((status,output),(2,''))
            self.assertIn('not verified',error)

    def test_human_brief_refuses_untrusted_actions_before_render(self):
        from lightup.lab_score_action_brief import render_action_brief
        from lightup.lab_score_review_delta import compare_portable_review_transports
        from lightup.lab_score_review_actions import build_review_actions
        data=build_review_actions(
            compare_portable_review_transports(str(self.hold),str(self.passing)),
            str(self.hold),str(self.passing))
        for fmt in ('actions-brief-markdown','actions-brief-html'):
            with self.subTest(fmt=fmt):
                changed=json.loads(json.dumps(data))
                changed['actions'][-1]['completion']='APPROVED'
                with self.assertRaises(ValueError):
                    render_action_brief(changed,fmt)
                changed=json.loads(json.dumps(data))
                changed['actions'][0]['anonymous_previous']='=<script>'
                with self.assertRaises(ValueError):
                    render_action_brief(changed,fmt)

    def test_original_human_brief_refuses_forged_reordered_or_duplicate_reviewer_actions(self):
        from copy import deepcopy
        from lightup.lab_score_action_brief import render_action_brief
        from lightup.lab_score_review_delta import compare_portable_review_transports
        from lightup.lab_score_review_actions import build_review_actions
        canonical=build_review_actions(
            compare_portable_review_transports(str(self.hold),str(self.passing)),
            str(self.hold),str(self.passing))
        forged=[]
        changed=deepcopy(canonical)
        changed['actions'].insert(1,deepcopy(changed['actions'][0]))
        changed['hold_action_rows']+=1
        forged.append(('duplicate HOLD',changed))
        changed=deepcopy(canonical)
        changed['review_status']='PASS'
        forged.append(('false local PASS with original HOLD',changed))
        changed=deepcopy(canonical)
        changed['unsigned_transport_sha256']['candidate']='not-an-original-receipt'
        forged.append(('forged source fingerprint',changed))
        changed=deepcopy(canonical)
        changed['unsigned_transport_sha256']['baseline']=True
        forged.append(('type-confused fingerprint',changed))
        changed=deepcopy(canonical)
        changed['hold_action_rows']=True
        forged.append(('type-confused HOLD count',changed))
        changed=deepcopy(canonical)
        changed['actions'].insert(0,dict(changed['actions'][0],
                                        transport='candidate'))
        changed['hold_action_rows']+=1
        forged.append(('interleaved baseline/candidate ordinal',changed))
        for name,data in forged:
            for fmt in ('actions-brief-markdown','actions-brief-html'):
                with self.subTest(name=name,fmt=fmt),self.assertRaises(ValueError):
                    render_action_brief(data,fmt)
        for fmt in ('actions-brief-markdown','actions-brief-html'):
            self.assertIn('NOT_VERIFIED',render_action_brief(canonical,fmt))

    def test_comparison_exports_reject_forged_counts_and_html(self):
        from copy import deepcopy
        from lightup.lab_score_review_delta import (
            compare_portable_review_transports, render_comparison)
        from lightup.lab_score_review_actions import build_review_actions
        original = compare_portable_review_transports(
            str(self.hold), str(self.passing))
        for fmt in ('json', 'text', 'csv', 'html'):
            self.assertIn('HOLD', render_comparison(original, fmt))
        cases = []
        for key, value in (
            ('review_status', 'PASS'), ('baseline_hold_preserved', False),
            ('authorization_granted', True), ('hidden_original_path', '/secret'),
        ):
            modified = deepcopy(original); modified[key] = value; cases.append(modified)
        for source, key, value in (
            ('baseline', 'unsigned_transport_sha256', 'not-a-digest'),
            ('baseline', 'global_status', '<svg onload=alert(1)>'),
            ('baseline', 'original_archives', 8),
            ('baseline', 'hold_pairs', True),
            ('candidate', 'pass_pairs', 100),
            ('candidate', 'injected_field', 'private provenance'),
        ):
            modified = deepcopy(original); modified[source][key] = value
            cases.append(modified)
        # A forged local PASS must never bury even one original HOLD pair.
        modified = deepcopy(original)
        self.assertGreater(modified['baseline']['hold_pairs'], 0)
        modified['baseline']['global_status'] = 'PASS'
        modified['baseline_hold_preserved'] = False
        modified['review_status'] = 'PASS'
        cases.append(modified)
        modified = deepcopy(original)
        modified['count_change_candidate_minus_baseline']['hold_pairs'] = 0
        cases.append(modified)
        modified = deepcopy(original)
        modified['count_change_candidate_minus_baseline']['new_private_key'] = 'secret'
        cases.append(modified)
        for idx, item in enumerate(cases):
            for fmt in ('json', 'text', 'csv', 'html'):
                with self.subTest(idx=idx, fmt=fmt), self.assertRaises(ValueError):
                    render_comparison(item, fmt)
            with self.subTest(idx=idx, fmt='actions'), self.assertRaises(ValueError):
                build_review_actions(item, str(self.hold), str(self.passing))

    def test_action_exports_admit_only_ordered_closed_synthetic_inventory(self):
        from copy import deepcopy
        from lightup.lab_score_review_delta import compare_portable_review_transports
        from lightup.lab_score_review_actions import build_review_actions, render_review_actions
        from lightup.lab_score_action_brief import render_action_brief
        original = build_review_actions(
            compare_portable_review_transports(str(self.hold), str(self.passing)),
            str(self.hold), str(self.passing))
        formats = ('actions-json', 'actions-csv', 'actions-html',
                   'actions-brief-markdown', 'actions-brief-html')
        def render(value, fmt):
            if fmt.startswith('actions-brief'):
                return render_action_brief(value, fmt)
            return render_review_actions(value, fmt)
        for fmt in formats:
            self.assertIn('NOT_VERIFIED', render(original, fmt))
        cases = []
        changed = deepcopy(original)
        changed['hidden_source_original'] = 'DO_NOT_EXPORT'
        cases.append(changed)
        changed = deepcopy(original)
        changed['actions'][-1]['original_customer_name'] = 'DO_NOT_EXPORT'
        cases.append(changed)
        changed = deepcopy(original)
        changed['actions'][-1]['completion'] = 'APPROVED'
        cases.append(changed)
        changed = deepcopy(original)
        changed['actions'][-1]['human_action'] = 'GRANT_LIVE_ACCESS'
        cases.append(changed)
        changed = deepcopy(original)
        changed['actions'][-1]['authorization_granted'] = True
        cases.append(changed)
        changed = deepcopy(original)
        changed['unsigned_transport_sha256']['baseline'] = 'private-source'
        cases.append(changed)
        changed = deepcopy(original)
        changed['hold_action_rows'] = True
        cases.append(changed)
        changed = deepcopy(original)
        changed['review_status'] = 'PASS'
        cases.append(changed)
        for invalid_reason in ([], {}):
            changed = deepcopy(original)
            changed['actions'][0]['reason'] = invalid_reason
            cases.append(changed)
        for idx, value in enumerate(cases):
            for fmt in formats:
                with self.subTest(case=idx, fmt=fmt), self.assertRaises(ValueError):
                    render(value, fmt)

    def test_multi_hold_uses_canonical_priority_and_rejects_reordering(self):
        from copy import deepcopy
        from lightup.lab_score_review_actions import build_review_actions, render_review_actions
        from lightup.lab_score_review_delta import compare_portable_review_transports
        from lightup.lab_score_action_brief import render_action_brief
        canonical = build_review_actions(
            compare_portable_review_transports(str(self.hold), str(self.passing)),
            str(self.hold), str(self.passing))
        replay = deepcopy(canonical['actions'][0])
        self.assertEqual(replay['reason'], 'evidence_reused')
        drift = dict(replay, anonymous_previous=1, anonymous_current=2,
                     reason='score_drift',
                     human_action='REVIEW_ISOLATED_SYNTHETIC_SCORER_DRIFT')
        multi = deepcopy(canonical)
        multi['actions'].insert(1, drift)
        multi['hold_action_rows'] += 1
        both = deepcopy(canonical)
        both['actions'].insert(1, dict(drift,
            anonymous_previous=replay['anonymous_previous'],
            anonymous_current=replay['anonymous_current']))
        both['hold_action_rows'] += 1
        def validate_all(value, succeeds):
            for fmt in ('actions-json','actions-csv','actions-html',
                        'actions-brief-markdown','actions-brief-html'):
                renderer = (render_action_brief if fmt.startswith('actions-brief')
                            else render_review_actions)
                with self.subTest(fmt=fmt, succeeds=succeeds):
                    if succeeds:
                        self.assertIn('NOT_VERIFIED',renderer(value,fmt))
                    else:
                        with self.assertRaises(ValueError):
                            renderer(value,fmt)
        validate_all(multi,True)
        validate_all(both,True)
        for item in (multi,both):
            reversed_item=deepcopy(item)
            reversed_item['actions'][:2]=reversed_item['actions'][1::-1]
            validate_all(reversed_item,False)
        interleaved=deepcopy(multi)
        interleaved['actions'].insert(2,deepcopy(replay))
        interleaved['hold_action_rows'] += 1
        validate_all(interleaved,False)

    def test_atomic_ten_file_original_bound_human_brief_room(self):
        from hashlib import sha256
        room=self.root/'full-private-ten-view-room'
        code,out,err=run('--compare-portable-reviews',self.hold,self.passing,
                         '--comparison-output-dir',room,'--include-actions',
                         '--include-briefs')
        self.assertEqual((code,err),(2,''))
        self.assertIn('ten private files',out)
        snapshot={p.name:p.read_bytes() for p in room.iterdir()}
        self.assertEqual(len(snapshot),10)
        self.assertEqual(set(snapshot),{'comparison.json','comparison.txt',
            'comparison.csv','comparison.html','actions.json','actions.csv',
            'actions.html','human-brief.md','human-brief.html','manifest.json'})
        self.assertEqual(room.stat().st_mode&0o777,0o700)
        self.assertTrue(all(p.stat().st_mode&0o777==0o600 for p in room.iterdir()))
        manifest=json.loads(snapshot['manifest.json'])
        self.assertEqual(manifest['schema'],
            'lightup.lab-score-human-two-transport-workroom.v3')
        self.assertEqual(set(manifest['file_sha256']),
                         set(snapshot)-{'manifest.json'})
        self.assertTrue(all(sha256(snapshot[name]).hexdigest()==digest
                            for name,digest in manifest['file_sha256'].items()))
        admit_inert_html(snapshot['human-brief.html'])
        self.assertIn(b'GLOBAL STATUS HOLD',snapshot['human-brief.html'])
        for fmt,name in (('actions-brief-markdown','human-brief.md'),
                         ('actions-brief-html','human-brief.html'),
                         ('actions-json','actions.json'),('json','comparison.json')):
            code,out,err=run('--verify-comparison-workroom',self.hold,self.passing,
                             '--comparison-output-dir',room,'--export-comparison',
                             '--format',fmt)
            self.assertEqual((code,err),(2,''))
            self.assertEqual(out.encode(),snapshot[name])
        self.assertEqual(snapshot,{p.name:p.read_bytes() for p in room.iterdir()})
        code,out,err=run('--verify-comparison-workroom',self.hold,self.passing,
                         '--comparison-output-dir',room)
        self.assertEqual((code,err),(2,''))
        self.assertIn('ten saved files reverified',out)
        (room/'human-brief.md').write_text('forged independent review')
        for fmt in ('json','actions-brief-html','actions-csv'):
            code,out,err=run('--verify-comparison-workroom',self.hold,self.passing,
                             '--comparison-output-dir',room,
                             '--export-comparison','--format',fmt)
            self.assertEqual((code,out),(2,''))
            self.assertIn('not verified',err)

    def test_ten_file_private_briefs_require_explicit_actions_and_new_room(self):
        with self.assertRaises(SystemExit):
            run('--compare-portable-reviews',self.hold,self.passing,
                '--include-briefs','--comparison-output-dir',self.root/'missing')
        with self.assertRaises(SystemExit):
            run('--verify-comparison-workroom',self.hold,self.passing,
                '--include-actions','--include-briefs',
                '--comparison-output-dir',self.root/'missing')
        with self.assertRaises(SystemExit):
            run('--compare-portable-reviews',self.hold,self.passing,
                '--include-actions','--include-briefs')

    def test_export_requires_original_source_and_saved_private_room(self):
        with self.assertRaises(SystemExit):
            run('--compare-portable-reviews',self.hold,self.passing,
                '--export-comparison','--format','html')
        with self.assertRaises(SystemExit):
            run('--verify-comparison-workroom',self.hold,self.passing,
                '--comparison-output-dir',self.root/'missing','--format','html')

    def test_original_hold_action_plan_is_source_bound_and_human_only(self):
        """The old original replay stays actionable even after candidate PASS."""
        from lightup.lab_score_portable_html_safety import admit_inert_html
        for fmt in ('actions-json','actions-csv','actions-html'):
            code,out,err=run('--compare-portable-reviews',
                             self.hold,self.passing,'--format',fmt)
            self.assertEqual((code,err),(2,''))
            self.assertNotIn(str(self.root),out)
            if fmt=='actions-json':
                data=json.loads(out)
                self.assertEqual(data['review_status'],'HOLD')
                self.assertEqual(data['hold_action_rows'],1)
                self.assertEqual(len(data['actions']),2)
                self.assertEqual(data['actions'][0]['transport'],'baseline')
                self.assertEqual(data['actions'][0]['reason'],'evidence_reused')
                self.assertEqual(data['actions'][0]['human_action'],
                                 'RECAPTURE_INDEPENDENT_SYNTHETIC_ORIGINALS')
                self.assertEqual(data['actions'][1]['transport'],
                                 'both_independent_origins')
                self.assertFalse(data['same_originals_proven'])
                self.assertFalse(data['authorization_granted'])
                self.assertFalse(data['remediation_verified'])
            elif fmt=='actions-csv':
                rows=list(csv.DictReader(io.StringIO(out)))
                self.assertEqual(len(rows),2)
                self.assertTrue(all(row['completion']=='NOT_VERIFIED'
                                    and row['authorization_granted']=='false'
                                    for row in rows))
                self.assertEqual(rows[0]['reason'],'evidence_reused')
            else:
                admit_inert_html(out.encode())
                self.assertIn('GLOBAL STATUS HOLD',out)
                self.assertIn('baseline',out)
                self.assertNotIn('<script',out)

    def test_saved_room_rebuilds_human_action_plan_and_rejects_other_tampering(self):
        room=self.root/'safe-action-source-room'
        code,out,err=run('--compare-portable-reviews',self.hold,self.passing,
                         '--comparison-output-dir',room)
        self.assertEqual((code,err),(2,''))
        original={p.name:p.read_bytes() for p in room.iterdir()}
        for fmt in ('actions-json','actions-csv','actions-html'):
            status,content,err=run('--verify-comparison-workroom',
                                   self.hold,self.passing,'--comparison-output-dir',room,
                                   '--export-comparison','--format',fmt)
            self.assertEqual((status,err),(2,''))
            self.assertTrue(content)
        self.assertEqual(original,{p.name:p.read_bytes() for p in room.iterdir()})
        (room/'comparison.html').write_text('tampered even when JSON actions requested')
        code,out,err=run('--verify-comparison-workroom',self.hold,self.passing,
                         '--comparison-output-dir',room,
                         '--export-comparison','--format','actions-json')
        self.assertEqual((code,out),(2,''))
        self.assertIn('not verified',err)
