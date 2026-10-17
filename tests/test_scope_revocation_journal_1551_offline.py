"""Strict offline detached journal regressions. Synthetic samples only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_scope_document_binding_1551_offline import packet_for_scope
from test_scope_consent_timeline_1551_offline import raw

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_revocation_journal_1551_offline.py"
spec = importlib.util.spec_from_file_location("scope1551_journal", SCRIPT)
journal_review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journal_review)

SCOPE = b"fictional scope owned for offline tests only\n"


def make_journal(batch):
    latest = batch["entries"][-1]["packet"]
    return {
        "schema_version": 1, "proposal_sha": latest["proposal_sha"],
        "scope_sha256": latest["scope_sha256"], "through_at": latest["review_at"],
        "principals": {x["role"]: x["principal"] for x in latest["consents"]},
        "covered_sequence": 11, "events": [],
    }


class DetachedJournalSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.scope_path = Path(self.temp.name) / "scope.txt"
        self.journal_path = Path(self.temp.name) / "journal.json"
        self.scope_path.write_bytes(SCOPE)
        self.batch = packet_for_scope(SCOPE)
        self.journal = make_journal(self.batch)
        self.save_journal()

    def save_journal(self):
        self.journal_path.write_bytes(raw(self.journal))
        self.pin = hashlib.sha256(self.journal_path.read_bytes()).hexdigest()

    def request(self, *, argv=None, snapshot=None, expected=3):
        if argv is None:
            argv = ["--scope-document", str(self.scope_path),
                    "--revocation-journal", str(self.journal_path),
                    "--expected-journal-sha256", self.pin]
        if snapshot is None:
            snapshot = raw(self.batch)
        result = subprocess.run([sys.executable,"-I","-S","-B",str(SCRIPT),*argv],
                                input=snapshot,capture_output=True,timeout=9)
        self.assertEqual(expected,result.returncode,result.stderr)
        decoded = json.loads(result.stdout)
        self.assertEqual("REVIEW_ONLY" if expected == 3 else "HOLD",decoded["status"])
        for field in journal_review.claim.AUTHORITY_FLAGS:
            self.assertIs(decoded[field],False,field)
        for secret in (SCOPE, bytes(str(self.scope_path),"utf8"),
                       bytes(str(self.journal_path),"utf8"),
                       b"client:example", b"operator:example"):
            self.assertNotIn(secret,result.stdout)
        self.assertEqual(result.stderr,b"")
        return decoded

    def test_exact_journal_review_remains_non_authorizing(self):
        self.assertEqual("UNAUTHENTICATED_JOURNAL_CONSISTENCY_ONLY",
                         self.request()["reason"])

    def test_detects_revocation_removed_without_external_digest_change(self):
        self.journal["events"] = [{"role":"client", "principal":"client:example",
                                   "effective_at":"2026-10-17T12:00:30Z", "event_seq":12}]
        self.save_journal()
        pinned_revoked_file = self.pin
        self.request(expected=2)
        self.journal["events"] = []
        self.save_journal()
        # Forged deletion must not match the independently held old revoked file.
        self.request(argv=["--scope-document",str(self.scope_path),
                           "--revocation-journal",str(self.journal_path),
                           "--expected-journal-sha256", pinned_revoked_file],expected=2)
        # Explicitly demonstrate why a self-selected NEW pin is not authority.
        self.request()

    def test_any_detached_revocation_holds_even_with_valid_pin(self):
        self.journal["events"] = [{"role":"client","principal":"client:example",
                                   "effective_at":"2026-10-17T12:00:30Z","event_seq":12}]
        self.save_journal()
        self.request(expected=2)

    def test_missing_sequence_coverage_holds(self):
        self.journal["covered_sequence"] = 10
        self.save_journal()
        self.request(expected=2)

    def test_claim_revision_scope_and_principal_drift_hold(self):
        for key, changed in (("scope_sha256","c"*64), ("proposal_sha","c"*40),
                             ("through_at","2026-10-17T12:00:00Z"),
                             ("principals",{"client":"client:other","operator":"operator:example"})):
            with self.subTest(key=key):
                self.journal = make_journal(self.batch)
                self.journal[key] = changed
                self.save_journal()
                self.request(expected=2)

    def test_schema_missing_extra_and_type_confusion_hold(self):
        for change in ("extra","missing","bool","string","sequence-bool","events-dict"):
            with self.subTest(change=change):
                self.journal = make_journal(self.batch)
                if change == "extra":self.journal["authorized"]=True
                elif change == "missing":del self.journal["principals"]
                elif change == "bool":self.journal["schema_version"]=True
                elif change == "string":self.journal["schema_version"]="1"
                elif change == "sequence-bool":self.journal["covered_sequence"]=True
                elif change == "events-dict":self.journal["events"]={}
                self.save_journal()
                self.request(expected=2)

    def test_raw_bytes_hash_fails_on_whitespace_change(self):
        self.journal_path.write_bytes(self.journal_path.read_bytes()+b" ")
        self.request(expected=2)

    def test_duplicate_json_keys_escape_and_nonfinite_hold(self):
        original=self.journal_path.read_bytes()
        for mutated in (original[:-1]+b',"events":[]}',
                        original.replace(b'"events":[]',b'"events":NaN'),
                        original.replace(b'"events"',b'"\\u0065vents"')):
            self.journal_path.write_bytes(mutated)
            self.pin=hashlib.sha256(mutated).hexdigest()
            self.request(expected=2)
        self.journal_path.write_bytes(original)
        self.pin=hashlib.sha256(original).hexdigest()

    def test_missing_pin_wrong_pin_and_unknown_flags_hold(self):
        core=["--scope-document",str(self.scope_path),"--revocation-journal",str(self.journal_path)]
        for argv in (core,core+["--expected-journal-sha256","0"*64],
                     core+["--expected-journal-sha256",self.pin.upper()],
                     core+["--expected-journal-sha256","c"*64],
                     core+["--expected-journal-sha256",self.pin,"--scan"],
                     ["--revocation-journal",str(self.journal_path)]):
            with self.subTest(argv=argv):
                self.request(argv=argv,expected=2)

    def test_symlink_to_journal_and_parent_directory_hold(self):
        link=Path(self.temp.name)/"alias"
        link.symlink_to(self.journal_path)
        prefix=["--scope-document",str(self.scope_path),"--revocation-journal"]
        self.request(argv=prefix+[str(link),"--expected-journal-sha256",self.pin],expected=2)
        directory=Path(self.temp.name)/"alias-parent"
        directory.symlink_to(self.journal_path.parent, target_is_directory=True)
        self.request(argv=prefix+[str(directory/self.journal_path.name),
                        "--expected-journal-sha256",self.pin],expected=2)

    def test_journal_fifo_directory_and_oversize_hold(self):
        self.request(argv=["--scope-document",str(self.scope_path),"--revocation-journal",
                           str(self.journal_path.parent),"--expected-journal-sha256",self.pin],expected=2)
        self.journal_path.write_bytes(b"x"* (journal_review.MAX_JOURNAL_BYTES+1))
        self.request(expected=2)
        if hasattr(os,"mkfifo"):
            pipe=Path(self.temp.name)/"fifo"
            os.mkfifo(pipe)
            self.request(argv=["--scope-document",str(self.scope_path),"--revocation-journal",
                               str(pipe),"--expected-journal-sha256",self.pin],expected=2)

    def test_deleting_or_changing_timeline_claims_hold(self):
        altered=packet_for_scope(b"changed unrelated bytes")
        self.request(snapshot=raw(altered),expected=2)
        invalid=raw(self.batch)+b"garbage"
        self.request(snapshot=invalid,expected=2)

    def test_rejects_incomplete_journal_even_with_unchanged_scope(self):
        self.journal["through_at"]="2026-10-17T12:00:00Z"
        self.save_journal()
        self.request(expected=2)

    def test_no_target_or_production_authority_import(self):
        source=SCRIPT.read_text("utf8")
        for forbidden in ("import requests","import socket","urllib.request",
                          "from lightup","ExecutionPermit(","AuthorizationGrant(",
                          "subprocess.run("):
            self.assertNotIn(forbidden,source)


if __name__ == "__main__":
    unittest.main()
