"""#1551 detached scope-document bytes: bounded, no-symlink, offline HOLD acceptance."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_scope_consent_timeline_1551_offline import make_timeline, raw, timeline

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_document_binding_1551_offline.py"
spec = importlib.util.spec_from_file_location("scope1551_detached", SCRIPT)
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)


def packet_for_scope(document):
    rows = make_timeline()
    digest = hashlib.sha256(document).hexdigest()
    for item in rows["entries"]:
        item["packet"]["scope_sha256"] = digest
        for claim in item["packet"]["consents"]:
            claim["scope_sha256"] = digest
    for i in range(1, len(rows["entries"])):
        rows["entries"][i]["previous_sha256"] = timeline.entry_digest(rows["entries"][i - 1])
    return rows


class ScopeDocumentAcceptance(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.document = b"fictional-scope-v1\nasset: fictional.example\n"
        self.path = Path(self.workspace.name) / "fictional-scope.txt"
        self.path.write_bytes(self.document)
        self.fixture = packet_for_scope(self.document)

    def invoke(self, argv=None, payload=None, expect=3):
        if argv is None:
            argv = ["--scope-document", str(self.path)]
        if payload is None:
            payload = raw(self.fixture)
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT), *argv],
                                input=payload, capture_output=True, timeout=12)
        self.assertEqual(expect, result.returncode, result.stderr)
        decoded = json.loads(result.stdout)
        self.assertEqual("REVIEW_ONLY" if expect == 3 else "HOLD", decoded["status"])
        self.assertTrue(all(decoded[k] is False for k in timeline.claim.AUTHORITY_FLAGS))
        self.assertNotIn(str(self.path).encode(), result.stdout)
        self.assertNotIn(self.document, result.stdout)
        self.assertEqual(b"", result.stderr)
        return result

    def test_exact_bytes_pass_as_review_not_authorization(self):
        self.invoke()

    def test_modified_file_fails_even_with_semantically_same_document(self):
        self.path.write_bytes(self.document + b" ")
        self.invoke(expect=2)

    def test_modified_claim_fails_even_if_internal_chain_recomputed(self):
        changed = packet_for_scope(b"other-fabricated-scope")
        self.invoke(payload=raw(changed), expect=2)

    def test_truncated_scope_file_fails(self):
        self.path.write_bytes(self.document[:-1])
        self.invoke(expect=2)

    def test_zero_length_scope_fails(self):
        self.path.write_bytes(b"")
        self.invoke(expect=2)

    def test_maximum_regular_file_size_is_enforced(self):
        self.path.write_bytes(b"x" * (timeline.MAX_SCOPE_DOCUMENT_BYTES + 1))
        self.invoke(expect=2)

    def test_missing_path_fails(self):
        self.invoke(["--scope-document", str(self.path)+"-missing"], expect=2)

    def test_symlink_fails_even_if_target_matches(self):
        link = Path(self.workspace.name) / "link"
        link.symlink_to(self.path)
        self.invoke(["--scope-document", str(link)], expect=2)

    def test_directory_path_fails(self):
        self.invoke(["--scope-document", self.workspace.name], expect=2)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX")
    def test_fifo_is_not_read_or_blocked(self):
        pipe = Path(self.workspace.name) / "pipe"
        os.mkfifo(pipe)
        self.invoke(["--scope-document", str(pipe)], expect=2)

    def test_unknown_and_ambiguous_flags_fail_closed(self):
        for args in ([], ["--authorize"], ["--scope-document"],
                     ["--scope-document", str(self.path), "--scan"],
                     ["--scope-document", str(self.path), "--expected-head"],
                     ["--scope-document", str(self.path), "--checkpoint", "0:"+"x"*64]):
            with self.subTest(args=args):
                self.invoke(args, expect=2)

    def test_detached_file_combined_with_independent_checkpoint_and_head(self):
        pin = timeline.entry_digest(self.fixture["entries"][1])
        head = timeline.entry_digest(self.fixture["entries"][2])
        args = ["--scope-document", str(self.path), "--checkpoint", "1:"+pin,
                "--expected-head", head]
        self.invoke(args)
        self.invoke(args[:-1]+["c"*64], expect=2)

    def test_detached_document_plus_old_checkpoint_rejects_newer_forged_history(self):
        original_pin = timeline.entry_digest(self.fixture["entries"][1])
        substituted = packet_for_scope(self.document)
        for item in substituted["entries"]:
            item["packet"]["consents"][1]["principal"] = "operator:substituted"
        for i in range(1,len(substituted["entries"])):
            substituted["entries"][i]["previous_sha256"]=timeline.entry_digest(substituted["entries"][i-1])
        self.invoke(["--scope-document", str(self.path)], raw(substituted))
        self.invoke(["--scope-document", str(self.path), "--checkpoint","1:"+original_pin],
                    raw(substituted), expect=2)

    def test_timeline_oversized_or_corrupted_fails(self):
        payload = raw(self.fixture)
        for bad in (b"", b"\xff"+payload, payload+b" "*(timeline.MAX_TIMELINE_BYTES+1)):
            self.invoke(payload=bad, expect=2)

    def test_source_is_only_local_offline_read_and_no_auth_import(self):
        source = SCRIPT.read_text("utf-8")
        for term in ("import socket", "urllib.request", "import requests", "subprocess.run(",
                     "from lightup", "ExecutionPermit(", "AuthorizationGrant("):
            self.assertNotIn(term, source)


    def test_document_mutation_mid_read_must_fail_closed(self):
        from unittest.mock import patch
        reader = os.read
        switched = [False]
        updated = self.document.replace(b"fictional", b"FICTIONAL")
        self.assertEqual(len(updated), len(self.document))
        def change_during_read(fd, count):
            data = reader(fd, count)
            if data and not switched[0]:
                switched[0] = True
                self.path.write_bytes(updated)
            return data
        with patch.object(binding.os, "read", side_effect=change_during_read):
            with self.assertRaises(ValueError):
                binding._read_regular_document(str(self.path))
        self.assertTrue(switched[0])


if __name__ == "__main__":
    unittest.main()
