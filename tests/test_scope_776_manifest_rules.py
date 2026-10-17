"""Fail-closed unit tests for the #776 offline provenance/authority manifest.

All Git, subprocess, and blob operations are mocked; no network or tests run.
This file is deliberately excluded from the pinned 26 acceptance tests but
included in normal project unit discovery.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "scope_776_composition_check_20261017.py"
spec = importlib.util.spec_from_file_location("scope776_manifest_under_test", CHECKER)
checker = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(checker)


class OfflineCompositionManifestRules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="scope776_manifest_test_")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "manifest.json"
        self.manifest = json.loads(checker.MANIFEST.read_text(encoding="utf-8"))
        p = patch.object(checker, "MANIFEST", self.path)
        p.start()
        self.addCleanup(p.stop)
        p = patch.object(checker, "git", side_effect=self.fake_git)
        p.start()
        self.addCleanup(p.stop)
        p = patch.object(checker, "blob", return_value=b"")
        p.start()
        self.addCleanup(p.stop)
        p = patch.object(checker.subprocess, "run")
        p.start()
        self.addCleanup(p.stop)

    @staticmethod
    def fake_git(*args):
        if args[:2] == ("diff", "--name-status"):
            return "".join("A\\t" + path + "\\n" for path in
                           checker.OWN_PATHS).encode("utf-8")
        if args[:2] == ("ls-tree", "HEAD"):
            return ("100644 blob " + "0" * 40 +
                    "\\t" + args[-1] + "\\n").encode("utf-8")
        if args and args[0] == "ls-tree":
            return b""
        if args and args[0] == "status":
            return b""
        return b""

    def assert_refused(self, expected: str):
        self.path.write_text(json.dumps(self.manifest), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, expected):
            checker.verify_manifest()

    def test_exact_pinned_ownership_manifest_admitted_without_real_git(self):
        self.path.write_text(json.dumps(self.manifest), encoding="utf-8")
        verified = checker.verify_manifest()
        self.assertEqual(verified["expected_total_methods"], 26)

    def test_authority_flags_cannot_be_promoted(self):
        for name in ("may_authorize", "may_dispatch", "may_scan",
                     "may_deploy", "may_release"):
            with self.subTest(name=name):
                self.manifest[name] = True
                self.assert_refused("scope776_authority_claim")
                self.manifest[name] = False

    def test_review_only_must_be_literal_true(self):
        for invalid in (False, 1, "true", None):
            with self.subTest(invalid=repr(invalid)):
                self.manifest["review_only"] = invalid
                self.assert_refused("scope776_authority_claim")
                self.manifest["review_only"] = True

    def test_sha_or_owner_lineage_drift_is_denied(self):
        self.manifest["pinned_owner_head"] = "0" * 40
        self.assert_refused("scope776_manifest_shape_or_count_changed")

    def test_source_pin_or_order_change_is_denied(self):
        self.manifest["composed_tests"][0]["git_blob_sha1"] = "f" * 40
        self.assert_refused("scope776_composition_source_drift")
        self.manifest["composed_tests"][0]["git_blob_sha1"] = (
            checker.SOURCE_BLOBS[648][2]
        )
        self.manifest["composed_tests"].reverse()
        self.assert_refused("scope776_composition_source_drift")

    def test_upstream_773_execution_claim_is_denied(self):
        self.manifest["upstream_773_reference_only"]["policy"] = "execute"
        self.assert_refused("scope776_external_owner_773_not_fenced")

    def test_source_count_inflation_is_denied(self):
        self.manifest["expected_total_methods"] = 999
        self.assert_refused("scope776_manifest_shape_or_count_changed")

    def test_source_red_count_understatement_is_denied(self):
        self.manifest["expected_source_reds"] = 0
        self.assert_refused("scope776_manifest_shape_or_count_changed")

    def test_any_other_worker_file_change_is_refused(self):
        original = self.fake_git

        def tamper(*args):
            if args[:2] == ("diff", "--name-status"):
                return original(*args) + b"M\\tsrc/lightup/domain.py\\n"
            return original(*args)

        with patch.object(checker, "git", side_effect=tamper):
            self.assert_refused("scope776_source_or_other_worker_path_changed")

    def test_deleted_or_overwritten_own_test_is_refused(self):
        original = self.fake_git

        def tamper(*args):
            if args[:2] == ("diff", "--name-status"):
                return original(*args).replace(b"A\\ttests/", b"M\\ttests/", 1)
            return original(*args)

        with patch.object(checker, "git", side_effect=tamper):
            self.assert_refused("scope776_source_or_other_worker_path_changed")

    def test_imported_source_and_vetted_risk_reference_are_exact(self):
        self.assertEqual([x["issue"] for x in self.manifest["composed_tests"]],
                         [648, 775])
        self.assertEqual(self.manifest["upstream_773_reference_only"]["source_commit"],
                         checker.REFERENCE_773[0])


if __name__ == "__main__":
    unittest.main()
