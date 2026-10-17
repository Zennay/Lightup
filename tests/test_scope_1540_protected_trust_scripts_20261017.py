"""#1540 protected CI evidence tools and Git checkout configuration canaries."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
TOOL=ROOT/"scripts"/"review_scope_worker_ownership_offline_1540.py"
S=importlib.util.spec_from_file_location("scope1540_trustscripts",TOOL)
reviewer=importlib.util.module_from_spec(S)
S.loader.exec_module(reviewer)
GOOD=json.loads((ROOT/"examples"/"scope1540-owner-review-only.json").read_text())


def raw(doc):
    return json.dumps(doc,ensure_ascii=True,sort_keys=True,separators=(",",":")).encode("ascii")


def changed(path):
    doc=json.loads(json.dumps(GOOD))
    doc["protected_paths"]=["unrelated/example.txt"]
    doc["reviews"][1]["compare"]["files"][0]["filename"]=path
    doc["ownership"][1]["paths"][0]=path
    return doc


class ControlPlaneEvidenceTests(unittest.TestCase):
    def test_security_canary_and_scope_evidence_scripts_always_hold(self):
        for path in (
            "scripts/check_safety_canaries.py",
            "scripts/review_scope_history_against_checkout_offline.py",
            "scripts/review_scope_registry_history_offline.py",
            "scripts/review_scope_capability_registry_offline.py",
            "scripts/export_scope_capability_registry_offline.py",
            "scripts/render_scope_registry_history_offline.py",
            "SCRIPTS/CHECK_SAFETY_CANARIES.PY",
        ):
            with self.subTest(path=path):
                self.assertEqual(reviewer.check(raw(changed(path))),"HOLD")

    def test_own_review_gate_modules_cannot_self_modify_under_review(self):
        for path in (
            "scripts/review_scope_worker_overlap_offline_1540.py",
            "scripts/review_scope_compare_snapshots_offline_1540.py",
            "scripts/review_scope_pr_compare_pair_offline_1540.py",
            "scripts/review_scope_worker_ownership_offline_1540.py",
            "SCRIPTS/REVIEW_SCOPE_WORKER_OWNERSHIP_OFFLINE_1540.PY",
        ):
            with self.subTest(path=path):
                self.assertEqual(reviewer.check(raw(changed(path))), "HOLD")

    def test_checkout_git_control_files_always_hold(self):
        for path in (".gitattributes",".gitmodules",".lfsconfig",".gitignore",
                     ".GITATTRIBUTES"):
            with self.subTest(path=path):
                self.assertEqual(reviewer.check(raw(changed(path))),"HOLD")

    def test_similar_but_not_identical_tools_do_not_fake_hold(self):
        for path in ("scripts/check_safety_canaries.py.bak",
                     "scripts/fictitious_regression.py",
                     ".gitattributes.example",
                     "docs/gitignore-guide.md"):
            with self.subTest(path=path):
                self.assertEqual(reviewer.check(raw(changed(path))),"REVIEW_ONLY")

    def test_renaming_from_hard_hold_script_denies_even_if_destination_is_docs(self):
        d=changed("docs/new-reviewer.md")
        d["reviews"][1]["compare"]["files"][0]={
            "status":"renamed","filename":"docs/new-reviewer.md",
            "previous_filename":"scripts/check_safety_canaries.py"}
        d["ownership"][1]["paths"]=[
            "docs/new-reviewer.md","scripts/check_safety_canaries.py"]
        self.assertEqual(reviewer.check(raw(d)),"HOLD")

    def test_trust_script_names_still_reject_casefold_aliases(self):
        d=changed("scripts/CHECK_safety_canaries.py")
        self.assertEqual(reviewer.check(raw(d)),"HOLD")


if __name__=="__main__":
    unittest.main()
