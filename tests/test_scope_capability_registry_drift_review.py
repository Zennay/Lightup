"""Synthetic manifest review is never executable authorization."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lightup.capability_registry_drift_review import review_capability_registry_drift


def manifest(records):
    return json.dumps({"capabilities": records}).encode()


def cap(name="web-baseline", state="planning", activation=True):
    return {"capability_id": name, "state": state, "requires_explicit_activation": activation}


class CapabilityDriftReviewTests(unittest.TestCase):
    def setUp(self):
        self.initial = manifest([cap(), cap("wireless-lab", "lab_only")])

    def verify_non_authority(self, receipt):
        for key in ("authorization_verified", "permit_issued", "execution_enabled", "merge_approved", "release_approved"):
            self.assertIs(getattr(receipt, key), False)
            self.assertIs(receipt.as_dict()[key], False)

    def test_equal_registry_only_review(self):
        r = review_capability_registry_drift(self.initial, self.initial)
        self.assertEqual(r.status, "REVIEW_ONLY")
        self.assertEqual(r.baseline_fingerprint, r.candidate_fingerprint)
        self.assertEqual(r.changed_capabilities, ())
        self.verify_non_authority(r)

    def test_order_independent_fingerprint(self):
        reordered = manifest([cap("wireless-lab", "lab_only"), cap()])
        self.assertEqual(review_capability_registry_drift(self.initial, reordered).status, "REVIEW_ONLY")

    def test_registry_addition_holds(self):
        r = review_capability_registry_drift(self.initial, manifest([cap(), cap("wireless-lab", "lab_only"), cap("new-capability")]))
        self.assertEqual((r.status, r.changed_capabilities), ("HOLD", ("new-capability",)))
        self.verify_non_authority(r)

    def test_registry_removal_holds(self):
        r = review_capability_registry_drift(self.initial, manifest([cap()]))
        self.assertEqual((r.status, r.changed_capabilities), ("HOLD", ("wireless-lab",)))

    def test_lab_to_planning_reclassification_holds(self):
        r = review_capability_registry_drift(self.initial, manifest([cap(), cap("wireless-lab")]))
        self.assertEqual(r.status, "HOLD")

    def test_activation_flag_relaxation_holds(self):
        r = review_capability_registry_drift(self.initial, manifest([cap(activation=False), cap("wireless-lab", "lab_only")]))
        self.assertEqual(r.changed_capabilities, ("web-baseline",))

    def test_all_invalid_fail_closed(self):
        cases = [
            b"", b"{}", b"[]", b"null", b"\xff", b"{" + b"x" * 33000 + b"}",
            b'{"capabilities":[],"capabilities":[]}', b'{"capabilities":[]}',
            manifest([cap(), cap()]),
            manifest([cap("web--baseline")]),
            manifest([cap("Web-baseline")]),
            manifest([cap("wireless-lab", "target_active")]),
            manifest([cap(activation=1)]),
            manifest([cap(activation="false")]),
            manifest([dict(cap(), unexpected=True)]),
            manifest([cap(str(i)) for i in range(129)]),
            manifest([cap("127.0.0.1")]),
        ]
        for invalid in cases:
            with self.subTest(invalid=invalid[:100]):
                r = review_capability_registry_drift(self.initial, invalid)
                self.assertEqual(r.status, "HOLD")
                self.verify_non_authority(r)

    def test_type_spoofing_fails_closed(self):
        class BytesSubclass(bytes):
            pass
        self.assertEqual(review_capability_registry_drift(self.initial, BytesSubclass(self.initial)).status, "HOLD")

    def test_both_invalid_cannot_compare_equal(self):
        self.assertEqual(review_capability_registry_drift(b"{}", b"{}").status, "HOLD")

    def test_changed_fingerprint_is_sensitive_to_flag(self):
        new = manifest([cap(activation=False), cap("wireless-lab", "lab_only")])
        receipt = review_capability_registry_drift(self.initial, new)
        self.assertNotEqual(receipt.baseline_fingerprint, receipt.candidate_fingerprint)

    def test_cli_regular_files_no_success_exit(self):
        script = Path(__file__).resolve().parents[1] / "scripts/review_scope_capability_registry_offline.py"
        with tempfile.TemporaryDirectory() as d:
            baseline = Path(d) / "baseline.json"
            candidate = Path(d) / "candidate.json"
            baseline.write_bytes(self.initial)
            candidate.write_bytes(self.initial)
            proc = subprocess.run([sys.executable, str(script), str(baseline), str(candidate)], text=True, capture_output=True)
            self.assertEqual(proc.returncode, 3, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["status"], "REVIEW_ONLY")
            candidate.write_bytes(manifest([cap()]))
            proc = subprocess.run([sys.executable, str(script), str(baseline), str(candidate)], text=True, capture_output=True)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(json.loads(proc.stdout)["status"], "HOLD")

    def test_cli_reject_symlink(self):
        if not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("safe open unsupported")
        script = Path(__file__).resolve().parents[1] / "scripts/review_scope_capability_registry_offline.py"
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / "original.json"
            link = Path(d) / "link.json"
            original.write_bytes(self.initial)
            link.symlink_to(original)
            proc = subprocess.run([sys.executable, str(script), str(link), str(original)], text=True, capture_output=True)
            self.assertEqual(proc.returncode, 2)
            self.assertFalse(json.loads(proc.stdout)["execution_enabled"])


if __name__ == "__main__":
    unittest.main()
