"""Offline checks for the proof-index verifier. No real targets or I/O."""
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "verify_scope_proof_manifest.py"
spec = importlib.util.spec_from_file_location("scope_proof_manifest", MODULE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

A = "a" * 40
B = "b" * 40


def fixture():
    return dict(implementation_sha=A, base_sha=B,
                hosted_py311_sha=A, hosted_py314_sha=A, permanent_vps_sha=A,
                owner_review_sha=A, trusted_grant_reviewed=True,
                revocation_race_passed=True, denied_side_effects_zero=True,
                positive_loopback_control_passed=True,
                real_target_activation_disabled=True,
                denial_side_effect_counts={
                    "handler": 0, "socket": 0, "queue": 0, "action_evidence": 0})


class ProofManifestTests(unittest.TestCase):
    def test_valid_index_only(self):
        self.assertEqual(module.verify(fixture()), [])

    def test_exact_sha_binding_for_every_proof(self):
        for key in ("hosted_py311_sha", "hosted_py314_sha",
                    "permanent_vps_sha", "owner_review_sha"):
            with self.subTest(key=key):
                obj = fixture()
                obj[key] = B
                self.assertTrue(module.verify(obj))

    def test_denial_boundaries_reject_effects(self):
        for key in ("handler", "socket", "queue", "action_evidence"):
            for value in (1, -1, None, False, "0", 0.0):
                with self.subTest(key=key, value=value):
                    obj = fixture()
                    obj["denial_side_effect_counts"][key] = value
                    self.assertTrue(module.verify(obj))

    def test_boolean_evidence_must_be_literal_true(self):
        for key in ("trusted_grant_reviewed", "revocation_race_passed",
                    "denied_side_effects_zero", "positive_loopback_control_passed",
                    "real_target_activation_disabled"):
            obj = fixture()
            obj[key] = 1
            self.assertTrue(module.verify(obj))

    def test_absent_or_malformed_manifest_is_denied(self):
        self.assertTrue(module.verify(None))
        self.assertTrue(module.verify({}))
        obj = fixture()
        obj["implementation_sha"] = "short"
        self.assertTrue(module.verify(obj))


if __name__ == "__main__":
    unittest.main()
