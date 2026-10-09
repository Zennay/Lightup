"""Offline integrity checks for the real-target release evidence manifest.

A manifest is an audit TODO list, never a grant or activation mechanism.
"""
import json
from pathlib import Path
import unittest

MANIFEST = Path(__file__).resolve().parents[1] / "docs" / "scope-real-target-release-evidence-20261009.json"
REQUIRED = {
    "trusted_issuer", "customer_consent", "engagement_binding",
    "asset_binding", "capability_binding", "revocation_at_dispatch",
    "zero_executor_calls_on_denial", "zero_evidence_writes_on_denial",
    "hosted_exact_sha_ci", "permanent_vps_exact_sha_ci",
    "source_owner_review",
}

class ScopeReleaseEvidenceManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_manifest_explicitly_holds_activation(self):
        self.assertEqual(self.manifest["release_gate"], "real_target_authorization")
        self.assertEqual(self.manifest["status"], "HOLD")
        self.assertIs(self.manifest["network_operations_permitted"], False)
        self.assertEqual(self.manifest["activation_rule"], "explicit_project_level_activation_required")

    def test_required_evidence_is_complete_and_unique(self):
        entries = self.manifest["requirements"]
        ids = [entry["id"] for entry in entries]
        self.assertEqual(set(ids), REQUIRED)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(entry["owner"] for entry in entries))

    def test_no_requirement_is_marked_as_verified_without_proof(self):
        for entry in self.manifest["requirements"]:
            with self.subTest(requirement=entry["id"]):
                self.assertEqual(entry["state"], "unverified")
                self.assertNotIn("approval", entry)
                self.assertNotIn("grant", entry)

if __name__ == "__main__":
    unittest.main()
