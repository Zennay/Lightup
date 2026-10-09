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

def validate_hold_manifest(data):
    """Return deterministic defects. Never infer activation from this fixture."""
    defects = []
    if type(data) is not dict:
        return ["manifest must be an object"]
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        defects.append("unsupported manifest schema")
    if data.get("status") != "HOLD" or data.get("network_operations_permitted") is not False:
        defects.append("activation must remain disabled")
    if data.get("release_gate") != "real_target_authorization":
        defects.append("unexpected release gate")
    if data.get("activation_rule") != "explicit_project_level_activation_required":
        defects.append("explicit activation rule missing")
    entries = data.get("requirements")
    if type(entries) is not list:
        return defects + ["requirements must be an array"]
    ids = []
    for entry in entries:
        if type(entry) is not dict or type(entry.get("id")) is not str:
            defects.append("malformed requirement entry")
            continue
        ids.append(entry["id"])
        if entry.get("state") != "unverified" or not isinstance(entry.get("owner"), str) or not entry["owner"].strip():
            defects.append("unaudited state or missing owner: " + entry["id"])
        if "approval" in entry or "grant" in entry:
            defects.append("fixture cannot issue approval or grant: " + entry["id"])
    if set(ids) != REQUIRED or len(ids) != len(REQUIRED):
        defects.append("required controls missing, duplicated or unexpected")
    return defects


class ScopeReleaseEvidenceManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_manifest_validator_accepts_hold_fixture(self):
        self.assertEqual(validate_hold_manifest(self.manifest), [])

    def test_mutated_activation_flags_fail_closed(self):
        import copy
        for status, allowed in [("READY", False), ("HOLD", True), ("HOLD", 0), ("HOLD", "false")]:
            with self.subTest(status=status, allowed=allowed):
                mutated = copy.deepcopy(self.manifest)
                mutated["status"] = status
                mutated["network_operations_permitted"] = allowed
                self.assertTrue(validate_hold_manifest(mutated))

    def test_mutated_proof_and_missing_requirement_fail_closed(self):
        import copy
        for operation in ("mark_verified", "remove", "duplicate", "blank_owner"):
            with self.subTest(operation=operation):
                mutated = copy.deepcopy(self.manifest)
                entries = mutated["requirements"]
                if operation == "mark_verified":
                    entries[0]["state"] = "verified"
                elif operation == "remove":
                    entries.pop()
                elif operation == "duplicate":
                    entries.append(copy.deepcopy(entries[0]))
                else:
                    entries[0]["owner"] = "  "
                self.assertTrue(validate_hold_manifest(mutated))

    def test_invalid_manifest_shapes_fail_closed(self):
        import copy
        for invalid in (None, [], "", 1, {"requirements": "invalid"},
                        {"requirements": [None]}, {"requirements": [{"id": 4}]}):
            with self.subTest(value=repr(invalid)):
                self.assertTrue(validate_hold_manifest(invalid))

    def test_schema_version_and_critical_fields_cannot_be_dropped(self):
        import copy
        for key, value in (("schema_version", True), ("schema_version", 2),
                           ("release_gate", None), ("activation_rule", None)):
            with self.subTest(key=key, value=value):
                candidate = copy.deepcopy(self.manifest)
                candidate[key] = value
                self.assertTrue(validate_hold_manifest(candidate))

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
