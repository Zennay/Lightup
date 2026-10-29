"""Field-level capability drift receipts remain offline and non-authorizing."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from lightup.capabilities import get_capabilities
from lightup.capability_registry_drift_review import review_capability_registry_drift
from scripts.export_scope_capability_registry_offline import snapshot_manifest

ROOT = Path(__file__).resolve().parents[1]
REVIEW_SCRIPT = ROOT / "scripts/review_scope_capability_registry_offline.py"


def cap(ident="web-baseline", state="planning", active=True, name="Web baseline", description="HTTP/TLS review"):
    return {
        "capability_id": ident, "state": state,
        "requires_explicit_activation": active,
        "name": name, "description": description,
    }


def serialize(*records):
    return json.dumps({"capabilities": list(records)}, sort_keys=True).encode()


class RegistryFieldReceiptTests(unittest.TestCase):
    def assert_denied(self, result):
        self.assertEqual(result.status, "HOLD")
        for field in ("authorization_verified", "permit_issued", "execution_enabled", "merge_approved", "release_approved"):
            self.assertIs(result.as_dict()[field], False)

    def test_identical_is_non_authorizing_and_has_empty_details(self):
        raw = serialize(cap())
        result = review_capability_registry_drift(raw, raw)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.changed_fields, ())
        self.assertEqual(result.as_dict()["changed_fields"], {})
        self.assertIs(result.as_dict()["permit_issued"], False)

    def test_added_capability_has_added_only(self):
        result = review_capability_registry_drift(
            serialize(cap()),
            serialize(cap(), cap(ident="api-baseline")),
        )
        self.assert_denied(result)
        self.assertEqual(result.as_dict()["changed_fields"], {"api-baseline": ["added"]})

    def test_removed_capability_has_removed_only(self):
        result = review_capability_registry_drift(
            serialize(cap(), cap(ident="api-baseline")),
            serialize(cap()),
        )
        self.assert_denied(result)
        self.assertEqual(result.as_dict()["changed_fields"], {"api-baseline": ["removed"]})

    def test_state_reclassification_is_exactly_state(self):
        result = review_capability_registry_drift(serialize(cap()), serialize(cap(state="lab_only")))
        self.assert_denied(result)
        self.assertEqual(result.as_dict()["changed_fields"], {"web-baseline": ["state"]})

    def test_explicit_activation_change_is_exactly_flag(self):
        result = review_capability_registry_drift(serialize(cap()), serialize(cap(active=False)))
        self.assert_denied(result)
        self.assertEqual(result.as_dict()["changed_fields"], {"web-baseline": ["requires_explicit_activation"]})

    def test_display_name_change_does_not_echo_values(self):
        result = review_capability_registry_drift(serialize(cap()), serialize(cap(name="Sensitive description marker")))
        self.assert_denied(result)
        self.assertEqual(result.as_dict()["changed_fields"], {"web-baseline": ["name"]})
        self.assertNotIn("Sensitive description marker", json.dumps(result.as_dict()))

    def test_description_change_does_not_echo_values(self):
        result = review_capability_registry_drift(serialize(cap()), serialize(cap(description="Private content marker")))
        self.assert_denied(result)
        self.assertEqual(result.as_dict()["changed_fields"], {"web-baseline": ["description"]})
        self.assertNotIn("Private content marker", json.dumps(result.as_dict()))

    def test_multiple_changes_have_fixed_field_order(self):
        result = review_capability_registry_drift(
            serialize(cap()),
            serialize(cap(state="disabled", active=False, name="Changed name", description="Changed description")),
        )
        self.assert_denied(result)
        self.assertEqual(result.as_dict()["changed_fields"]["web-baseline"], [
            "state", "requires_explicit_activation", "name", "description",
        ])

    def test_capability_ids_are_sorted(self):
        before = serialize(cap("zeta-cap"), cap("alpha-cap"), cap("omega-cap"))
        after = serialize(cap("alpha-cap", active=False), cap("omega-cap", name="Change"), cap("zeta-cap", state="disabled"))
        result = review_capability_registry_drift(before, after)
        self.assert_denied(result)
        self.assertEqual(result.changed_capabilities, ("alpha-cap", "omega-cap", "zeta-cap"))
        self.assertEqual(list(result.as_dict()["changed_fields"]), list(result.changed_capabilities))

    def test_legacy_to_full_metadata_declares_two_fields(self):
        legacy = {k: v for k, v in cap().items() if k not in ("name", "description")}
        result = review_capability_registry_drift(serialize(legacy), serialize(cap()))
        self.assert_denied(result)
        self.assertEqual(result.as_dict()["changed_fields"], {"web-baseline": ["name", "description"]})

    def test_invalid_manifest_has_empty_details_without_leak(self):
        result = review_capability_registry_drift(serialize(cap()), b'{"capabilities":[{"capability_id":"a"}]}')
        self.assert_denied(result)
        self.assertEqual(result.reason, "invalid_manifest")
        self.assertEqual(result.as_dict()["changed_fields"], {})
        self.assertEqual(result.as_dict()["changed_capabilities"], [])

    def test_real_registry_description_metadata_holds(self):
        original = get_capabilities()
        baseline = snapshot_manifest(original)
        new = (replace(original[0], description=original[0].description + " synthetic"),) + original[1:]
        result = review_capability_registry_drift(baseline, snapshot_manifest(new))
        self.assert_denied(result)
        self.assertEqual(result.as_dict()["changed_fields"], {original[0].capability_id: ["description"]})

    def test_read_only_cli_receipt_contains_fields_but_not_text(self):
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder) / "before.json", Path(folder) / "after.json"
            a.write_bytes(serialize(cap()))
            b.write_bytes(serialize(cap(description="Private content marker")))
            run = subprocess.run([sys.executable, str(REVIEW_SCRIPT), str(a), str(b)], text=True, capture_output=True, timeout=15)
            self.assertEqual(run.returncode, 2, run.stderr)
            receipt = json.loads(run.stdout)
            self.assertEqual(receipt["changed_fields"], {"web-baseline": ["description"]})
            self.assertIs(receipt["execution_enabled"], False)
            self.assertNotIn("Private content marker", run.stdout)

    def test_read_only_cli_invalid_identity_has_no_details(self):
        with tempfile.TemporaryDirectory() as folder:
            a = Path(folder) / "same.json"
            a.write_bytes(serialize(cap()))
            run = subprocess.run([sys.executable, str(REVIEW_SCRIPT), str(a), str(a)], text=True, capture_output=True, timeout=15)
            self.assertEqual(run.returncode, 2, run.stderr)
            receipt = json.loads(run.stdout)
            self.assertFalse(receipt.get("changed_fields"))
            self.assertIs(receipt["authorization_verified"], False)


if __name__ == "__main__":
    unittest.main()
