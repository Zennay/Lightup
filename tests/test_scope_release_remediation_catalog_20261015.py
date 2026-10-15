"""Test fixed owner/evidence handoffs without authenticating any user claim."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from scope_release_dependency_inventory_20261015 import GATES, FLAGS, assess
from scope_release_dependency_nl_20261015 import summarize as inventory_nl
from scope_release_gate_transition_20261015 import compare
from scope_release_gate_transition_nl_20261015 import summarize as transition_nl
from scope_release_remediation_catalog_20261015 import CATALOG, remediation

INVENTORY = ROOT / "scripts" / "scope_release_dependency_nl_20261015.py"
TRANSITION = ROOT / "scripts" / "scope_release_gate_transition_nl_20261015.py"

def single(status="MISSING"):
    return json.dumps({"schema": 1, "checks": {g: status for g in GATES}}).encode()

def pair(before="MISSING", after="BLOCKED"):
    old = {"schema": 1, "checks": {g: before for g in GATES}}
    new = {"schema": 1, "checks": {g: after for g in GATES}}
    return json.dumps({"schema": 1, "previous": old, "current": new}).encode()


class RemediationCatalogTests(unittest.TestCase):
    def assert_no_release(self, text):
        self.assertIn("Vrijgave: NEE", text)
        self.assertNotIn("Vrijgave: JA", text)
        self.assertNotIn("scan_allowed: true", text.lower())

    def test_all_nine_gates_are_covered_in_canonical_order(self):
        self.assertEqual(tuple(CATALOG), GATES)
        self.assertEqual(len(CATALOG), 9)

    def test_all_fields_are_fixed_nonempty_printable_strings(self):
        for gate in GATES:
            with self.subTest(gate=gate):
                guide = remediation(gate)
                self.assertEqual(len(guide), 5)
                for field in guide:
                    self.assertIs(type(field), str)
                    self.assertEqual(field, field.strip())
                    self.assertGreater(len(field), 12)
                    self.assertNotIn("\n", field)
                    self.assertNotIn("\r", field)
                    self.assertNotIn("<script", field.lower())

    def test_only_known_owner_role_boundaries(self):
        self.assertEqual(
            {guide.owner_boundary for guide in CATALOG.values()},
            {"EXTERNAL_HUMAN", "OTHER_SOURCE_OWNER",
             "OTHER_SOURCE_OWNER_AND_HUMAN", "OTHER_INFRA_OWNER",
             "EXTERNAL_REVIEWER"})

    def test_real_source_owner_handoffs_are_descriptive_not_claimed_fixed(self):
        for gate, marker in (
            ("live_grant_and_revocation", "#107"),
            ("operator_step_up", "#1172/#1173"),
            ("durable_prehandler_evidence", "#1454/#1455"),
            ("permanent_vps_ci", "#1144"),
        ):
            with self.subTest(gate=gate):
                guide = remediation(gate)
                self.assertIn(marker, guide.owner_role)
                self.assertTrue(guide.reason_not_lifted)
                self.assertFalse(guide.owner_boundary == "EXTERNAL_HUMAN")

    def test_human_release_and_consent_not_self_attestable(self):
        for gate in ("client_consent", "asset_and_capability_scope",
                     "independent_security_privacy_review",
                     "explicit_human_release"):
            with self.subTest(gate=gate):
                guide = remediation(gate)
                self.assertIn(guide.owner_boundary,
                              ("EXTERNAL_HUMAN", "EXTERNAL_REVIEWER"))
                self.assertIn("onafhankelijk", guide.acceptance_evidence.lower()
                              + guide.concrete_action.lower()
                              + guide.reason_not_lifted.lower())

    def test_remediation_rejects_unknown_and_polymorphic_keys(self):
        class GateSubclass(str):
            pass
        for key in (None, b"client_consent", True, 1, "",
                    "client_consent\nGO", GateSubclass("client_consent")):
            with self.subTest(value=repr(key)):
                with self.assertRaises(ValueError):
                    remediation(key)

    def test_inventory_all_missing_shows_owner_action_and_evidence(self):
        text = inventory_nl(single())
        self.assert_no_release(text)
        self.assertEqual(text.count("Verantwoordelijke:"), len(GATES))
        self.assertEqual(text.count("Eerst oplossen:"), len(GATES))
        self.assertEqual(text.count("Onafhankelijk bewijs nodig:"), len(GATES))
        self.assertEqual(text.count("Waarom nog niet vrij:"), len(GATES))

    def test_inventory_all_claimed_still_lists_every_unresolved_owner(self):
        text = inventory_nl(single("SELF_REPORTED"))
        self.assert_no_release(text)
        self.assertIn("9 van 9", text)
        self.assertEqual(text.count("Waarom nog niet vrij:"), len(GATES))
        for gate in GATES:
            self.assertIn(remediation(gate).concrete_action, text)

    def test_invalid_inventory_does_not_drop_requirements(self):
        text = inventory_nl(b'{"schema":1,"checks":{}}')
        self.assert_no_release(text)
        self.assertIn("ongeldig of onvolledig", text)
        for gate in GATES:
            self.assertIn(remediation(gate).acceptance_evidence, text)

    def test_transition_changed_gates_still_list_every_owner(self):
        text = transition_nl(pair("BLOCKED", "SELF_REPORTED"))
        self.assert_no_release(text)
        self.assertIn("9 van 9", text)
        self.assertEqual(text.count("Verantwoordelijke:"), len(GATES))
        self.assertEqual(text.count("Bewijs nodig:"), len(GATES))
        self.assertEqual(text.count("Waarom niet vanuit deze review:"), len(GATES))

    def test_transition_unchanged_claims_have_same_remediation(self):
        text = transition_nl(pair("SELF_REPORTED", "SELF_REPORTED"))
        self.assert_no_release(text)
        self.assertEqual(text.count("Eerst oplossen:"), len(GATES))
        for gate in GATES:
            self.assertIn(remediation(gate).reason_not_lifted, text)

    def test_transition_invalid_both_atomic_and_all_gates_explicit(self):
        text = transition_nl(b'invalid')
        self.assert_no_release(text)
        self.assertEqual(text.count("Niet controleerbaar"), len(GATES))
        self.assertEqual(text.count("Verantwoordelijke:"), len(GATES))
        self.assertNotIn("Huidige zelfgerapporteerde voorwaarden:", text)

    def test_machine_permission_flags_never_change_due_to_dutch_remediation(self):
        a = assess(single("SELF_REPORTED"))
        b = compare(pair("SELF_REPORTED", "SELF_REPORTED"))
        self.assertTrue(all(a[x] is False and b[x] is False for x in FLAGS))
        self.assert_no_release(inventory_nl(single("SELF_REPORTED")))
        self.assert_no_release(transition_nl(pair("SELF_REPORTED", "SELF_REPORTED")))

    def test_cli_status_and_stderr_are_fixed_on_both_tools(self):
        for script, raw in (
            (INVENTORY, single("SELF_REPORTED")),
            (TRANSITION, pair("MISSING", "SELF_REPORTED")),
            (INVENTORY, b'no-json'),
            (TRANSITION, b'no-json'),
        ):
            with self.subTest(script=script.name, length=len(raw)):
                proc = subprocess.run([sys.executable, str(script)], input=raw,
                                      capture_output=True, timeout=6)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stderr, b"")
                self.assert_no_release(proc.stdout.decode())

    def test_extra_secret_claim_in_both_formats_is_not_echoed(self):
        secret = "SECRET_PSEUDO_CLIENT_APPROVAL_6047"
        a = json.loads(single())
        a["client_name"] = secret
        b = json.loads(pair())
        b["previous"]["client_name"] = secret
        for output in (inventory_nl(json.dumps(a).encode()),
                       transition_nl(json.dumps(b).encode())):
            self.assert_no_release(output)
            self.assertNotIn(secret, output)

    def test_checked_in_fictional_examples_never_show_release_go(self):
        inventory = (ROOT / "docs/fixtures/scope-release-fictional-packet-20261015.json").read_bytes()
        transition = (ROOT / "docs/fixtures/scope-release-fictional-transition-20261015.json").read_bytes()
        for output in (inventory_nl(inventory), transition_nl(transition)):
            self.assert_no_release(output)
            self.assertEqual(output.count("Verantwoordelijke:"), len(GATES))

    def test_no_catalog_record_says_we_can_authorize_locally(self):
        dangerous = ("nu geautoriseerd", "vrijgave toegestaan", "deployment toegestaan",
                     "grant verleend", "scan toegestaan")
        for guide in CATALOG.values():
            text = " ".join(guide).lower()
            for phrase in dangerous:
                self.assertNotIn(phrase, text)


    def test_catalog_cannot_be_rewritten_by_importing_review_code(self):
        with self.assertRaises(TypeError):
            CATALOG["client_consent"] = remediation("explicit_human_release")
        with self.assertRaises(TypeError):
            del CATALOG["operator_step_up"]
        with self.assertRaises(AttributeError):
            remediation("client_consent").owner_role = "ANY_WORKER"
        self.assertEqual(tuple(CATALOG), GATES)

    def test_optimized_python_cannot_skip_coverage_guard(self):
        # A missing gate must never silently disappear when Python runs with -O.
        script = ROOT / "scripts" / "scope_release_remediation_catalog_20261015.py"
        text = script.read_text()
        self.assertIn("if tuple(CATALOG) != GATES:", text)
        self.assertNotIn("assert tuple(CATALOG)", text)


if __name__ == "__main__":
    unittest.main()
