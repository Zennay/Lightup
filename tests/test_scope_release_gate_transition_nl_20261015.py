"""Dutch transition report checks with synthetic streams only."""
from __future__ import annotations
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_release_dependency_inventory_20261015 import GATES
from scope_release_gate_transition_nl_20261015 import LABELS, summarize

SCRIPT = ROOT / "scripts" / "scope_release_gate_transition_nl_20261015.py"
TRANSITIONS = (
    ("MISSING", "MISSING", "UNCHANGED"),
    ("MISSING", "BLOCKED", "NEW_BLOCKER"),
    ("MISSING", "SELF_REPORTED", "NEW_UNVERIFIED_CLAIM"),
    ("BLOCKED", "MISSING", "BLOCKER_REMOVED_UNVERIFIED"),
    ("BLOCKED", "BLOCKED", "UNCHANGED"),
    ("BLOCKED", "SELF_REPORTED", "NEW_UNVERIFIED_CLAIM"),
    ("SELF_REPORTED", "MISSING", "CLAIM_WITHDRAWN"),
    ("SELF_REPORTED", "BLOCKED", "CLAIM_WITHDRAWN_AND_BLOCKED"),
    ("SELF_REPORTED", "SELF_REPORTED", "UNCHANGED"),
)


def payload(before, after):
    return json.dumps({"schema":1,
       "previous":{"schema":1,"checks":{g:before for g in GATES}},
       "current":{"schema":1,"checks":{g:after for g in GATES}}}).encode()


class DutchTransitionTests(unittest.TestCase):
    def cli(self, raw):
        r = subprocess.run([sys.executable, str(SCRIPT)], input=raw,
                           capture_output=True, check=False, timeout=5)
        self.assertEqual(r.returncode, 2)
        self.assertFalse(r.stderr)
        return r.stdout.decode()

    def assert_hold(self, report):
        self.assertIn("Uitkomst: HOLD", report)
        self.assertIn("Vrijgave: NEE", report)
        self.assertIn("GEEN VRIJGAVE", report)
        self.assertNotIn("Vrijgave: JA", report)

    def test_every_exact_status_transition_has_plain_dutch_description(self):
        self.assertEqual(set(LABELS), {row[2] for row in TRANSITIONS})
        for old, new, transition in TRANSITIONS:
            with self.subTest(old=old, new=new):
                output = self.cli(payload(old, new))
                self.assert_hold(output)
                self.assertIn(LABELS[transition], output)

    def test_all_nine_gates_appear_even_when_unchanged(self):
        output = self.cli(payload("MISSING", "MISSING"))
        self.assert_hold(output)
        self.assertEqual(output.count("Geen verandering in zelfrapportage"), len(GATES))
        self.assertIn("0 van 9", output)

    def test_all_self_reports_never_count_as_release_evidence(self):
        output = self.cli(payload("SELF_REPORTED", "SELF_REPORTED"))
        self.assert_hold(output)
        self.assertIn("9 van 9", output)
        self.assertIn("Zelfrapportage is geen onafhankelijke autorisatie", output)

    def test_claims_withdrawn_are_visible_in_plain_language(self):
        output = self.cli(payload("SELF_REPORTED", "BLOCKED"))
        self.assert_hold(output)
        self.assertEqual(output.count("Zelfrapportage ingetrokken en als geblokkeerd gemeld"), len(GATES))
        self.assertIn("9 van 9", output)
        self.assertIn("0 van 9", output)

    def test_report_has_no_arbitrary_fields_or_user_claims(self):
        value = json.loads(payload("MISSING","BLOCKED"))
        secret = "FICTIVE_SECRET_SCOPE_TOKEN_17423"
        value["current"]["private_comment"] = secret
        output = self.cli(json.dumps(value).encode())
        self.assert_hold(output)
        self.assertNotIn(secret, output)
        self.assertIn("Niet controleerbaar", output)

    def test_invalid_data_yields_zero_claims_and_no_per_gate_transition(self):
        for malformed in (b"", b"null", b"{}", b"[]", b"{", b"\xff",
                          b" "*8193, b'{"schema":1,"schema":1}'):
            with self.subTest(malformed=malformed[:24]):
                output = self.cli(malformed)
                self.assert_hold(output)
                self.assertIn("Er is geen eerdere of huidige voortgang vastgesteld", output)
                self.assertNotIn("Vorige zelfgerapporteerde voorwaarden:", output)
                self.assertNotIn("Huidige zelfgerapporteerde voorwaarden:", output)
                self.assertEqual(output.count("Niet controleerbaar"), len(GATES))

    def test_reordered_gate_input_is_output_identical(self):
        doc = json.loads(payload("MISSING","BLOCKED"))
        doc["previous"]["checks"] = dict(reversed(list(doc["previous"]["checks"].items())))
        doc["current"]["checks"] = dict(reversed(list(doc["current"]["checks"].items())))
        self.assertEqual(self.cli(json.dumps(doc).encode()),
                         self.cli(payload("MISSING","BLOCKED")))

    def test_invalid_status_markup_never_appears_in_dutch_output(self):
        doc = json.loads(payload("MISSING","BLOCKED"))
        doc["current"]["checks"][GATES[0]] = "MISSING\n# APPROVED"
        out = self.cli(json.dumps(doc).encode())
        self.assert_hold(out)
        self.assertNotIn("# APPROVED", out)

    def test_dependent_gate_names_have_fixed_order(self):
        text = self.cli(payload("BLOCKED","MISSING"))
        positions = [text.index(g) for g in (
            "Toestemming van de klant", "Actuele toestemming en intrekking",
            "Bewijs vóór een actie", "Tests op de echte VPS-runner",
            "Expliciet besluit door een mens")]
        self.assertEqual(positions, sorted(positions))

    def test_local_socket_stream_is_denied_as_incomplete(self):
        left, right = socket.socketpair()
        try:
            r = subprocess.run([sys.executable, str(SCRIPT)], stdin=left,
                               capture_output=True, timeout=5)
            self.assertEqual(r.returncode, 2)
            self.assertFalse(r.stderr)
            text = r.stdout.decode()
            self.assert_hold(text)
            self.assertIn("Niet controleerbaar", text)
        finally:
            left.close()
            right.close()

    def test_cannot_use_all_claimed_as_approval(self):
        text = summarize(payload("MISSING","SELF_REPORTED"))
        self.assert_hold(text)
        self.assertIn("geen onafhankelijke autorisatie", text)
        self.assertEqual(text.count("Nieuw uitsluitend zelf als aanwezig gemeld"), len(GATES))

    def test_exact_names_match_nine_gate_catalog(self):
        from scope_release_dependency_nl_20261015 import EXPLANATIONS
        report = summarize(payload("MISSING","BLOCKED"))
        for label, _ in EXPLANATIONS.values():
            self.assertEqual(report.count("**"+label+":"), 1)


if __name__ == "__main__":
    unittest.main()
