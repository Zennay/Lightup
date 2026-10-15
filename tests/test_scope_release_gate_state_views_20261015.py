"""Non-authorizing per-gate output contract with synthetic-only data."""
from pathlib import Path
import json
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_release_dependency_inventory_20261015 import GATES, FLAGS, assess, InvalidPacket
from scope_release_dependency_nl_20261015 import STATUS_NL, EXPLANATIONS, summarize

SCRIPT = ROOT / "scripts" / "scope_release_dependency_inventory_20261015.py"
NL_SCRIPT = ROOT / "scripts" / "scope_release_dependency_nl_20261015.py"
STATES = ("MISSING", "BLOCKED", "SELF_REPORTED")


def make_packet(states):
    return json.dumps({"schema": 1, "checks": states}, ensure_ascii=True).encode()


class GateStateViewsTests(unittest.TestCase):
    def check_held(self, payload):
        result = assess(payload)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["provenance"], "SELF_ASSERTED_UNVERIFIED")
        for key in FLAGS:
            self.assertIs(result[key], False)
        return result

    def test_every_input_status_is_visible_only_as_fixed_value(self):
        for state in STATES:
            result = self.check_held(make_packet({gate: state for gate in GATES}))
            self.assertEqual(list(result["gate_states"]), list(GATES))
            self.assertEqual(list(result["gate_states"].values()), [state] * len(GATES))

    def test_distinguish_missing_blocked_and_unverified_claim(self):
        states = {gate: STATES[index % 3] for index, gate in enumerate(GATES)}
        result = self.check_held(make_packet(states))
        self.assertEqual(result["gate_states"], states)
        self.assertEqual(result["self_reported_count"], 3)
        self.assertEqual(len(result["needs_attention"]), 6)

    def test_dutch_friendly_states_match_only_hardcoded_vocabulary(self):
        states = {gate: STATES[index % 3] for index, gate in enumerate(GATES)}
        report = summarize(make_packet(states))
        for gate in GATES:
            label, _ = EXPLANATIONS[gate]
            self.assertIn(label + " — " + STATUS_NL[states[gate]], report)
        self.assertIn("NIET TOEGESTAAN", report)
        self.assertIn("Vrijgave: NEE", report)
        self.assertNotIn("TOEGESTAAN\n\nStatus: PASS", report)

    def test_invalid_input_has_no_claimed_gate_progress(self):
        proc = subprocess.run([sys.executable, str(SCRIPT)], input=b"not-json",
                              capture_output=True, timeout=5)
        self.assertEqual(proc.returncode, 2)
        result = json.loads(proc.stdout)
        self.assertEqual(result["gate_states"], {g: "UNKNOWN" for g in GATES})
        self.assertEqual(result["self_reported_count"], 0)
        self.assertTrue(all(result[k] is False for k in FLAGS))

    def test_invalid_dutch_report_uses_only_unknown(self):
        report = summarize(b'{"schema":1,"checks":{}}')
        self.assertIn("Niet controleerbaar", report)
        self.assertEqual(report.count("Niet controleerbaar"), len(GATES))
        self.assertNotIn("Alleen zelf gemeld", report)

    def test_client_claim_never_becomes_approved(self):
        report = summarize(make_packet({g: "SELF_REPORTED" for g in GATES}))
        self.assertEqual(report.count("Alleen zelf gemeld"), len(GATES))
        self.assertIn("geen verifieerbaar bewijs", report)
        self.assertIn("Vrijgave: NEE", report)

    def test_order_invariance(self):
        states = {gate: STATES[i % 3] for i, gate in enumerate(GATES)}
        backwards = dict(reversed(tuple(states.items())))
        self.assertEqual(self.check_held(make_packet(states)),
                         self.check_held(make_packet(backwards)))
        self.assertEqual(summarize(make_packet(states)), summarize(make_packet(backwards)))

    def test_status_injection_rejected_before_rendering(self):
        for fake in ("SELF_REPORTED\n# ALLOWED", "PASS", "<script>", "Zelf gemeld", 1, True):
            states = {gate: "MISSING" for gate in GATES}
            states[GATES[2]] = fake
            payload = make_packet(states)
            with self.subTest(fake=str(fake)):
                with self.assertRaises(InvalidPacket):
                    assess(payload)
                text = summarize(payload)
                self.assertIn("Niet controleerbaar", text)
                self.assertNotIn("# ALLOWED", text)
                self.assertNotIn("<script>", text)

    def test_cli_receipts_agree_with_pure_statuses(self):
        raw = make_packet({gate: "BLOCKED" for gate in GATES})
        for script in (SCRIPT, NL_SCRIPT):
            proc = subprocess.run([sys.executable, str(script)], input=raw,
                                  capture_output=True, timeout=5)
            self.assertEqual(proc.returncode, 2)
            self.assertFalse(proc.stderr)
            self.assertIn(b"HOLD", proc.stdout.upper())
        receipt = subprocess.run([sys.executable, str(SCRIPT)], input=raw,
                                 capture_output=True, timeout=5)
        self.assertEqual(json.loads(receipt.stdout)["gate_states"],
                         {g: "BLOCKED" for g in GATES})


if __name__ == "__main__":
    unittest.main()
