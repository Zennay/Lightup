"""Synthetic release-gate transition tests; no customer targets or grants."""
from __future__ import annotations

import itertools
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_release_dependency_inventory_20261015 import GATES, FLAGS, InvalidPacket
from scope_release_gate_transition_20261015 import TRANSITIONS, compare

SCRIPT = ROOT / "scripts" / "scope_release_gate_transition_20261015.py"
STATES = ("MISSING", "BLOCKED", "SELF_REPORTED")


def packet(status="MISSING"):
    return {"schema": 1, "checks": {gate: status for gate in GATES}}


def envelope(previous=None, current=None):
    return {"schema": 1, "previous": previous or packet(), "current": current or packet()}


def json_bytes(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False).encode("ascii")


class GateTransitionTests(unittest.TestCase):
    def assert_hold(self, result):
        self.assertEqual(result["status"], "HOLD")
        self.assertIn(result["provenance"], ("UNVERIFIED", "SELF_ASSERTED_UNVERIFIED"))
        for name in FLAGS:
            self.assertIs(result[name], False)

    def cli(self, raw):
        proc = subprocess.run([sys.executable, str(SCRIPT)], input=raw,
                              capture_output=True, check=False, timeout=5)
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(proc.stderr)
        result = json.loads(proc.stdout)
        self.assert_hold(result)
        return result

    def test_all_nine_transition_pairs_are_exhaustively_bounded(self):
        self.assertEqual(len(TRANSITIONS), 9)
        for old, new in itertools.product(STATES, repeat=2):
            with self.subTest(before=old, after=new):
                result = compare(json_bytes(envelope(packet(old), packet(new))))
                self.assert_hold(result)
                expected = 0 if old == new else len(GATES)
                self.assertEqual(len(result["changes"]), expected)
                self.assertEqual(result["unchanged_count"], len(GATES) - expected)
                for item in result["changes"]:
                    self.assertEqual(item["transition"], TRANSITIONS[old, new])

    def test_unverified_self_reports_are_not_evidence_of_readiness(self):
        result = self.cli(json_bytes(envelope(packet(), packet("SELF_REPORTED"))))
        self.assertEqual(len(result["new_unverified_claims"]), len(GATES))
        self.assertEqual(result["current_self_reported"], len(GATES))
        self.assertEqual(result["status"], "HOLD")
        self.assertNotIn("READY", json.dumps(result))

    def test_withdrawn_self_claims_are_explicit(self):
        result = self.cli(json_bytes(envelope(packet("SELF_REPORTED"), packet())))
        self.assertEqual(result["withdrawn_claims"], list(GATES))
        self.assertEqual(result["new_blockers"], [])
        self.assertEqual(result["new_unverified_claims"], [])
        self.assertEqual(result["current_self_reported"], 0)

    def test_new_blocks_and_withdrawals_cannot_be_silently_hidden(self):
        result = self.cli(json_bytes(envelope(packet("SELF_REPORTED"), packet("BLOCKED"))))
        self.assertEqual(result["new_blockers"], list(GATES))
        self.assertEqual(result["withdrawn_claims"], list(GATES))
        self.assertTrue(all(c["transition"] == "CLAIM_WITHDRAWN_AND_BLOCKED"
                            for c in result["changes"]))

    def test_blocker_to_missing_is_not_considered_authorized(self):
        result = self.cli(json_bytes(envelope(packet("BLOCKED"), packet("MISSING"))))
        self.assertEqual(result["current_self_reported"], 0)
        self.assertEqual(result["new_blockers"], [])
        self.assertEqual(result["new_unverified_claims"], [])
        self.assertTrue(all(x["transition"] == "BLOCKER_REMOVED_UNVERIFIED"
                            for x in result["changes"]))

    def test_mixed_transitions_are_canonical_and_atomic(self):
        old, new = packet(), packet()
        old["checks"][GATES[0]] = "SELF_REPORTED"
        new["checks"][GATES[0]] = "BLOCKED"
        new["checks"][GATES[1]] = "SELF_REPORTED"
        new["checks"][GATES[2]] = "BLOCKED"
        new["checks"] = dict(reversed(tuple(new["checks"].items())))
        result = self.cli(json_bytes(envelope(old, new)))
        self.assertEqual([x["gate"] for x in result["changes"]], list(GATES[:3]))
        self.assertEqual(result["withdrawn_claims"], [GATES[0]])
        self.assertEqual(result["new_blockers"], [GATES[0], GATES[2]])
        self.assertEqual(result["new_unverified_claims"], [GATES[1]])
        self.assertEqual(result["unchanged_count"], len(GATES)-3)

    def test_no_diffs_still_means_no_release(self):
        for state in STATES:
            with self.subTest(state=state):
                result = self.cli(json_bytes(envelope(packet(state), packet(state))))
                self.assertEqual(result["changes"], [])
                self.assertEqual(result["unchanged_count"], len(GATES))
                self.assertEqual(result["status"], "HOLD")

    def test_root_and_nested_duplicate_keys_are_refused(self):
        bad = [
            b'{"schema":1,"schema":1,"previous":{},"current":{}}',
            b'{"schema":1,"previous":{"schema":1,"schema":1,"checks":{}},"current":{}}',
            b'{"schema":1,"previous":{"schema":1,"checks":{"client_consent":"MISSING","client_consent":"BLOCKED"}},"current":{}}',
            b'{"schema":1,"previous":{},"current":{},"current":{}}',
        ]
        for item in bad:
            with self.subTest(data=item[:30]):
                self.assertEqual(self.cli(item)["reason_code"], "INVALID_OR_INCOMPLETE_COMPARISON")
                with self.assertRaises(InvalidPacket):
                    compare(item)

    def test_wrong_schema_unknown_root_and_missing_snapshot_denied(self):
        for obj in (
            {"schema": True, "previous": packet(), "current": packet()},
            {"schema": 2, "previous": packet(), "current": packet()},
            {"schema": "1", "previous": packet(), "current": packet()},
            {"schema": 1, "previous": packet()},
            {"schema": 1, "previous": packet(), "current": packet(), "grant": True},
            {"schema": 1, "previous": [], "current": packet()},
            {"schema": 1, "previous": packet(), "current": "MISSING"},
        ):
            with self.subTest(obj=repr(obj)[:70]):
                self.assertEqual(self.cli(json_bytes(obj))["changes"], [])

    def test_invalid_either_snapshot_rejects_both_atomically(self):
        for side in ("previous", "current"):
            for value in (True, 1, "PASS", "SELF_REPORTED\nAPPROVED", {}, []):
                obj = envelope()
                if isinstance(value, dict):
                    obj[side]["checks"] = {}
                elif isinstance(value, list):
                    obj[side]["checks"] = []
                else:
                    obj[side]["checks"][GATES[4]] = value
                with self.subTest(side=side, type=type(value).__name__):
                    result = self.cli(json_bytes(obj))
                    self.assertEqual(result["changes"], [])
                    self.assertEqual(result["previous_self_reported"], 0)
                    self.assertEqual(result["current_self_reported"], 0)

    def test_reject_invalid_encoding_and_excessive_size(self):
        for raw in (b"", b"{", b"null", b"[]", b"\xff",
                    b"\xef\xbb\xbf"+json_bytes(envelope()),
                    b" " * 8193, json_bytes(envelope()) + b"{}",
                    b'{"schema":NaN,"previous":{},"current":{}}',
                    b'{"schema":Infinity,"previous":{},"current":{}}'):
            with self.subTest(raw=raw[:22]):
                self.assertEqual(self.cli(raw)["reason_code"], "INVALID_OR_INCOMPLETE_COMPARISON")

    def test_invalid_bytes_subclass_rejected(self):
        class FakeBytes(bytes):
            pass
        with self.assertRaises(InvalidPacket):
            compare(FakeBytes(json_bytes(envelope())))

    def test_input_text_and_secret_cannot_be_reflected(self):
        secret = "FAKE_SECRET_APPROVAL_CANARY_40549"
        obj = envelope()
        obj["current"]["sensitive"] = secret
        proc = subprocess.run([sys.executable, str(SCRIPT)], input=json_bytes(obj),
                              capture_output=True, timeout=5)
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn(secret.encode(), proc.stdout + proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["status"], "HOLD")

    def test_status_output_has_only_fixed_identifiers(self):
        old, new = packet(), packet()
        old["checks"][GATES[0]] = "SELF_REPORTED"
        new["checks"][GATES[0]] = "BLOCKED"
        result = self.cli(json_bytes(envelope(old, new)))
        self.assertEqual({x["gate"] for x in result["changes"]}, {GATES[0]})
        self.assertTrue(all(set(x) == {"gate","previous","current","transition"}
                            for x in result["changes"]))

    def test_reversing_pair_reverses_claim_changes_not_authority(self):
        old, new = packet("MISSING"), packet("SELF_REPORTED")
        a = self.cli(json_bytes(envelope(old, new)))
        b = self.cli(json_bytes(envelope(new, old)))
        self.assertEqual(a["new_unverified_claims"], list(GATES))
        self.assertEqual(b["withdrawn_claims"], list(GATES))
        self.assertTrue(all(not a[k] and not b[k] for k in FLAGS))

    def test_cli_rejects_unclosed_complete_pipe_with_deadline(self):
        p = subprocess.Popen([sys.executable, str(SCRIPT)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            p.stdin.write(json_bytes(envelope()))
            p.stdin.flush()
            p.wait(timeout=6)
            self.assertEqual(p.returncode, 2)
            self.assertEqual(p.stderr.read(), b"")
            self.assertEqual(json.loads(p.stdout.read())["reason_code"],
                             "INVALID_OR_INCOMPLETE_COMPARISON")
        finally:
            p.stdin.close()
            p.stdout.close()
            p.stderr.close()
            if p.poll() is None:
                p.kill()
                p.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
