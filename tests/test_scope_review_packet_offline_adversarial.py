"""Untrusted packet mutation and local-resource canaries (offline only)."""
import importlib.util
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_scope_review_packet_offline.py"
spec = importlib.util.spec_from_file_location("scope_packet_for_adversarial", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def sample():
    return {
        "schema_version": 1,
        "request_id": "req_123", "tenant_id": "tenant_456", "asset_id": "asset_789",
        "requester_id": "user_111", "authorization_reference": "AUTH-123",
        "scope_reference": "SCOPE-123", "requested_mode": "TARGET_ACTIVE", "risk_level": 3,
        "requested_capabilities": ["http_headers", "tls_baseline"],
        "review_evidence_digests": ["a" * 64, "b" * 64],
        "window_start": "2026-10-20T11:00:00Z", "window_end": "2026-10-20T12:00:00Z",
    }


class AdversarialScopeReviewPacketTests(unittest.TestCase):
    def assertNoAuthority(self, result):
        self.assertIn(result["state"], ("REVIEW_ONLY", "HOLD"))
        self.assertTrue(result["non_authorizing"])
        for key in gate.AUTHORITY_FLAGS:
            self.assertIs(result[key], False)
        self.assertEqual(set(result), {"state", "reason", "non_authorizing", *gate.AUTHORITY_FLAGS})

    def test_all_mode_risk_crossproduct_never_authorizes(self):
        for mode in gate.MODES:
            for risk in (-1, 0, 1, 2, 3, 4, 5, 6):
                p = sample(); p["requested_mode"] = mode; p["risk_level"] = risk
                if mode in ("ANALYSIS_ONLY", "PASSIVE_PUBLIC"):
                    p["requested_capabilities"] = ["future_simulation"]
                result = gate.evaluate(json.dumps(p).encode())
                with self.subTest(mode=mode, risk=risk):
                    self.assertNoAuthority(result)
                    if risk not in gate.MODES[mode]:
                        self.assertEqual("HOLD", result["state"])

    def test_fake_authority_claims_cannot_cross_intake(self):
        for claim in ("operator_approved", "target_grant_issued", "authorization_verified", "release_approved", "live_grant", "permit_issued"):
            p = sample(); p[claim] = True
            with self.subTest(claim=claim):
                result = gate.evaluate(json.dumps(p).encode())
                self.assertEqual("HOLD", result["state"])
                self.assertNoAuthority(result)

    def test_deterministic_json_fuzz_never_unhandled(self):
        rand = random.Random(1316)
        alphabet = '{}[]":, \\abcdefghijklmnopqrstuvwxyz0123456789\n\t'
        for i in range(400):
            raw = ''.join(rand.choice(alphabet) for _ in range(rand.randrange(0, 256))).encode()
            with self.subTest(index=i):
                self.assertNoAuthority(gate.evaluate(raw))

    def test_recursive_and_nonfinite_exponent_inputs_hold(self):
        for raw in (b'[' * 1400 + b'0' + b']' * 1400, b'{"risk_level":1e999}', b'{"risk_level":-1e999}', b'"\\ud800"'):
            self.assertEqual("HOLD", gate.evaluate(raw)["state"])
            self.assertNoAuthority(gate.evaluate(raw))

    def test_bytearray_and_string_input_hold(self):
        raw = json.dumps(sample()).encode()
        for value in (bytearray(raw), memoryview(raw), raw.decode(), None, True):
            self.assertEqual("HOLD", gate.evaluate(value)["state"])
            self.assertNoAuthority(gate.evaluate(value))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX named-pipe primitive")
    def test_named_pipe_is_nonblocking_hold(self):
        with tempfile.TemporaryDirectory() as d:
            fifo = Path(d) / "pipe.json"
            os.mkfifo(fifo)
            job = subprocess.run([sys.executable, str(SCRIPT), str(fifo)], capture_output=True, text=True, timeout=4)
            self.assertEqual(2, job.returncode)
            result = json.loads(job.stdout)
            self.assertEqual(("HOLD", "NOT_REGULAR_FILE"), (result["state"], result["reason"]))
            self.assertNoAuthority(result)

    def test_no_secret_content_in_shape_receipt(self):
        p = sample()
        for text in ("CUSTOMER_SECRET", "password", "127.0.0.1", "token"):
            p["authorization_reference"] = text + "\nINVALID"
            result = gate.evaluate(json.dumps(p).encode())
            wire = json.dumps(result)
            self.assertNotIn(text, wire)
            self.assertNoAuthority(result)

    def test_length_edge_rejects_payload_over_16k(self):
        p = sample()
        p["request_id"] = "r" + "a" * gate.MAX_BYTES
        r = gate.evaluate(json.dumps(p).encode())
        self.assertEqual("SIZE_LIMIT", r["reason"])
        self.assertNoAuthority(r)


if __name__ == "__main__":
    unittest.main()
