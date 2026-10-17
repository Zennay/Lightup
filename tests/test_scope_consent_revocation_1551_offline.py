"""Offline acceptance for #1551; no production authorization integration."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_consent_revocation_1551_offline.py"
spec = importlib.util.spec_from_file_location("scope1551_offline", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

SHA = "a" * 40
SCOPE = "b" * 64
TIME = "2026-10-17T12:00:00Z"


def packet():
    return {
        "schema_version": 1, "proposal_sha": SHA, "scope_sha256": SCOPE, "review_at": TIME,
        "consents": [
            {"role": "client", "principal": "client:fictional-a", "proposal_sha": SHA, "scope_sha256": SCOPE,
             "issued_at": "2026-10-17T11:50:00Z", "expires_at": "2026-10-17T12:50:00Z", "event_seq": 10},
            {"role": "operator", "principal": "operator:fictional-b", "proposal_sha": SHA, "scope_sha256": SCOPE,
             "issued_at": "2026-10-17T11:52:00Z", "expires_at": "2026-10-17T12:52:00Z", "event_seq": 11},
        ],
        "revocations": [],
    }


def revoke(seq=12, at="2026-10-17T11:55:00Z"):
    return {"role": "client", "principal": "client:fictional-a", "proposal_sha": SHA,
            "scope_sha256": SCOPE, "effective_at": at, "event_seq": seq}


def raw(p):
    return json.dumps(p, separators=(",", ":"), sort_keys=True).encode()


class ConsentRevocationContract(unittest.TestCase):
    def assert_status(self, p, status):
        out = mod.review(raw(p))
        self.assertEqual(status, out["status"], out)
        self.assertEqual(1, out["schema_version"])
        for flag in mod.AUTHORITY_FLAGS:
            self.assertIs(out[flag], False, flag)
        self.assertEqual(set(out), {"schema_version", "status", "reason", *mod.AUTHORITY_FLAGS})

    def test_positive_fictional_pair_only_review(self):
        self.assert_status(packet(), "REVIEW_ONLY")

    def test_never_authorizes_even_on_valid_fixture(self):
        r = mod.review(raw(packet()))
        self.assertEqual("UNAUTHENTICATED_CLAIMS_ONLY", r["reason"])
        self.assertNotIn("allowed", r)
        self.assertNotIn("permit", r)

    def test_exact_schema_versions(self):
        for version in (0, 2, True, "1", 1.0, None):
            with self.subTest(version=version):
                p = packet(); p["schema_version"] = version
                self.assert_status(p, "HOLD")

    def test_root_missing_or_unexpected_keys(self):
        for edit in ("missing", "extra"):
            p = packet()
            if edit == "missing":
                del p["review_at"]
            else:
                p["authorize"] = True
            self.assert_status(p, "HOLD")

    def test_consent_same_role_and_missing_role(self):
        p = packet(); p["consents"][1]["role"] = "client"
        p["consents"][1]["principal"] = "client:fictional-b"
        self.assert_status(p, "HOLD")
        p = packet(); p["consents"] = p["consents"][:1]
        self.assert_status(p, "HOLD")

    def test_principal_canonical_and_distinct(self):
        for principal in ("operator:fictional-a", "client:UPPER", "operator:UPPER",
                          "operator:fictional/a", "operator:𝔞", "operator:", 42, None):
            with self.subTest(principal=principal):
                p = packet(); p["consents"][0]["principal"] = principal
                self.assert_status(p, "HOLD")

    def test_digest_revision_mismatch_or_null(self):
        for field, value in (("proposal_sha", "0"*40), ("proposal_sha", "A"*40),
                             ("proposal_sha", "c"*40), ("scope_sha256", "0"*64),
                             ("scope_sha256", "B"*64), ("scope_sha256", "c"*64)):
            with self.subTest(field=field, value=value[:6]):
                p = packet(); p[field] = value
                self.assert_status(p, "HOLD")

    def test_claim_drift_independently(self):
        for i, field in ((0, "proposal_sha"), (1, "scope_sha256")):
            p = packet()
            p["consents"][i][field] = "c"*(40 if field == "proposal_sha" else 64)
            self.assert_status(p, "HOLD")

    def test_invalid_timestamp_syntax(self):
        for t in ("2026-10-17T12:00:00+00:00", "2026-10-17t12:00:00Z", "2026-02-30T12:00:00Z",
                  "2026-10-17T12:00:00.000Z", "2026-10-17T12:00:60Z", "2026-1-17T12:00:00Z",
                  True, 1234):
            with self.subTest(timestamp=t):
                p = packet(); p["review_at"] = t
                self.assert_status(p, "HOLD")

    def test_expired_not_yet_issued_and_exact_boundary(self):
        for start, end in (("2026-10-17T12:00:01Z", "2026-10-17T12:30:00Z"),
                           ("2026-10-17T11:30:00Z", TIME),
                           (TIME, TIME),
                           ("2026-10-15T00:00:00Z", "2026-10-17T12:10:00Z")):
            with self.subTest(start=start, end=end):
                p = packet(); p["consents"][0]["issued_at"] = start
                p["consents"][0]["expires_at"] = end
                self.assert_status(p, "HOLD")

    def test_consent_skew(self):
        p = packet(); p["consents"][1]["issued_at"] = "2026-10-17T11:33:00Z"
        self.assert_status(p, "HOLD")

    def test_revocation_effective(self):
        p = packet(); p["revocations"] = [revoke()]
        self.assert_status(p, "HOLD")

    def test_revocation_exact_review_time(self):
        p = packet(); p["revocations"] = [revoke(at=TIME)]
        self.assert_status(p, "HOLD")

    def test_future_revocation_is_not_inferred_as_safe(self):
        p = packet(); p["revocations"] = [revoke(at="2026-10-17T12:00:01Z")]
        self.assert_status(p, "HOLD")

    def test_ambiguous_event_sequences(self):
        for seq in (10, 11, True, 0, -1, 65536, 1.5):
            with self.subTest(seq=seq):
                p = packet(); p["revocations"] = [revoke(seq=seq)]
                self.assert_status(p, "HOLD")

    def test_consent_sequence_backdating(self):
        p = packet(); p["consents"][1]["issued_at"] = "2026-10-17T11:49:00Z"
        self.assert_status(p, "HOLD")

    def test_revocation_cross_revision_or_actor(self):
        for field, bad in (("proposal_sha", "c"*40), ("scope_sha256", "c"*64),
                           ("principal", "client:somebodyelse"), ("role", "auditor")):
            p = packet(); event = revoke(); event[field] = bad; p["revocations"] = [event]
            self.assert_status(p, "HOLD")

    def test_revocation_event_count_bound(self):
        p = packet(); p["revocations"] = [revoke(seq=i+100) for i in range(mod.MAX_REVOCATIONS + 1)]
        self.assert_status(p, "HOLD")

    def test_missing_or_extra_nested_field(self):
        for section in ("consents", "revocations"):
            for edit in ("extra", "missing"):
                p = packet()
                if section == "revocations":
                    p[section] = [revoke()]
                event = p[section][0]
                if edit == "extra":
                    event["untrusted_status"] = "approved"
                else:
                    del event["event_seq"]
                self.assert_status(p, "HOLD")

    def test_json_duplicate_fields_and_nonfinite(self):
        good = raw(packet())
        self.assertEqual("HOLD", mod.review(good[:-1] + b',"schema_version":1}')["status"])
        self.assertEqual("HOLD", mod.review(good.replace(b'"schema_version":1', b'"schema_version":NaN'))["status"])
        self.assertEqual("HOLD", mod.review(b'{"__proto__":true}')["status"])

    def test_null_bytes_invalid_utf8_excess_and_byte_subclass(self):
        p = raw(packet())
        for data in (p+b"\0", b"\xff"+p, b"", p+(b" " * mod.MAX_INPUT_BYTES),
                     bytearray(p), memoryview(p)):
            with self.subTest(kind=type(data).__name__, size=len(data)):
                self.assertEqual("HOLD", mod.review(data)["status"])
        class Spoof(bytes):
            def decode(self, *args, **kwargs):
                return json.dumps(packet())
        self.assertEqual("HOLD", mod.review(Spoof(b"invalid"))["status"])

    def test_bounded_fuzz_no_permission(self):
        original = raw(packet())
        for cut in range(0, len(original), 7):
            out = mod.review(original[:cut])
            self.assertEqual("HOLD", out["status"])
            self.assertTrue(all(out[k] is False for k in mod.AUTHORITY_FLAGS))
        for offset in range(0, min(len(original), 250), 11):
            mutated = original[:offset] + b"\xff" + original[offset+1:]
            self.assertEqual("HOLD", mod.review(mutated)["status"])

    def test_real_cli_subprocess_exits_and_output(self):
        for data, expect in ((raw(packet()), 3), (raw({**packet(), "revocations":[revoke()]}), 2),
                             (b"not json", 2), (b"", 2)):
            process = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                                     input=data, capture_output=True, timeout=10)
            self.assertEqual(expect, process.returncode, process.stderr)
            result = json.loads(process.stdout)
            self.assertEqual("REVIEW_ONLY" if expect == 3 else "HOLD", result["status"])
            self.assertTrue(all(result[k] is False for k in mod.AUTHORITY_FLAGS))
            self.assertEqual(b"", process.stderr)

    def test_unknown_cli_flags_atomic_hold(self):
        process = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT), "--authorize"],
                                 input=raw(packet()), capture_output=True, timeout=10)
        self.assertEqual(2, process.returncode)
        self.assertEqual("HOLD", json.loads(process.stdout)["status"])

    def test_no_production_or_network_modules_imported(self):
        source = SCRIPT.read_text("utf-8")
        for forbidden in ("import requests", "import socket", "import subprocess", "from lightup",
                          "AuthorizationGrant(", "ExecutionPermit(", "urllib.request"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
