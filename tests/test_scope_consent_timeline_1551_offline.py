"""Continuity review #1551: no execution authority, no production integration."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_consent_timeline_1551_offline.py"
spec = importlib.util.spec_from_file_location("scope1551_timeline", SCRIPT)
timeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timeline)


def packet(at="2026-10-17T12:00:00Z"):
    sha = "a" * 40
    scope = "b" * 64
    return {
        "schema_version": 1, "proposal_sha": sha, "scope_sha256": scope,
        "review_at": at, "revocations": [],
        "consents": [
            {"role": "client", "principal": "client:example", "proposal_sha": sha,
             "scope_sha256": scope, "issued_at": "2026-10-17T11:50:00Z",
             "expires_at": "2026-10-17T12:50:00Z", "event_seq": 10},
            {"role": "operator", "principal": "operator:example", "proposal_sha": sha,
             "scope_sha256": scope, "issued_at": "2026-10-17T11:52:00Z",
             "expires_at": "2026-10-17T12:52:00Z", "event_seq": 11},
        ],
    }


def make_timeline(n=3):
    entries = []
    for index in range(n):
        p = packet(f"2026-10-17T12:{index:02d}:00Z")
        old = entries[-1] if entries else None
        entries.append({"packet": p, "previous_sha256": timeline.entry_digest(old) if old else None})
    return {"schema_version": 1, "entries": entries}


def raw(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class Timeline(unittest.TestCase):
    def assert_status(self, obj, status):
        output = timeline.review(raw(obj))
        self.assertEqual(status, output["status"])
        for key in timeline.claim.AUTHORITY_FLAGS:
            self.assertIs(output[key], False)
        self.assertEqual({"schema_version", "status", "reason", *timeline.claim.AUTHORITY_FLAGS}, set(output))

    def test_valid_anchored_three_step_snapshot_is_only_review(self):
        self.assert_status(make_timeline(), "REVIEW_ONLY")
        self.assertEqual("UNAUTHENTICATED_CONTINUITY_ONLY", timeline.review(raw(make_timeline()))["reason"])

    def test_single_step_cannot_claim_continuity(self):
        self.assert_status(make_timeline(1), "HOLD")

    def test_reject_empty_and_overlong_batch(self):
        for count in (0, 1, 17):
            with self.subTest(count=count):
                self.assert_status(make_timeline(count), "HOLD")

    def test_root_unknown_key_or_schema(self):
        for change in ("extra", "missing", "schema-string", "schema-bool"):
            p = make_timeline()
            if change == "extra": p["release"] = True
            elif change == "missing": del p["schema_version"]
            elif change == "schema-string": p["schema_version"] = "1"
            else: p["schema_version"] = True
            self.assert_status(p, "HOLD")

    def test_missing_or_alias_chain_anchor(self):
        for change in ("missing", "zero", "wrong", "uppercase", "numeric"):
            p = make_timeline()
            item = p["entries"][1]
            if change == "missing": del item["previous_sha256"]
            elif change == "zero": item["previous_sha256"] = "0" * 64
            elif change == "wrong": item["previous_sha256"] = "b" * 64
            elif change == "uppercase": item["previous_sha256"] = item["previous_sha256"].upper()
            else: item["previous_sha256"] = 2
            self.assert_status(p, "HOLD")

    def test_first_entry_must_have_null_predecessor(self):
        p = make_timeline(); p["entries"][0]["previous_sha256"] = "c" * 64
        self.assert_status(p, "HOLD")

    def test_inplace_tampering_cannot_preserve_downstream_anchor(self):
        for value in ("c" * 64, "0" * 64):
            p = make_timeline()
            p["entries"][0]["packet"]["scope_sha256"] = value
            self.assert_status(p, "HOLD")

    def test_recomputed_chain_does_not_hide_consent_drift(self):
        for edit in ("principal", "revision", "consent-sequence"):
            p = make_timeline()
            second = p["entries"][1]["packet"]
            if edit == "principal":
                second["consents"][1]["principal"] = "operator:someoneelse"
            elif edit == "revision":
                second["proposal_sha"] = "c" * 40
                for c in second["consents"]: c["proposal_sha"] = "c" * 40
            else:
                second["consents"][0]["event_seq"] = 12
            p["entries"][2]["previous_sha256"] = timeline.entry_digest(p["entries"][1])
            self.assert_status(p, "HOLD")

    def test_revocation_even_if_rechained_is_never_review(self):
        p = make_timeline()
        p["entries"][1]["packet"]["revocations"].append({
            "role": "client", "principal": "client:example", "proposal_sha": "a" * 40,
            "scope_sha256": "b" * 64, "effective_at": "2026-10-17T12:00:30Z", "event_seq": 12
        })
        p["entries"][2]["previous_sha256"] = timeline.entry_digest(p["entries"][1])
        self.assert_status(p, "HOLD")

    def test_snapshot_revocation_erase_cannot_pass_without_chain_update(self):
        p = make_timeline()
        p["entries"][0]["packet"]["revocations"] = [{"synthetic": "revoked"}]
        self.assert_status(p, "HOLD")
        p["entries"][0]["packet"]["revocations"] = []
        self.assert_status(p, "REVIEW_ONLY")  # Cannot establish real completeness from unauthenticated material.

    def test_backward_or_duplicate_time_with_rechaining(self):
        for timestamp in ("2026-10-17T12:00:00Z", "2026-10-17T11:59:00Z"):
            p = make_timeline()
            p["entries"][1]["packet"]["review_at"] = timestamp
            p["entries"][2]["previous_sha256"] = timeline.entry_digest(p["entries"][1])
            self.assert_status(p, "HOLD")

    def test_consent_reordering_is_not_an_immutable_claim(self):
        p = make_timeline()
        p["entries"][1]["packet"]["consents"].reverse()
        p["entries"][2]["previous_sha256"] = timeline.entry_digest(p["entries"][1])
        self.assert_status(p, "HOLD")

    def test_inner_claim_rejects_future_and_expired(self):
        p = make_timeline()
        p["entries"][2]["packet"]["review_at"] = "2026-10-17T12:52:00Z"
        self.assert_status(p, "HOLD")

    def test_nonbyte_and_large_inputs(self):
        good = raw(make_timeline())
        for bad in (bytearray(good), memoryview(good), b"", b"\xff"+good,
                    good+b"\0", good + b" " * timeline.MAX_TIMELINE_BYTES):
            self.assertEqual("HOLD", timeline.review(bad)["status"])
        class Spoof(bytes):
            def decode(self, *args, **kwargs):
                return good.decode()
        self.assertEqual("HOLD", timeline.review(Spoof(b"not_json"))["status"])

    def test_exact_boundary_valid_json_128k(self):
        good = raw(make_timeline())
        exact = good + b" " * (timeline.MAX_TIMELINE_BYTES - len(good))
        self.assertEqual("REVIEW_ONLY", timeline.review(exact)["status"])
        self.assertEqual("HOLD", timeline.review(exact+b" ")["status"])

    def test_escaped_identity_alias_and_duplicate_json_fields(self):
        good = raw(make_timeline())
        self.assertIn(b'"scope_sha256"', good)
        self.assertEqual("HOLD", timeline.review(good.replace(b'"scope_sha256"', b'"\\u0073cope_sha256"', 1))["status"])
        self.assertEqual("HOLD", timeline.review(good.replace(b'"schema_version":1', b'"schema_version":NaN', 1))["status"])
        self.assertEqual("HOLD", timeline.review(good[:-1]+b',"entries":[]}')["status"])

    def test_truncation_and_mutation_fuzz(self):
        good = raw(make_timeline())
        for i in range(0, len(good), 13):
            self.assertEqual("HOLD", timeline.review(good[:i])["status"])
        for i in range(0, 300, 19):
            self.assertEqual("HOLD", timeline.review(good[:i]+b"\xff"+good[i+1:])["status"])

    def test_actual_subprocess_valid_invalid_unknown_args(self):
        for p, expected in ((raw(make_timeline()), 3), (raw(make_timeline(1)), 2), (b"{", 2)):
            result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                                    input=p, capture_output=True, timeout=10)
            self.assertEqual(expected, result.returncode, result.stderr)
            out = json.loads(result.stdout)
            self.assertEqual("REVIEW_ONLY" if expected == 3 else "HOLD", out["status"])
            self.assertEqual(b"", result.stderr)
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT), "--authorize"],
                                input=raw(make_timeline()), capture_output=True, timeout=10)
        self.assertEqual(2, result.returncode)
        self.assertEqual("HOLD", json.loads(result.stdout)["status"])

    def test_fragmented_io_and_partial_stdout(self):
        class Fragments:
            def __init__(self, data): self.data, self.i = data, 0
            def read(self, _count):
                if self.i >= len(self.data): return b""
                chunk = self.data[self.i:self.i+1]; self.i += 1; return chunk
        class Source:
            def __init__(self, data): self.buffer = Fragments(data)
        class Output:
            def write(self, wire): return True
            def flush(self): pass
        with patch.object(timeline.sys, "stdin", Source(raw(make_timeline()))):
            with patch.object(timeline.sys, "stdout", io.StringIO()) as handle:
                self.assertEqual(3, timeline.main([]))
                self.assertEqual("REVIEW_ONLY", json.loads(handle.getvalue())["status"])
        with patch.object(timeline.sys, "stdin", Source(raw(make_timeline()))):
            with patch.object(timeline.sys, "stdout", Output()):
                self.assertEqual(2, timeline.main([]))

    def test_no_tool_or_network_execution(self):
        source = SCRIPT.read_text("utf-8")
        for forbidden in ("import requests", "import socket", "urllib.request",
                          "from lightup", "os.system", "subprocess.run(", "ExecutionPermit("):
            self.assertNotIn(forbidden, source)


    def test_independent_head_pin_matches_only_exact_snapshot_chain(self):
        batch = make_timeline()
        external_pin = timeline.entry_digest(batch["entries"][-1])
        result = timeline.review(raw(batch), expected_head_sha256=external_pin)
        self.assertEqual("REVIEW_ONLY", result["status"])
        self.assertTrue(all(result[k] is False for k in timeline.claim.AUTHORITY_FLAGS))
        tampered = copy.deepcopy(batch)
        for e in tampered["entries"]:
            e["packet"]["consents"][1]["principal"] = "operator:rewritten"
        for index in range(1, len(tampered["entries"])):
            tampered["entries"][index]["previous_sha256"] = timeline.entry_digest(tampered["entries"][index - 1])
        # An attacker can rewrite ALL untrusted snapshots and recompute the chain.
        self.assertEqual("REVIEW_ONLY", timeline.review(raw(tampered))["status"])
        # An independently retained digest catches that whole-chain substitution.
        self.assertEqual("HOLD", timeline.review(raw(tampered), expected_head_sha256=external_pin)["status"])

    def test_external_anchor_must_be_exact_lowercase_sha256(self):
        batch = raw(make_timeline())
        good = timeline.entry_digest(make_timeline()["entries"][-1])
        for pin in ("0"*64, good.upper(), "g"*64, good[:-1], "", "none",
                    True, 1.0, 42, b"c"*64, [], {}):
            with self.subTest(pin=repr(pin)[:20]):
                self.assertEqual("HOLD", timeline.review(batch, expected_head_sha256=pin)["status"])

    def test_pinned_cli_subprocess_and_unknown_arguments(self):
        batch = raw(make_timeline())
        pin = timeline.entry_digest(make_timeline()["entries"][-1])
        for argv, expected in ((["--expected-head", pin], 3),
                               (["--expected-head", "c"*64], 2),
                               (["--expected-head", pin, "--authorize"], 2),
                               (["--expected-head"], 2)):
            result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT), *argv],
                                    input=batch, capture_output=True, timeout=10)
            self.assertEqual(expected, result.returncode, result.stderr)
            self.assertTrue(all(json.loads(result.stdout)[k] is False
                                for k in timeline.claim.AUTHORITY_FLAGS))

    def test_deep_nesting_and_numeric_overflow_fail_atomic_hold(self):
        good = raw(make_timeline())
        self.assertEqual("HOLD", timeline.review(b'{"schema_version":1,"entries":'+
                                                b"["*2000+b"0"+b"]"*2000+b"}")["status"])
        replacement = good.replace(b'"schema_version":1', b'"schema_version":1e9999', 1)
        self.assertEqual("HOLD", timeline.review(replacement)["status"])


    def test_pinned_corrupted_bytes_never_grant_any_authority(self):
        import random
        rng = random.Random(1551)
        original = make_timeline()
        raw_original = raw(original)
        pin = timeline.entry_digest(original["entries"][-1])
        counts = {"HOLD": 0, "REVIEW_ONLY": 0}
        for _ in range(3000):
            trial = bytearray(raw_original)
            operation = rng.randrange(4)
            offset = rng.randrange(len(trial))
            if operation == 0:
                trial[offset] = rng.randrange(256)
            elif operation == 1:
                del trial[offset]
            elif operation == 2:
                trial[offset:offset] = bytes([rng.randrange(256)])
            else:
                trial = trial[:offset]
            result = timeline.review(bytes(trial), expected_head_sha256=pin)
            counts[result["status"]] += 1
            self.assertTrue(all(result[k] is False for k in timeline.claim.AUTHORITY_FLAGS))
        self.assertEqual({"HOLD": 2998, "REVIEW_ONLY": 2}, counts)

    def test_semantically_equivalent_whitespace_does_not_forge_new_head(self):
        batch = make_timeline()
        pin = timeline.entry_digest(batch["entries"][-1])
        original = raw(batch)
        changed = original.replace(b'"event_seq":11,', b'"event_seq":11\t,', 1)
        self.assertNotEqual(original, changed)
        result = timeline.review(changed, expected_head_sha256=pin)
        self.assertEqual("REVIEW_ONLY", result["status"])
        self.assertTrue(all(result[k] is False for k in timeline.claim.AUTHORITY_FLAGS))


if __name__ == "__main__":
    unittest.main()
