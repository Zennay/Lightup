"""Synthetic, offline-only non-authorization packet validation regression."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_scope_review_packet_offline.py"
spec = importlib.util.spec_from_file_location("scope_packet_offline_test_module", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def good():
    return {
        "schema_version": 1,
        "request_id": "req_123", "tenant_id": "tenant_456", "asset_id": "asset_789",
        "requester_id": "user_111", "authorization_reference": "AUTH-123",
        "scope_reference": "SCOPE-123", "requested_mode": "TARGET_ACTIVE", "risk_level": 3,
        "requested_capabilities": ["http_headers", "tls_baseline"],
        "review_evidence_digests": ["a" * 64, "b" * 64],
        "window_start": "2026-10-20T11:00:00Z", "window_end": "2026-10-20T12:00:00Z",
    }


def validate(p):
    return module.evaluate(json.dumps(p, ensure_ascii=False).encode("utf8"))


class ReviewPacketTests(unittest.TestCase):
    def assertHold(self, p, code=None):
        result = validate(p)
        self.assertEqual("HOLD", result["state"])
        if code:
            self.assertEqual(code, result["reason"])
        for key in module.AUTHORITY_FLAGS:
            self.assertIs(result[key], False)
        self.assertIs(result["non_authorizing"], True)

    def test_canonical_packet_shape_only(self):
        r = validate(good())
        self.assertEqual((r["state"], r["reason"]), ("REVIEW_ONLY", "SHAPE_ONLY_UNVERIFIED"))
        self.assertTrue(all(r[x] is False for x in module.AUTHORITY_FLAGS))

    def test_all_other_modes_valid_in_review_only(self):
        for mode, risk, caps in (("ANALYSIS_ONLY", 0, ["future_simulation"]), ("PASSIVE_PUBLIC", 1, ["future_simulation"]), ("LAB_ACTIVE", 5, ["http_headers"]), ("TARGET_ACTIVE", 4, ["service_inventory"])):
            with self.subTest(mode=mode):
                p = good(); p.update(requested_mode=mode, risk_level=risk, requested_capabilities=caps)
                self.assertEqual("REVIEW_ONLY", validate(p)["state"])

    def test_missing_each_field(self):
        for key in good():
            p = good(); del p[key]
            with self.subTest(key=key): self.assertHold(p, "SCHEMA_FIELDS")

    def test_extra_field_even_if_fake_approved(self):
        for key in ("approved", "authorization_verified", "permit_issued", "target_url", "operator_signature"):
            p=good();p[key]=True
            with self.subTest(key=key): self.assertHold(p, "SCHEMA_FIELDS")

    def test_non_dict_packet(self):
        for x in ([], None, "ok", 8, False):
            with self.subTest(x=x): self.assertHold(x, "SCHEMA_FIELDS")

    def test_schema_bool_or_string(self):
        for x in (True, "1", 1.0, 2, None):
            p=good();p["schema_version"]=x
            self.assertHold(p, "SCHEMA_VERSION")

    def test_identifiers_canonical(self):
        for key in ("request_id", "tenant_id", "asset_id", "requester_id"):
            for x in ("", " a", "Aaa", "ab", "a"*65, True, 4, "аbc", "äbc", "a\nq", "a\u200dq", "a/abc"):
                p=good();p[key]=x
                with self.subTest(key=key,x=x): self.assertHold(p, "ENCODING" if isinstance(x, str) and "\u200d" in x else "IDENTITY_FORMAT")

    def test_reference_unicode_and_controls(self):
        for key in ("authorization_reference", "scope_reference"):
            for x in ("", "X", "abc\n", "a\u200bb", "a\ufeffb", "äbc", "../", False, 5, "a"*129):
                p=good();p[key]=x
                with self.subTest(key=key,x=x): self.assertHold(p, "ENCODING" if isinstance(x, str) and any(ch in x for ch in ("\u200b", "\ufeff")) else "REFERENCE_FORMAT")

    def test_mode_is_exact(self):
        for x in ("TARGET_ACTIVE ", "unknown", "target_active", None, False, []):
            p=good();p["requested_mode"]=x
            self.assertHold(p, "MODE_RISK")

    def test_risk_bool_float_or_out_of_mode(self):
        for x in (True, 3.0, "3", -1, 5, None, []):
            p=good();p["risk_level"]=x
            self.assertHold(p, "MODE_RISK")

    def test_destructive_target_mode_hold(self):
        p=good();p["risk_level"]=5
        self.assertHold(p, "MODE_RISK")

    def test_capability_unknown_duplicate_unsorted(self):
        for x in (["unknown"], ["tls_baseline", "http_headers"], ["http_headers"]*2, [], ["future_simulation"]*5, [True], "http_headers", None):
            p=good();p["requested_capabilities"]=x
            self.assertHold(p, "CAPABILITIES")

    def test_passive_cannot_include_active_capabilities(self):
        p=good();p.update(requested_mode="PASSIVE_PUBLIC",risk_level=1)
        self.assertHold(p, "MODE_CAPABILITY")

    def test_analysis_cannot_include_active_capabilities(self):
        p=good();p.update(requested_mode="ANALYSIS_ONLY",risk_level=0)
        self.assertHold(p, "MODE_CAPABILITY")

    def test_evidence_digests_shape(self):
        for x in ([], ["A"*64], ["g"*64], ["a"*63], ["a"*65], ["a"*64]*2, ["b"*64, "a"*64], "a"*64, [True], ["a"*64]*9):
            p=good();p["review_evidence_digests"]=x
            self.assertHold(p, "EVIDENCE_SHAPE")

    def test_window_format(self):
        for x in ("2026-10-20T11:00:00+00:00", "2026-10-20T11:00Z", "2026-02-30T11:00:00Z", "2026-10-20t11:00:00z", 0, True, None, "2026-10-20T25:00:00Z", "2026-10-20T11:00:60Z"):
            p=good();p["window_start"]=x
            with self.subTest(x=x): self.assertHold(p, "WINDOW_FORMAT")

    def test_window_interval_bounds(self):
        for end in ("2026-10-20T10:00:00Z", "2026-10-20T11:00:00Z", "2026-10-20T11:00:59Z", "2026-10-21T11:00:01Z"):
            p=good();p["window_end"]=end
            self.assertHold(p, "WINDOW_BOUNDS")

    def test_window_upper_exact(self):
        p=good();p["window_end"]="2026-10-21T11:00:00Z"
        self.assertEqual("REVIEW_ONLY",validate(p)["state"])

    def test_duplicate_json_keys_rejected(self):
        raw=json.dumps(good()).replace('"risk_level": 3', '"risk_level": 3, "risk_level": 0')
        self.assertEqual("DUPLICATE_KEY",module.evaluate(raw.encode())["reason"])

    def test_nested_duplicate_json_keys_rejected(self):
        raw=b'{"a":{"x":1,"x":2}}'
        self.assertEqual("DUPLICATE_KEY",module.evaluate(raw)["reason"])

    def test_nonfinite_json_rejected(self):
        for raw in (b'{"x":NaN}',b'{"x":Infinity}',b'{"x":-Infinity}'):
            self.assertEqual("NONFINITE_NUMBER",module.evaluate(raw)["reason"])

    def test_invalid_json_bytes_rejected(self):
        for raw in (b"{", b"\xff", b"\xef\xbb\xbf{}", b"{\x00}", b""):
            self.assertEqual("HOLD",module.evaluate(raw)["state"])

    def test_overlarge_raw_denied(self):
        self.assertEqual("SIZE_LIMIT",module.evaluate(b"x"*(module.MAX_BYTES+1))["reason"])

    def test_no_error_details_leaked(self):
        p=good();p["authorization_reference"]="SECRET\nTOKEN"
        data=json.dumps(validate(p))
        self.assertNotIn("SECRET",data)
        self.assertNotIn("TOKEN",data)

    def test_no_mutation_of_input(self):
        p=good();original=copy.deepcopy(p)
        self.assertEqual("REVIEW_ONLY",validate(p)["state"])
        self.assertEqual(p,original)

    def test_cli_regular_file_review_only(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"packet.json";path.write_text(json.dumps(good()))
            proc=subprocess.run([sys.executable,str(SCRIPT),str(path)],capture_output=True,text=True,timeout=4)
            self.assertEqual(0,proc.returncode)
            self.assertEqual("REVIEW_ONLY",json.loads(proc.stdout)["state"])
            self.assertFalse(proc.stderr)

    def test_cli_invalid_packet_holds(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"packet.json";path.write_text('{"bad": 1}')
            proc=subprocess.run([sys.executable,str(SCRIPT),str(path)],capture_output=True,text=True,timeout=4)
            self.assertEqual(2,proc.returncode)
            self.assertEqual("HOLD",json.loads(proc.stdout)["state"])

    def test_cli_symlink_holds(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"packet.json";path.write_text(json.dumps(good()))
            link=Path(d)/"link.json";link.symlink_to(path)
            proc=subprocess.run([sys.executable,str(SCRIPT),str(link)],capture_output=True,text=True,timeout=4)
            self.assertEqual(2,proc.returncode)
            self.assertEqual("INPUT_UNAVAILABLE",json.loads(proc.stdout)["reason"])

    def test_cli_directory_holds(self):
        with tempfile.TemporaryDirectory() as d:
            proc=subprocess.run([sys.executable,str(SCRIPT),d],capture_output=True,text=True,timeout=4)
            self.assertEqual(2,proc.returncode)
            self.assertEqual("NOT_REGULAR_FILE",json.loads(proc.stdout)["reason"])

    def test_cli_missing_file_holds_without_path_echo(self):
        proc=subprocess.run([sys.executable,str(SCRIPT),"/missing-SECRET-private.json"],capture_output=True,text=True,timeout=4)
        self.assertEqual(2,proc.returncode)
        self.assertNotIn("SECRET",proc.stdout)
        self.assertNotIn("SECRET",proc.stderr)

    def test_cli_binary_oversize_holds(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"big.json";path.write_bytes(b"{"*(module.MAX_BYTES+2))
            proc=subprocess.run([sys.executable,str(SCRIPT),str(path)],capture_output=True,text=True,timeout=4)
            self.assertEqual(2,proc.returncode)
            self.assertEqual("SIZE_LIMIT",json.loads(proc.stdout)["reason"])

    def test_sensitive_no_network_modules_in_script(self):
        source=SCRIPT.read_text()
        for s in ("import requests", "import socket", "subprocess.run", "urllib.request", "http.client", "ToolExecutor"):
            self.assertNotIn(s,source)


if __name__ == "__main__": unittest.main()
