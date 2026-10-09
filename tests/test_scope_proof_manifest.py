"""Offline checks for the proof-index verifier. No real targets or I/O."""
import importlib.util
import json
import os
from unittest import mock
import contextlib
import io
import tempfile
import py_compile
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "verify_scope_proof_manifest.py"
spec = importlib.util.spec_from_file_location("scope_proof_manifest", MODULE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

A = "a" * 40
B = "b" * 40


def fixture():
    return dict(schema_version=1, implementation_sha=A, base_sha=B,
                hosted_py311_run_id=101, hosted_py314_run_id=102,
                permanent_vps_run_id=103,
                hosted_py311_sha=A, hosted_py314_sha=A, permanent_vps_sha=A,
                owner_review_sha=A, trusted_grant_reviewed=True,
                revocation_race_passed=True, denied_side_effects_zero=True,
                positive_loopback_control_passed=True,
                real_target_activation_disabled=True,
                denial_side_effect_counts={
                    "handler": 0, "socket": 0, "queue": 0, "action_evidence": 0})


class ProofManifestTests(unittest.TestCase):
    def test_script_compiles_as_standalone_python(self):
        with tempfile.TemporaryDirectory() as directory:
            py_compile.compile(str(MODULE), cfile=str(Path(directory) / "verifier.pyc"), doraise=True)

    def test_run_ids_for_independent_proof_lanes_must_differ(self):
        fields = ("hosted_py311_run_id", "hosted_py314_run_id", "permanent_vps_run_id")
        for first in fields:
            for second in fields:
                if first == second:
                    continue
                with self.subTest(first=first, second=second):
                    obj = fixture()
                    obj[second] = obj[first]
                    self.assertTrue(any("must be distinct" in e for e in module.verify(obj)))

    def test_missing_or_forged_run_ids_fail_closed(self):
        for field in ("hosted_py311_run_id", "hosted_py314_run_id", "permanent_vps_run_id"):
            for value in (None, 0, -1, True, 1.0, "123"):
                with self.subTest(field=field, value=value):
                    obj = fixture()
                    obj[field] = value
                    self.assertTrue(module.verify(obj))
            obj = fixture()
            del obj[field]
            self.assertTrue(module.verify(obj))

    def test_attacker_controlled_field_never_echoed_in_cli_output(self):
        marker = "SECRET-MARKER-NEVER-LOG"
        obj = fixture()
        obj[marker] = "sensitive"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(json.dumps(obj), encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = module.main(["verify", str(path)])
            self.assertEqual(status, 1)
            self.assertNotIn(marker, stdout.getvalue() + stderr.getvalue())
            self.assertNotIn("sensitive", stdout.getvalue() + stderr.getvalue())

    def test_duplicate_json_field_never_echoed(self):
        marker = "SECRET-DUPLICATE-FIELD"
        raw = json.dumps(fixture()).replace('"schema_version": 1', f'"{marker}": true, "{marker}": false, "schema_version": 1')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(raw, encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = module.main(["verify", str(path)])
            self.assertEqual(status, 2)
            self.assertNotIn(marker, stderr.getvalue())

    def test_schema_version_is_exact_integer(self):
        for value in (None, True, False, "1", 1.0, 0, 2, -1):
            with self.subTest(version=value):
                obj = fixture()
                obj["schema_version"] = value
                self.assertTrue(module.verify(obj))

    def test_missing_schema_version_fails_closed(self):
        obj = fixture()
        del obj["schema_version"]
        self.assertTrue(module.verify(obj))

    def test_valid_index_only(self):
        self.assertEqual(module.verify(fixture()), [])

    def test_implementation_must_not_equal_base(self):
        obj = fixture()
        obj["base_sha"] = obj["implementation_sha"]
        self.assertTrue(any("must differ" in e for e in module.verify(obj)))

    def test_null_sha_placeholder_rejected_for_all_proof_refs(self):
        for key in ("implementation_sha", "base_sha", "hosted_py311_sha",
                    "hosted_py314_sha", "permanent_vps_sha", "owner_review_sha"):
            with self.subTest(field=key):
                obj = fixture()
                obj[key] = "0" * 40
                self.assertTrue(any("null placeholder" in error for error in module.verify(obj)))

    def test_exact_sha_binding_for_every_proof(self):
        for key in ("hosted_py311_sha", "hosted_py314_sha",
                    "permanent_vps_sha", "owner_review_sha"):
            with self.subTest(key=key):
                obj = fixture()
                obj[key] = B
                self.assertTrue(module.verify(obj))

    def test_denial_boundaries_reject_effects(self):
        for key in ("handler", "socket", "queue", "action_evidence"):
            for value in (1, -1, None, False, "0", 0.0):
                with self.subTest(key=key, value=value):
                    obj = fixture()
                    obj["denial_side_effect_counts"][key] = value
                    self.assertTrue(module.verify(obj))

    def test_boolean_evidence_must_be_literal_true(self):
        for key in ("trusted_grant_reviewed", "revocation_race_passed",
                    "denied_side_effects_zero", "positive_loopback_control_passed",
                    "real_target_activation_disabled"):
            obj = fixture()
            obj[key] = 1
            self.assertTrue(module.verify(obj))

    def test_unknown_top_level_authority_is_denied(self):
        obj = fixture()
        obj["client_approved"] = True
        self.assertTrue(any("unknown field" in e for e in module.verify(obj)))

    def test_unknown_side_effect_channel_is_denied(self):
        obj = fixture()
        obj["denial_side_effect_counts"]["network"] = 0
        self.assertTrue(any("unknown denial boundary" in e for e in module.verify(obj)))

    def test_missing_side_effect_boundary_is_denied(self):
        for boundary in ("handler", "socket", "queue", "action_evidence"):
            obj = fixture()
            del obj["denial_side_effect_counts"][boundary]
            with self.subTest(boundary=boundary):
                self.assertTrue(module.verify(obj))

    def test_duplicate_top_level_json_key_fails_closed(self):
        raw = json.dumps(fixture()).replace('"trusted_grant_reviewed": true', '"trusted_grant_reviewed": false, "trusted_grant_reviewed": true')
        with self.assertRaises(ValueError):
            json.loads(raw, object_pairs_hook=module.reject_duplicate_keys)

    def test_duplicate_nested_boundary_key_fails_closed(self):
        raw = json.dumps(fixture()).replace('"handler": 0', '"handler": 1, "handler": 0')
        with self.assertRaises(ValueError):
            json.loads(raw, object_pairs_hook=module.reject_duplicate_keys)

    def test_cli_duplicate_field_never_passes(self):
        raw = json.dumps(fixture()).replace('"trusted_grant_reviewed": true', '"trusted_grant_reviewed": false, "trusted_grant_reviewed": true')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            path.write_text(raw, encoding="utf-8")
            self.assertEqual(module.main(["verify", str(path)]), 2)

    def test_nonfinite_json_constants_rejected_at_cli(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                raw = json.dumps(fixture()).replace('"handler": 0', f'"handler": {constant}')
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "fixture.json"
                    path.write_text(raw, encoding="utf-8")
                    self.assertEqual(module.main(["verify", str(path)]), 2)

    def test_excessive_json_nesting_returns_hold_not_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deep.json"
            path.write_text("[" * 1500 + "0" + "]" * 1500, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                result = module.main(["verify", str(path)])
            self.assertEqual(result, 2)
            self.assertNotIn("Traceback", output.getvalue())

    def test_oversized_manifest_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b" " * (module.MAX_MANIFEST_BYTES + 1))
            self.assertEqual(module.main(["verify", str(path)]), 2)

    def test_byte_limit_bounded_read_and_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boundary.json"
            raw = json.dumps(fixture()).encode("utf-8")
            path.write_bytes(raw + b" " * (module.MAX_MANIFEST_BYTES - len(raw)))
            self.assertEqual(module.main(["verify", str(path)]), 0)
            with path.open("ab") as stream:
                stream.write(b"X" * (module.MAX_MANIFEST_BYTES * 2))
            self.assertEqual(module.main(["verify", str(path)]), 2)

    def test_malformed_utf8_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.json"
            path.write_bytes(bytes([0xff, 0xfe]))
            self.assertEqual(module.main(["verify", str(path)]), 2)

    def test_symlink_proof_input_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "proof.json"
            original.write_text(json.dumps(fixture()), encoding="utf-8")
            link = Path(directory) / "linked.json"
            link.symlink_to(original)
            self.assertEqual(module.main(["verify", str(link)]), 2)

    def test_fifo_proof_input_fails_closed_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO unsupported")
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "proof.fifo"
            os.mkfifo(fifo)
            self.assertEqual(module.main(["verify", str(fifo)]), 2)

    def test_missing_secure_open_flag_fails_closed(self):
        for flag in ("O_NOFOLLOW", "O_NONBLOCK"):
            with self.subTest(flag=flag):
                with mock.patch.object(module.os, flag, None):
                    # An absent secure primitive must never turn into a permissive open.
                    self.assertEqual(module.main(["verify", "unused.json"]), 2)

    def test_zero_secure_open_flag_fails_closed(self):
        for flag in ("O_NOFOLLOW", "O_NONBLOCK"):
            with self.subTest(flag=flag):
                with mock.patch.object(module.os, flag, 0):
                    with tempfile.TemporaryDirectory() as directory:
                        path = Path(directory) / "valid.json"
                        path.write_text(json.dumps(fixture()), encoding="utf-8")
                        self.assertEqual(module.main(["verify", str(path)]), 2)

    def test_directory_proof_input_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(module.main(["verify", directory]), 2)

    def test_cli_valid_index_is_structural_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "valid.json"
            path.write_text(json.dumps(fixture()), encoding="utf-8")
            self.assertEqual(module.main(["verify", str(path)]), 0)

    def test_absent_or_malformed_manifest_is_denied(self):
        self.assertTrue(module.verify(None))
        self.assertTrue(module.verify({}))
        obj = fixture()
        obj["implementation_sha"] = "short"
        self.assertTrue(module.verify(obj))


if __name__ == "__main__":
    unittest.main()
