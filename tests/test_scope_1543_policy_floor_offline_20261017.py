"""Owner-isolated, no-authority offline change-policy floor tests (#1543).

No target, handler, grants, Git commands, network, or installed source mutation.
"""
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_scope_policy_floor_offline_1543.py"
spec = importlib.util.spec_from_file_location("scope_policy_floor_1543", SCRIPT)
assert spec and spec.loader
reviewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reviewer)


def good() -> dict:
    return {
        "schema": reviewer.SCHEMA,
        "policy": {
            "severity_verdicts": {
                "critical": "BLOCK",
                "high": "REVIEW_REQUIRED",
                "medium": "PASS_WITH_WARNING",
                "low": "PASS_WITH_WARNING",
                "info": "PASS",
            },
            "surface_change_verdict": "REVIEW_REQUIRED",
            "incomplete_coverage_verdict": "REVIEW_REQUIRED",
            "ignore_rules": [],
            "ignore_paths": [],
            "min_confidence": 0,
        },
    }


def encode(document: object) -> bytes:
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")


def run_cli(payload: bytes, *args: str) -> tuple[int, dict]:
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(SCRIPT), *args],
        input=payload, capture_output=True, timeout=8, check=False,
    )
    if completed.stderr:
        raise AssertionError("CLI leaked stderr or failed unexpectedly")
    return completed.returncode, json.loads(completed.stdout.decode("utf-8"))


class PolicyFloorTests(unittest.TestCase):
    def assert_hold(self, document: object) -> None:
        self.assertEqual(reviewer.evaluate(encode(document)), reviewer.HOLD)

    def test_explicit_strict_policy_only_review(self):
        self.assertEqual(reviewer.evaluate(encode(good())), reviewer.REVIEW_ONLY)

    def test_stricter_policy_is_compatible(self):
        specimen = good()
        specimen["policy"]["severity_verdicts"]["medium"] = "BLOCK"
        specimen["policy"]["severity_verdicts"]["high"] = "BLOCK"
        specimen["policy"]["surface_change_verdict"] = "BLOCK"
        self.assertEqual(reviewer.evaluate(encode(specimen)), reviewer.REVIEW_ONLY)

    def test_every_severity_cannot_be_downgraded(self):
        for severity, weaker in [
            ("critical", "REVIEW_REQUIRED"),
            ("high", "PASS_WITH_WARNING"),
            ("medium", "PASS"),
            ("low", "PASS"),
        ]:
            with self.subTest(severity=severity):
                specimen = good()
                specimen["policy"]["severity_verdicts"][severity] = weaker
                self.assert_hold(specimen)

    def test_false_verdicts_are_not_coerced(self):
        for value in [False, True, None, 0, 3, [], {}, "BLOCK ", "block"]:
            with self.subTest(value=repr(value)):
                specimen = good()
                specimen["policy"]["severity_verdicts"]["critical"] = value
                self.assert_hold(specimen)

    def test_critical_missing_and_unknown_severity_hold(self):
        specimen = good()
        del specimen["policy"]["severity_verdicts"]["critical"]
        self.assert_hold(specimen)
        specimen = good()
        specimen["policy"]["severity_verdicts"]["supercritical"] = "BLOCK"
        self.assert_hold(specimen)

    def test_coverage_gap_must_stay_review_required(self):
        for key in ("surface_change_verdict", "incomplete_coverage_verdict"):
            for verdict in ("PASS_WITH_WARNING", "PASS"):
                with self.subTest(key=key, verdict=verdict):
                    specimen = good()
                    specimen["policy"][key] = verdict
                    self.assert_hold(specimen)

    def test_both_suppression_channels_hold(self):
        for key, value in (
            ("ignore_rules", ["high-risk"]),
            ("ignore_paths", ["**/*"]),
            ("ignore_paths", [".github/workflows/*"]),
            ("ignore_rules", "*"),
            ("ignore_paths", {}),
            ("ignore_paths", None),
            ("ignore_rules", False),
        ):
            with self.subTest(key=key, value=repr(value)):
                specimen = good()
                specimen["policy"][key] = value
                self.assert_hold(specimen)

    def test_confidence_threshold_must_be_exact_zero(self):
        for confidence in (0.01, 0.5, 1, "0", "0.0", False, True, None, [], {}):
            with self.subTest(confidence=repr(confidence)):
                specimen = good()
                specimen["policy"]["min_confidence"] = confidence
                self.assert_hold(specimen)
        specimen = good()
        specimen["policy"]["min_confidence"] = 0.0
        self.assertEqual(reviewer.evaluate(encode(specimen)), reviewer.REVIEW_ONLY)

    def test_nonfinite_confidence_holds(self):
        for value in [float("nan"), float("inf"), float("-inf")]:
            specimen = good()
            specimen["policy"]["min_confidence"] = value
            self.assert_hold(specimen)

    def test_missing_extra_and_authority_like_fields_hold(self):
        for level in ("root", "policy"):
            for key in ("release_allowed", "authorized", "operator_consent", "scanner", "foo"):
                with self.subTest(level=level, key=key):
                    specimen = good()
                    (specimen if level == "root" else specimen["policy"])[key] = False
                    self.assert_hold(specimen)
        specimen = good()
        del specimen["policy"]["ignore_paths"]
        self.assert_hold(specimen)

    def test_malformed_and_duplicate_json_hold(self):
        for payload in (
            b"",
            b"{",
            b"[]",
            b'{"schema":"a","schema":"b","policy":{}}',
            b'{"schema":"lightup.scope.synthetic_policy_floor.v1","policy":{"ignore_rules":[],"ignore_rules":[]}}',
            b"NaN",
            b"Infinity",
            b"{}{}",
            b"\xff",
            b"\xef\xbb\xbf{}",
            b" " * (reviewer.MAX_INPUT_BYTES + 1),
            b'{"schema": "\\ud800"}',
        ):
            with self.subTest(payload=repr(payload[:28])):
                self.assertEqual(reviewer.evaluate(payload), reviewer.HOLD)

    def test_absurd_depth_and_oversize_are_atomic_hold(self):
        for raw in (b"[" * 1100 + b"0" + b"]" * 1100, b"0" * 10000):
            self.assertEqual(reviewer.evaluate(raw), reviewer.HOLD)

    def test_inexact_utf8_and_unicode_schemas_hold(self):
        for marker in ("lightup.scope.synthetic_policy_floor.v１", "LIGHTUP.scope.synthetic_policy_floor.v1", " " + reviewer.SCHEMA):
            specimen = good()
            specimen["schema"] = marker
            self.assert_hold(specimen)

    def test_cli_positive_receipt_is_never_exit_zero(self):
        code, result = run_cli(encode(good()))
        self.assertEqual(code, 3)
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertEqual(result["basis"], "untrusted_synthetic_policy_only")
        for flag in reviewer.FALSE_FLAGS:
            self.assertIs(result[flag], False)

    def test_cli_negative_receipt_is_same_privacy_shape(self):
        specimen = good()
        specimen["policy"]["ignore_paths"] = ["PRIVATE_CUSTOMER_PATH"]
        code, result = run_cli(encode(specimen))
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "HOLD")
        self.assertNotIn("PRIVATE_CUSTOMER_PATH", json.dumps(result))
        for flag in reviewer.FALSE_FLAGS:
            self.assertIs(result[flag], False)

    def test_cli_rejects_arguments_and_never_echoes(self):
        code, result = run_cli(encode(good()), "--allow-release")
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "HOLD")

    def test_no_external_imports_or_source_wiring(self):
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name.split(".")[0] for alias in node.names)
            if isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module.split(".")[0])
        self.assertEqual(set(imports), {"__future__", "json", "sys", "typing"})
        self.assertNotIn("lightup", imports)
        self.assertNotIn("subprocess", imports)

    def test_installed_change_review_source_accepts_unsafe_policy_today(self):
        # Source-owner characterization, not a permission/grant. Never mutate its code.
        sys.path.insert(0, str(ROOT / "src"))
        from lightup.change_review import ChangeReviewPolicy
        from lightup.future_security_ci_verdict import SecurityCIVerdict
        from lightup.models import Severity
        policy = ChangeReviewPolicy.from_mapping({
            "severity_verdicts": {"critical": "PASS"},
            "ignore_paths": ["*"],
            "min_confidence": 1.0,
        })
        self.assertEqual(policy.severity_verdicts[Severity.CRITICAL], SecurityCIVerdict.PASS)
        self.assertEqual(policy.ignore_paths, ("*",))
        self.assertEqual(policy.min_confidence, 1.0)

    @unittest.expectedFailure
    def test_source_owner_must_eventually_reject_downgraded_critical(self):
        # Strict owner repair contract: intentionally RED until source owner upgrades.
        sys.path.insert(0, str(ROOT / "src"))
        from lightup.change_review import ChangeReviewPolicy
        with self.assertRaises(ValueError):
            ChangeReviewPolicy.from_mapping({"severity_verdicts": {"critical": "PASS"}})


if __name__ == "__main__":
    unittest.main()
