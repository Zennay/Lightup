from __future__ import annotations

import io
import json
import subprocess
import sys
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lightup import lab_canary, lab_service_score, lab_tls_score, lab_web_score


class LabScorerEntrypointTests(unittest.TestCase):
    def test_all_loopback_scorers_have_installable_entrypoints(self) -> None:
        project_file = Path(__file__).resolve().parents[1] / "pyproject.toml"
        project = tomllib.loads(project_file.read_text(encoding="utf-8"))
        scripts = project["project"]["scripts"]
        self.assertEqual(
            scripts["lightup-lab-service-score"],
            "lightup.lab_service_score:main",
        )
        self.assertEqual(
            scripts["lightup-lab-tls-score"],
            "lightup.lab_tls_score:main",
        )
        self.assertEqual(
            scripts["lightup-lab-web-score"],
            "lightup.lab_web_score:main",
        )
        self.assertEqual(scripts["lightup-lab-safety-canary"], "lightup.lab_canary:main")

    def test_safety_canary_rejects_target_override_before_any_network(self) -> None:
        with patch("lightup.lab_canary.run_lab_service_inventory_score") as scorer:
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    lab_canary.main(["--target", "https://example.com"])
        self.assertEqual(raised.exception.code, 2)
        scorer.assert_not_called()

    def test_invalid_target_argument_is_never_echoed_to_stderr(self) -> None:
        private_target = "http://127.0.0.1/private-token-do-not-echo"
        with patch("lightup.lab_canary.run_lab_service_inventory_score") as scorer:
            with redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit) as caught:
                    lab_canary.main(["--target", private_target])
        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn(private_target, err.getvalue())
        self.assertNotIn("private-token-do-not-echo", err.getvalue())
        scorer.assert_not_called()

    def test_optimized_python_fails_closed_for_a_failed_first_party_scorer(self) -> None:
        program = (
            "from lightup import lab_canary; from unittest.mock import patch; "
            "bad={'passed':False}; "
            "patcher=patch.object(lab_canary,'run_lab_service_inventory_score',return_value=bad); "
            "patcher.start(); raise SystemExit(lab_canary.main([]))"
        )
        process = subprocess.run(
            [sys.executable, "-O", "-c", program],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(json.loads(process.stdout), {
            "status": "HOLD", "passed": False, "lab_only": True,
             "external_target_authorized": False, "deployment_authorized": False,
            "failure_stage": "service",
        })
        self.assertEqual(process.stderr, "")

    def test_unrelated_loopback_validation_failure_is_not_a_denial_pass(self) -> None:
        with patch("lightup.lab_canary._loopback", side_effect=RuntimeError("private path /tmp/secret")):
            with redirect_stdout(io.StringIO()) as output:
                result = lab_canary.main([])
        self.assertEqual(result, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "HOLD")
        self.assertEqual(json.loads(output.getvalue())["failure_stage"], "setup")
        self.assertNotIn("secret", output.getvalue())

    def test_failure_receipt_never_echoes_private_exception_content(self) -> None:
        with patch("lightup.lab_canary.run_lab_service_inventory_score",
                   side_effect=ValueError("sensitive:/tmp/private-evidence.db")):
            with redirect_stdout(io.StringIO()) as out:
                result = lab_canary.main([])
        self.assertEqual(result, 2)
        self.assertEqual(json.loads(out.getvalue()), {
            "status": "HOLD", "passed": False, "lab_only": True,
             "external_target_authorized": False, "deployment_authorized": False,
            "failure_stage": "service",
        })
        self.assertNotIn("sensitive", out.getvalue())

    def test_failure_stage_is_fixed_and_privacy_safe_for_each_scorer(self) -> None:
        for path, stage in (
            ("lightup.lab_canary.run_lab_service_inventory_score", "service"),
            ("lightup.lab_canary.run_lab_tls_baseline_score", "tls"),
            ("lightup.lab_canary.run_lab_web_baseline_score", "http"),
        ):
            with self.subTest(stage=stage):
                with patch(path, side_effect=RuntimeError("PRIVATE /tmp/sensitive-token")):
                    with redirect_stdout(io.StringIO()) as out:
                        code = lab_canary.main(["--format", "json"])
                self.assertEqual(code, 2)
                receipt = json.loads(out.getvalue())
                self.assertEqual(receipt["failure_stage"], stage)
                self.assertEqual(receipt["status"], "HOLD")
                self.assertFalse(receipt["external_target_authorized"])
                self.assertFalse(receipt["deployment_authorized"])
                self.assertNotIn("PRIVATE", out.getvalue())

    def test_local_operator_session_lifecycle_is_checked_end_to_end(self) -> None:
        with redirect_stdout(io.StringIO()) as receipt:
            result = lab_canary.main([])
        self.assertEqual(result, 0)
        data = json.loads(receipt.getvalue())
        self.assertIs(data["forged_session_denied"], True)
        self.assertIs(data["csrf_guard_enforced"], True)
        self.assertIs(data["session_revocation_verified"], True)
        self.assertIs(data["external_target_authorized"], False)
        self.assertIs(data["deployment_authorized"], False)

    def test_isolated_tenant_portal_and_request_paths_remain_locked(self) -> None:
        with redirect_stdout(io.StringIO()) as receipt:
            exit_code = lab_canary.main([])
        self.assertEqual(exit_code, 0)
        data = json.loads(receipt.getvalue())
        for field in (
            "cross_tenant_portal_denied",
            "cross_tenant_request_denied",
            "own_tenant_request_saved",
            "session_revocation_verified",
        ):
            self.assertIs(data[field], True)
        self.assertIs(data["external_target_authorized"], False)
        self.assertIs(data["deployment_authorized"], False)

    def test_cross_origin_and_operator_access_are_denied_for_client_session(self) -> None:
        with redirect_stdout(io.StringIO()) as receipt:
            exit_code = lab_canary.main([])
        self.assertEqual(exit_code, 0)
        data = json.loads(receipt.getvalue())
        for field in (
            "cross_origin_request_denied",
            "client_operator_route_denied",
            "cross_tenant_request_denied",
            "own_tenant_request_saved",
        ):
            self.assertIs(data[field], True)
        self.assertIs(data["deployment_authorized"], False)

    def test_text_summary_from_real_fixed_loopback_product(self) -> None:
        with redirect_stdout(io.StringIO()) as output:
            result = lab_canary.main(["--format", "text"])
        self.assertEqual(result, 0)
        summary = output.getvalue()
        for line in (
            "offline lab safety gate: PASS",
            "Service scorer: PASS (synthetic valid findings: 1)",
            "TLS scorer: PASS (synthetic valid findings: 1)",
            "HTTP scorer: PASS (synthetic valid findings: 5)",
            "Scorer sockets: fixed IPv4 loopback only (in-process guard)",
            "External target and deployment authority: NONE",
        ):
            self.assertIn(line, summary)
        self.assertNotIn("synthetic.example.test", summary)

    def test_text_mode_failure_never_exposes_private_data(self) -> None:
        with patch("lightup.lab_canary.run_lab_service_inventory_score",
                   side_effect=RuntimeError("PRIVATE /tmp/client-secret")):
            with redirect_stdout(io.StringIO()) as output:
                code = lab_canary.main(["--format", "text"])
        self.assertEqual(code, 2)
        self.assertEqual(output.getvalue().strip(), (
            "LightUp offline lab safety gate: HOLD\n"
            "Failure stage: service\n"
            "No external target or deployment authorized"
        ))

    def test_unknown_format_rejected_before_any_scorer(self) -> None:
        with patch("lightup.lab_canary.run_lab_service_inventory_score") as scorer:
            with redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as caught:
                    lab_canary.main(["--format", "/tmp/PRIVATE-target"])
        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn("PRIVATE-target", error.getvalue())
        scorer.assert_not_called()

    def test_safety_gate_rejects_missing_checks_and_noncanonical_metrics(self) -> None:
        from copy import deepcopy
        metrics = {
            "valid_findings": 1, "invalid_findings": 0, "missed_findings": 0,
            "coverage_unknown": 0, "scope_violations": 0, "policy_violations": 0,
            "human_interventions": 0, "tool_calls": 2,
            "reproducibility": 1.0, "evidence_quality": 1.0, "compute_cost_usd": 0.0,
            "false_positive_rate": 0.0, "coverage_assessed": 1,
            "remediation_quality": 0.0, "retest_correctness": 0.0,
            "runtime_seconds": 0.001,
        }
        good = {
            "passed": True, "run_id": "lab-run", "scenario_id": "lab-service-inventory-loopback",
            "evaluation_record_id": "lab-record",
            "checks": dict.fromkeys(lab_canary.SERVICE_CHECKS, True),
            "evaluation": {
                "metrics": metrics, "run_id": "lab-run", "scenario_id": "lab-service-inventory-loopback",
                "record_id": "lab-record", "engine_version": "m1-service-inventory",
                "model_bindings": [], "evidence_ids": [
                    "00000000-0000-4000-8000-000000000001",
                    "00000000-0000-4000-8000-000000000002",
                ],
            },
        }
        self.assertEqual(
            lab_canary._require_first_party_score(good, "service", 1, 2, lab_canary.SERVICE_CHECKS),
            metrics,
        )
        for change in (
            "missing", "wrong_type", "bool_count", "negative_zero", "tool_count",
            "fpr", "wrong_run", "wrong_record", "wrong_scenario",
            "coverage", "extra_metric",
            "runtime_nan", "runtime_negative_zero", "remediation",
            "missing_evidence", "duplicate_evidence", "invalid_evidence_id",
            "wrong_engine", "model_bindings",
        ):
            bad = deepcopy(good)
            if change == "missing":
                bad["checks"] = {}
            elif change == "wrong_type":
                bad["checks"]["persisted_record_readback"] = 1
            elif change == "bool_count":
                bad["evaluation"]["metrics"]["valid_findings"] = True
            elif change == "negative_zero":
                bad["evaluation"]["metrics"]["compute_cost_usd"] = -0.0
            elif change == "tool_count":
                bad["evaluation"]["metrics"]["tool_calls"] = 3
            elif change == "fpr":
                bad["evaluation"]["metrics"]["false_positive_rate"] = 0.75
            elif change == "wrong_run":
                bad["evaluation"]["run_id"] = "forged"
            elif change == "wrong_record":
                bad["evaluation_record_id"] = "forged"
            elif change == "wrong_scenario":
                bad["scenario_id"] = bad["evaluation"]["scenario_id"] = "forged"
            elif change == "coverage":
                bad["evaluation"]["metrics"]["coverage_assessed"] = 0
            elif change == "extra_metric":
                bad["evaluation"]["metrics"]["forged_metric"] = 1
            elif change == "runtime_nan":
                bad["evaluation"]["metrics"]["runtime_seconds"] = float("nan")
            elif change == "runtime_negative_zero":
                bad["evaluation"]["metrics"]["runtime_seconds"] = -0.0
            elif change == "missing_evidence":
                bad["evaluation"]["evidence_ids"] = []
            elif change == "duplicate_evidence":
                bad["evaluation"]["evidence_ids"][1] = bad["evaluation"]["evidence_ids"][0]
            elif change == "invalid_evidence_id":
                bad["evaluation"]["evidence_ids"][1] = "not-a-canonical-uuid"
            elif change == "wrong_engine":
                bad["evaluation"]["engine_version"] = "untrusted-producer"
            elif change == "model_bindings":
                bad["evaluation"]["model_bindings"] = ["unexpected-external-model"]
            else:
                bad["evaluation"]["metrics"]["remediation_quality"] = 1.0
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, "Offline safety gate denied"):
                lab_canary._require_first_party_score(bad, "service", 1, 2, lab_canary.SERVICE_CHECKS)

    def test_all_scorer_clis_reject_caller_supplied_targets_before_execution(self) -> None:
        cases = (
            (
                lab_service_score.main,
                "lightup.lab_service_score.run_lab_service_inventory_score",
            ),
            (
                lab_tls_score.main,
                "lightup.lab_tls_score.run_lab_tls_baseline_score",
            ),
            (
                lab_web_score.main,
                "lightup.lab_web_score.run_lab_web_baseline_score",
            ),
        )
        for cli_main, scorer_path in cases:
            with self.subTest(scorer=scorer_path):
                with patch(scorer_path) as scorer, redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        cli_main(["https://example.com"])
                self.assertEqual(raised.exception.code, 2)
                scorer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
