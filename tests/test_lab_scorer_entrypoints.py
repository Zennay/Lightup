from __future__ import annotations

import io
import subprocess
import sys
import tomllib
import unittest
from contextlib import redirect_stderr
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

    def test_optimized_python_fails_closed_for_a_failed_first_party_scorer(self) -> None:
        program = (
            "from lightup import lab_canary; from unittest.mock import patch; "
            "bad={'passed':False}; "
            "patcher=patch.object(lab_canary,'run_lab_service_inventory_score',return_value=bad); "
            "patcher.start(); lab_canary.main([])"
        )
        process = subprocess.run(
            [sys.executable, "-O", "-c", program],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("Offline safety gate denied: service scorer", process.stderr)
        self.assertNotIn('"service_inventory_labeval_passed": true', process.stdout)

    def test_unrelated_loopback_validation_failure_is_not_a_denial_pass(self) -> None:
        with patch("lightup.lab_canary._loopback", side_effect=RuntimeError("internal failure")):
            with self.assertRaisesRegex(RuntimeError, "internal failure"):
                lab_canary.main([])

    def test_safety_gate_rejects_missing_checks_and_noncanonical_metrics(self) -> None:
        from copy import deepcopy
        metrics = {
            "valid_findings": 1, "invalid_findings": 0, "missed_findings": 0,
            "coverage_unknown": 0, "scope_violations": 0, "policy_violations": 0,
            "human_interventions": 0, "tool_calls": 2,
            "reproducibility": 1.0, "evidence_quality": 1.0, "compute_cost_usd": 0.0,
        }
        good = {
            "passed": True,
            "checks": dict.fromkeys(lab_canary.SERVICE_CHECKS, True),
            "evaluation": {"metrics": metrics},
        }
        self.assertEqual(
            lab_canary._require_first_party_score(good, "service", 1, 2, lab_canary.SERVICE_CHECKS),
            metrics,
        )
        for change in ("missing", "wrong_type", "bool_count", "negative_zero", "tool_count"):
            bad = deepcopy(good)
            if change == "missing":
                bad["checks"] = {}
            elif change == "wrong_type":
                bad["checks"]["persisted_record_readback"] = 1
            elif change == "bool_count":
                bad["evaluation"]["metrics"]["valid_findings"] = True
            elif change == "negative_zero":
                bad["evaluation"]["metrics"]["compute_cost_usd"] = -0.0
            else:
                bad["evaluation"]["metrics"]["tool_calls"] = 3
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
