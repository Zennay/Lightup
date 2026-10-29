from __future__ import annotations

import json
import os
import stat
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup import lab_score_suite


def _score_result(name: str, valid_findings: int) -> dict:
    run_id = f"run-{name}"
    record_id = f"record-{name}"
    evidence_ids = [
        f"{name}-evidence-{index + 1}"
        for index in range(lab_score_suite._EXPECTED_EVIDENCE[name])
    ]
    metrics = {
        "valid_findings": valid_findings,
        "invalid_findings": 0,
        "missed_findings": 0,
        "coverage_assessed": 1,
        "coverage_unknown": 0,
        "scope_violations": 0,
        "policy_violations": 0,
        "reproducibility": 1.0,
        "evidence_quality": 1.0,
        "tool_calls": lab_score_suite._EXPECTED_EVIDENCE[name],
        "human_interventions": 0,
        "compute_cost_usd": 0.0,
    }
    return {
        "passed": True,
        "scenario_id": lab_score_suite._SCENARIOS[name],
        "run_id": run_id,
        "evaluation_record_id": record_id,
        "checks": {
            check: True for check in lab_score_suite._PUBLIC_CHECKS[name]
        },
        "evaluation": {
            "record_id": record_id,
            "scenario_id": lab_score_suite._SCENARIOS[name],
            "engine_version": lab_score_suite._ENGINE_VERSIONS[name],
            "model_bindings": [],
            "run_id": run_id,
            "evidence_ids": evidence_ids,
            "metrics": metrics,
        },
    }


class LabScoreSuiteTests(unittest.TestCase):
    def test_runs_all_scorers_and_writes_private_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "suite-run"
            with (
                patch.object(
                    lab_score_suite,
                    "run_lab_service_inventory_score",
                    return_value=_score_result("service_inventory", 1),
                ) as service,
                patch.object(
                    lab_score_suite,
                    "run_lab_tls_baseline_score",
                    return_value=_score_result("tls_baseline", 1),
                ) as tls,
                patch.object(
                    lab_score_suite,
                    "run_lab_web_baseline_score",
                    return_value=_score_result("http_baseline", 5),
                ) as http,
            ):
                report = lab_score_suite.run_lab_score_suite(output_dir)

            self.assertTrue(report["passed"])
            self.assertEqual(
                set(report["scorers"]),
                {"service_inventory", "tls_baseline", "http_baseline"},
            )
            self.assertTrue(all(item["passed"] for item in report["scorers"].values()))
            self.assertEqual(
                [Path(call.args[0]).name for call in (
                    service.call_args,
                    tls.call_args,
                    http.call_args,
                )],
                [
                    "service_inventory.sqlite3",
                    "tls_baseline.sqlite3",
                    "http_baseline.sqlite3",
                ],
            )
            self.assertEqual(len({
                service.call_args.args[0],
                tls.call_args.args[0],
                http.call_args.args[0],
            }), 3)
            self.assertEqual(
                report["safety"],
                {
                    "fixture_scope": "fixed 127.0.0.1 loopback fixtures only",
                    "external_target_interaction": False,
                    "authorization_grants_issued": False,
                    "worker_dispatch": False,
                    "remediation_or_retest": False,
                    "deployment": False,
                },
            )

            report_path = output_dir / "report.json"
            self.assertEqual(json.loads(report_path.read_text(encoding="utf-8")), report)
            self.assertEqual(stat.S_IMODE(output_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)

    def test_independently_rejects_bad_metrics_even_when_scorer_says_pass(self) -> None:
        service_result = _score_result("service_inventory", 1)
        service_result["evaluation"]["metrics"]["invalid_findings"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(
                    lab_score_suite,
                    "run_lab_service_inventory_score",
                    return_value=service_result,
                ),
                patch.object(
                    lab_score_suite,
                    "run_lab_tls_baseline_score",
                    return_value=_score_result("tls_baseline", 1),
                ),
                patch.object(
                    lab_score_suite,
                    "run_lab_web_baseline_score",
                    return_value=_score_result("http_baseline", 5),
                ),
            ):
                report = lab_score_suite.run_lab_score_suite(
                    Path(temporary) / "suite-run"
                )

            self.assertFalse(report["passed"])
            self.assertFalse(report["scorers"]["service_inventory"]["passed"])
            self.assertIn(
                "metric_mismatch:invalid_findings",
                report["scorers"]["service_inventory"]["failure_reasons"],
            )
            self.assertTrue(report["scorers"]["tls_baseline"]["passed"])
            self.assertTrue(report["scorers"]["http_baseline"]["passed"])

    def test_boolean_values_cannot_impersonate_numeric_metrics(self) -> None:
        service_result = _score_result("service_inventory", 1)
        metrics = service_result["evaluation"]["metrics"]
        metrics["valid_findings"] = True
        metrics["invalid_findings"] = False
        metrics["reproducibility"] = True
        metrics["evidence_quality"] = True
        metrics["coverage_assessed"] = True

        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(
                    lab_score_suite,
                    "run_lab_service_inventory_score",
                    return_value=service_result,
                ),
                patch.object(
                    lab_score_suite,
                    "run_lab_tls_baseline_score",
                    return_value=_score_result("tls_baseline", 1),
                ),
                patch.object(
                    lab_score_suite,
                    "run_lab_web_baseline_score",
                    return_value=_score_result("http_baseline", 5),
                ),
            ):
                report = lab_score_suite.run_lab_score_suite(
                    Path(temporary) / "suite-run"
                )

        self.assertFalse(report["passed"])
        failures = report["scorers"]["service_inventory"]["failure_reasons"]
        for metric in (
            "valid_findings",
            "invalid_findings",
            "reproducibility",
            "evidence_quality",
            "coverage_assessed",
        ):
            self.assertIn(f"metric_mismatch:{metric}", failures)

    def test_scorer_exception_is_private_and_does_not_skip_later_scorers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(
                    lab_score_suite,
                    "run_lab_service_inventory_score",
                    return_value=_score_result("service_inventory", 1),
                ),
                patch.object(
                    lab_score_suite,
                    "run_lab_tls_baseline_score",
                    side_effect=RuntimeError("private /tmp/customer-path"),
                ),
                patch.object(
                    lab_score_suite,
                    "run_lab_web_baseline_score",
                    return_value=_score_result("http_baseline", 5),
                ) as http,
            ):
                report = lab_score_suite.run_lab_score_suite(
                    Path(temporary) / "suite-run"
                )

            self.assertFalse(report["passed"])
            tls = report["scorers"]["tls_baseline"]
            self.assertEqual(tls["error_type"], "RuntimeError")
            self.assertEqual(tls["failure_reasons"], ["scorer_exception"])
            self.assertTrue(http.called)
            serialized = (Path(temporary) / "suite-run" / "report.json").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("private /tmp/customer-path", serialized)

    def test_existing_output_directory_is_never_reused_or_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "existing"
            output_dir.mkdir(mode=0o700)
            sentinel = output_dir / "keep.txt"
            sentinel.write_text("keep", encoding="utf-8")
            with patch.object(lab_score_suite, "run_lab_service_inventory_score") as service:
                with self.assertRaises(FileExistsError):
                    lab_score_suite.run_lab_score_suite(output_dir)
                service.assert_not_called()
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_symlink_output_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir(mode=0o700)
            link = root / "alias"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"symlinks unavailable: {type(exc).__name__}")
            with self.assertRaises(ValueError):
                lab_score_suite.run_lab_score_suite(link)

    def test_real_loopback_suite_scores_and_persists_all_capabilities(self) -> None:
        expected_findings = {
            "service_inventory": 1,
            "tls_baseline": 1,
            "http_baseline": 5,
        }
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "real-suite"
            report = lab_score_suite.run_lab_score_suite(output_dir)

            self.assertTrue(report["passed"], json.dumps(report, indent=2))
            self.assertEqual(set(report["scorers"]), set(expected_findings))
            for name, expected_count in expected_findings.items():
                with self.subTest(capability=name):
                    result = report["scorers"][name]
                    self.assertTrue(result["passed"], result)
                    self.assertEqual(
                        result["metrics"]["valid_findings"], expected_count
                    )
                    self.assertTrue(result["checks"])
                    self.assertTrue(all(value is True for value in result["checks"].values()))
                    self.assertGreaterEqual(result["evidence_count"], 2)
                    self.assertTrue((output_dir / result["database_file"]).is_file())
                    self.assertTrue(result["evaluation_record_id"])
            self.assertTrue((output_dir / "report.json").is_file())

    def test_installed_entry_point_targets_suite_main(self) -> None:
        project_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
        project = tomllib.loads(project_path.read_text(encoding="utf-8"))
        self.assertEqual(
            project["project"]["scripts"]["lightup-lab-score-suite"],
            "lightup.lab_score_suite:main",
        )


if __name__ == "__main__":
    unittest.main()
