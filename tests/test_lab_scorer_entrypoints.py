from __future__ import annotations

import io
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
