from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
