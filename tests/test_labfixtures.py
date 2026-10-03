from __future__ import annotations

import contextlib
import io
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from lightup.ai.gateway import ModelRole
from lightup.ai.pipeline import AssessmentReviewPipeline
from lightup.labeval import LabScenario
from lightup.labfixtures import PROFILES, FixtureProfile, expected_findings, make_handler
from lightup.labrun import main_assess, run_lab_baseline, run_planned_assessment, scripted_demo_gateway


@contextlib.contextmanager
def _serve(profile: FixtureProfile):
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(profile))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()


class ProfileDefinitionTest(unittest.TestCase):
    def test_profiles_are_well_formed(self):
        self.assertEqual(set(PROFILES), {"exposed", "partially-hardened", "hardened"})
        for name, profile in PROFILES.items():
            self.assertEqual(name, profile.profile_id)
            self.assertTrue(profile.description)

    def test_unknown_planted_check_is_rejected(self):
        with self.assertRaises(ValueError):
            FixtureProfile("bad", "x", (), None, ("no-such-check",))

    def test_duplicate_planted_check_is_rejected(self):
        with self.assertRaises(ValueError):
            FixtureProfile("bad", "x", (), None,
                           ("missing-referrer-policy", "missing-referrer-policy"))


class PlantedGroundTruthTest(unittest.TestCase):
    """The engine must find exactly what each profile plants — no more, no less."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_each_profile_scores_perfectly_against_its_own_truth(self):
        for name, profile in PROFILES.items():
            with self.subTest(profile=name), _serve(profile) as url:
                result = run_lab_baseline(url, self.base / f"{name}.db",
                                          expected=expected_findings(profile))
                metrics = result["evaluation"]["metrics"]
                self.assertEqual(metrics["valid_findings"], len(profile.expected_check_ids))
                self.assertEqual(metrics["invalid_findings"], 0)
                self.assertEqual(metrics["missed_findings"], 0)
                self.assertEqual({f["check_id"] for f in result["findings"]},
                                 set(profile.expected_check_ids))

    def test_zero_finding_ground_truth_counts_unexpected_results(self):
        with _serve(PROFILES["exposed"]) as url:
            single = run_lab_baseline(url, self.base / "zero-single.db", expected=())
            scenario = LabScenario("zero", "zero findings expected", (url,),
                                   expected_findings=())
            multi = run_planned_assessment(scripted_demo_gateway((url,)), scenario,
                                           self.base / "zero-multi.db")
        for result in (single, multi):
            self.assertEqual(result["evaluation"]["metrics"]["invalid_findings"],
                             len(PROFILES["exposed"].expected_check_ids))
            self.assertEqual(result["evaluation"]["metrics"]["false_positive_rate"], 1.0)
            self.assertIn("scored against", result["evaluation"]["notes"])

    def test_unspecified_ground_truth_remains_unscored(self):
        with _serve(PROFILES["exposed"]) as url:
            single = run_lab_baseline(url, self.base / "unscored-single.db")
            scenario = LabScenario("unknown", "unknown truth", (url,))
            multi = run_planned_assessment(scripted_demo_gateway((url,)), scenario,
                                           self.base / "unscored-multi.db")
        for result in (single, multi):
            self.assertIn("unscored", result["evaluation"]["notes"])
            self.assertEqual(result["evaluation"]["metrics"]["invalid_findings"], 0)
            self.assertEqual(len(result["findings"]),
                             len(PROFILES["exposed"].expected_check_ids))

    def test_mismatched_truth_is_scored_honestly(self):
        # A hardened fixture scored against the exposed profile's truth must
        # report everything as missed — never as a clean pass.
        with _serve(PROFILES["hardened"]) as url:
            result = run_lab_baseline(url, self.base / "mismatch.db",
                                      expected=expected_findings(PROFILES["exposed"]))
        metrics = result["evaluation"]["metrics"]
        self.assertEqual(metrics["valid_findings"], 0)
        self.assertEqual(metrics["invalid_findings"], 0)
        self.assertEqual(metrics["missed_findings"],
                         len(PROFILES["exposed"].expected_check_ids))


class ScriptedDemoGatewayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_demo_gateway_plans_http_and_inventory_lanes(self):
        profile = PROFILES["exposed"]
        with _serve(profile) as url:
            scenario = LabScenario("demo", "demo", targets=(url,),
                                   expected_findings=expected_findings(profile))
            gateway = scripted_demo_gateway((url,))
            result = run_planned_assessment(gateway, scenario, self.base / "s.db")
            self.assertEqual([c["tool_id"] for c in result["plan"]],
                             ["lab-http-baseline", "lab-service-inventory"])
            metrics = result["evaluation"]["metrics"]
            self.assertEqual(metrics["valid_findings"], len(profile.expected_check_ids))
            self.assertEqual(metrics["missed_findings"], 0)
            self.assertEqual(metrics["policy_violations"], 0)
            # The demo gateway also binds the review roles (echo fallback).
            review = AssessmentReviewPipeline(gateway).review(result).to_dict()
            self.assertEqual(len(review["findings"]), len(profile.expected_check_ids))
            self.assertTrue(review["findings"][0]["verdict"].startswith("[verifier]"))
            self.assertEqual(review["model_bindings"]["verifier"], "scripted/scripted-demo")

    def test_demo_gateway_rejects_non_http_endpoints(self):
        with self.assertRaises(ValueError):
            scripted_demo_gateway(("127.0.0.1",))

    def test_demo_gateway_fails_closed_on_public_endpoints(self):
        with self.assertRaises(PermissionError):
            scripted_demo_gateway(("http://8.8.8.8/",))


class LabAssessCliTest(unittest.TestCase):
    def test_cli_runs_offline_with_profile_scoring_and_review(self):
        profile = PROFILES["partially-hardened"]
        with tempfile.TemporaryDirectory() as tmp, _serve(profile) as url:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main_assess([url, "--db", str(Path(tmp) / "cli.db"),
                                    "--profile", "partially-hardened"])
            self.assertEqual(code, 0)
            result = json.loads(stdout.getvalue())
            metrics = result["evaluation"]["metrics"]
            self.assertEqual(metrics["valid_findings"], len(profile.expected_check_ids))
            self.assertEqual(metrics["missed_findings"], 0)
            self.assertIn("review", result)

    def test_cli_hardened_profile_still_counts_unexpected_findings(self):
        with tempfile.TemporaryDirectory() as tmp, _serve(PROFILES["exposed"]) as url:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main_assess([url, "--db", str(Path(tmp) / "zero-cli.db"),
                                    "--profile", "hardened", "--no-review"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout.getvalue())["evaluation"]["metrics"]
                             ["invalid_findings"],
                             len(PROFILES["exposed"].expected_check_ids))

    def test_cli_fails_closed_on_public_target(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main_assess(["http://8.8.8.8/", "--db", "unused.db", "--no-review"])
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(stdout.getvalue()))


class ExampleConfigTest(unittest.TestCase):
    """The shipped example config must stay loadable and key-free."""

    def test_example_config_shape(self):
        path = Path(__file__).resolve().parent.parent / "config" / "gateway.example.json"
        config = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("anthropic", config["providers"])
        self.assertEqual(config["providers"]["anthropic"]["type"], "anthropic")
        # Keys are referenced by environment variable name, never stored.
        for spec in config["providers"].values():
            self.assertNotIn("api_key", spec)
        self.assertEqual(config["providers"]["anthropic"]["api_key_env"],
                         "ANTHROPIC_API_KEY")
        for role_name, binding in config["roles"].items():
            ModelRole(role_name)  # raises on unknown roles
            self.assertEqual(binding["provider"], "anthropic")
            self.assertTrue(binding["model"])


if __name__ == "__main__":
    unittest.main()
