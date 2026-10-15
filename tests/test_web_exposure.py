from __future__ import annotations

import contextlib
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.ai.orchestration import RunContext, ToolCall, ToolExecutor
from lightup.benchmark import run_benchmark
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.labeval import LabEvaluationHarness, LabIsolationError, LabScenario, score_findings
from lightup.labfixtures_web import (
    WEB_PROFILES,
    WebFixtureProfile,
    make_web_handler,
    web_expected_findings,
)
from lightup.labrun import full_lab_registry
from lightup.state import StateStore
from lightup.workers import web_exposure


@contextlib.contextmanager
def _serve(profile):
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_web_handler(profile))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()


def _run(url, tmp):
    registry = full_lab_registry()
    executor = ToolExecutor(registry, StateStore(tmp))
    harness = LabEvaluationHarness()
    scenario = LabScenario("web", "web", (url,))
    context = harness.start_run(scenario)
    result = executor.execute(
        context, ToolCall(web_exposure.TOOL_ID, asset=scenario.targets[0],
                          arguments=(("url", url),)))
    return dict(result.metadata)


class ProfileScoringTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_each_profile_scores_against_its_own_truth(self):
        for name, profile in WEB_PROFILES.items():
            with self.subTest(profile=name), _serve(profile) as url:
                meta = _run(url, f"{self.tmp.name}/{name}.db")
                found = tuple(i for i in meta["issues"].split(",") if i)
                valid, invalid, missed = score_findings(web_expected_findings(profile), found)
                self.assertEqual(invalid, 0, f"{name} false positives: {found}")
                self.assertEqual(missed, 0, f"{name} missed, found: {found}")

    def test_catch_all_server_suppresses_path_checks(self):
        with _serve(WEB_PROFILES["catch-all"]) as url:
            meta = _run(url, f"{self.tmp.name}/catchall.db")
        self.assertEqual(meta["soft_404"], "true")
        self.assertEqual(meta["issues"], "")

    def test_hardened_profile_has_no_findings(self):
        with _serve(WEB_PROFILES["web-hardened"]) as url:
            meta = _run(url, f"{self.tmp.name}/hard.db")
        self.assertEqual(meta["issues"], "")


class ProfileDefinitionTest(unittest.TestCase):
    def test_unknown_planted_check_rejected(self):
        with self.assertRaises(ValueError):
            WebFixtureProfile("bad", "x", expected_check_ids=("no-such-check",))

    def test_profiles_well_formed(self):
        self.assertEqual(set(WEB_PROFILES), {"leaky-app", "web-hardened", "catch-all"})


class SafetyTest(unittest.TestCase):
    def test_non_lab_context_refused(self):
        context = RunContext(
            run_id="r", client_id="c", engagement_id="e",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT, approved_risk=RiskLevel.STANDARD,
            authorization=None, is_lab=False,
            created_at=__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc))
        with self.assertRaises(LabIsolationError):
            web_exposure.run_web_exposure(context, {"url": "http://127.0.0.1/"})

    def test_public_target_fails_closed(self):
        with self.assertRaises(LabIsolationError):
            web_exposure._validated_lab_endpoint("http://example.com/")

    def test_https_refused(self):
        with self.assertRaises(LabIsolationError):
            web_exposure._validated_lab_endpoint("https://127.0.0.1/")


class BenchmarkTest(unittest.TestCase):
    def test_full_benchmark_is_perfect(self):
        report = run_benchmark()
        self.assertTrue(report.all_perfect, report.to_dict())
        self.assertEqual(report.micro_scores()["f1"], 1.0)
        self.assertGreaterEqual(report.to_dict()["totals"]["profiles"], 6)


if __name__ == "__main__":
    unittest.main()
