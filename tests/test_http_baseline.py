from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

from lightup.ai.orchestration import (
    RunContext,
    ToolCall,
    ToolDenied,
    ToolExecutor,
    ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.labeval import LabIsolationError
from lightup.labrun import FIXTURE_EXPECTED, run_lab_baseline
from lightup.state import StateStore
from lightup.workers import http_baseline


class FixtureHandler(BaseHTTPRequestHandler):
    """Mirrors lab/http_fixture.py: Server banner, no defensive headers."""

    server_version = "LightUpFixture/0.1"

    def do_GET(self):
        body = b'{"service":"lightup-fixture","ok":true}\n'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


class HardenedHandler(FixtureHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def version_string(self):
        return "server"  # still a banner, intentionally


class HttpBaselineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "state.db"

    def tearDown(self):
        self.tmp.cleanup()

    def test_worker_refuses_non_lab_targets_before_connecting(self):
        for url in ("http://example.com/", "http://8.8.8.8/", "https://127.0.0.1/"):
            with self.assertRaises(LabIsolationError):
                http_baseline.observe(url)

    def test_worker_refuses_non_lab_context(self):
        from datetime import datetime, timezone

        context = RunContext(
            run_id="r", client_id="c", engagement_id="e",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD, authorization=None,
            is_lab=False, created_at=datetime.now(timezone.utc),
        )
        with self.assertRaises(LabIsolationError):
            http_baseline.run_http_baseline(context, {"url": self.url})

    def test_executor_denies_outside_lab(self):
        registry = ToolRegistry()
        http_baseline.register(registry)
        executor = ToolExecutor(registry, StateStore(self.db))
        from datetime import datetime, timezone

        context = RunContext(
            run_id=str(uuid4()), client_id="c", engagement_id="e",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD, authorization=None,
            is_lab=False, created_at=datetime.now(timezone.utc),
        )
        with self.assertRaises(ToolDenied):
            executor.execute(context, ToolCall(http_baseline.TOOL_ID, self.url,
                                               arguments=(("url", self.url),)))

    def test_fixture_issues_detected(self):
        observation = http_baseline.observe(self.url)
        found = {issue.check_id for issue in observation.issues}
        self.assertIn("missing-content-security-policy", found)
        self.assertIn("missing-x-content-type-options", found)
        self.assertIn("server-banner-disclosure", found)
        self.assertEqual(observation.status, 200)

    def test_end_to_end_lab_run_with_ground_truth(self):
        result = run_lab_baseline(self.url, self.db, expected=FIXTURE_EXPECTED)
        self.assertEqual(result["status"], 200)
        self.assertGreaterEqual(len(result["findings"]), 3)
        metrics = result["evaluation"]["metrics"]
        self.assertEqual(metrics["valid_findings"], len(FIXTURE_EXPECTED))
        self.assertEqual(metrics["invalid_findings"], 0)
        self.assertEqual(metrics["missed_findings"], 0)
        self.assertEqual(metrics["scope_violations"], 0)
        self.assertEqual(metrics["policy_violations"], 0)
        self.assertEqual(metrics["tool_calls"], 1)
        # Evidence is recorded in the ledger.
        state = StateStore(self.db)
        with state.connect() as con:
            row = con.execute("SELECT * FROM evidence WHERE evidence_id=?",
                              (result["evidence_id"],)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["capability_id"], http_baseline.CAPABILITY_ID)
        # Client-facing shape: Finding -> Impact -> Fix -> Retest.
        for finding in result["findings"]:
            for key in ("finding", "impact", "fix", "retest", "severity"):
                self.assertIn(key, finding)
        self.assertIn("# LightUp Assessment Findings", result["report_markdown"])

    def test_hardened_fixture_scores_fewer_findings(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), HardenedHandler)
        url = f"http://127.0.0.1:{server.server_port}/"
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            observation = http_baseline.observe(url)
            found = {issue.check_id for issue in observation.issues}
            self.assertNotIn("missing-content-security-policy", found)
            self.assertNotIn("missing-x-content-type-options", found)
            self.assertEqual(found, {"server-banner-disclosure"})
        finally:
            server.shutdown()
            server.server_close()

    def test_lab_run_refuses_public_url(self):
        with self.assertRaises(LabIsolationError):
            run_lab_baseline("http://example.com/", self.db)

    def test_cli_lab_baseline(self):
        from contextlib import redirect_stdout
        from io import StringIO

        from lightup.cli import main as cli_main

        out = StringIO()
        with redirect_stdout(out):
            code = cli_main(["lab-baseline", self.url,
                             "--db", str(self.db), "--expect-fixture"])
        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["evaluation"]["metrics"]["invalid_findings"], 0)

        out = StringIO()
        with redirect_stdout(out):
            code = cli_main(["lab-baseline", "http://example.com/",
                             "--db", str(self.db)])
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(out.getvalue()))


if __name__ == "__main__":
    unittest.main()
