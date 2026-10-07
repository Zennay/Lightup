from __future__ import annotations

import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from lightup.labeval import ExpectedFinding, LabScenario
from lightup.labrun import run_planned_assessment, scripted_demo_gateway
from lightup.workers import tls_baseline


class _TlsFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        return


class TlsLabGroundTruthTest(unittest.TestCase):
    """Calibrate the planner-driven TLS lane against one planted condition."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        cls.cert = base / "cert.pem"
        cls.key = base / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(cls.key),
                "-out",
                str(cls.cert),
                "-days",
                "2",
                "-subj",
                "/CN=127.0.0.1",
            ],
            check=True,
            capture_output=True,
        )

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _TlsFixtureHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(cls.cert), str(cls.key))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_port
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def test_planner_scores_self_signed_tls_fixture_against_explicit_truth(self):
        check_id = "untrusted-certificate-chain"
        title, severity, _impact, _remediation = tls_baseline.TLS_CHECKS[check_id]
        expected = (
            ExpectedFinding(
                check_id,
                title,
                tls_baseline.CAPABILITY_ID,
                severity.value,
            ),
        )
        url = f"https://127.0.0.1:{self.port}/"
        scenario = LabScenario(
            "tls-self-signed-ground-truth",
            "Modern self-signed TLS fixture",
            targets=(url,),
            expected_findings=expected,
        )

        with tempfile.TemporaryDirectory() as tmp:
            result = run_planned_assessment(
                scripted_demo_gateway((url,)),
                scenario,
                Path(tmp) / "state.db",
            )

        tls_calls = [
            call for call in result["plan"]
            if call["tool_id"] == tls_baseline.TOOL_ID
        ]
        self.assertEqual(len(tls_calls), 1)
        self.assertEqual(tls_calls[0]["asset"], "127.0.0.1")
        self.assertEqual(tls_calls[0]["arguments"]["host"], "127.0.0.1")
        self.assertEqual(tls_calls[0]["arguments"]["port"], self.port)

        findings = {
            finding["check_id"]: finding
            for finding in result["findings"]
        }
        self.assertEqual(set(findings), {check_id})
        self.assertEqual(findings[check_id]["capability_id"], tls_baseline.CAPABILITY_ID)
        self.assertEqual(findings[check_id]["target"], "127.0.0.1")

        metrics = result["evaluation"]["metrics"]
        self.assertEqual(metrics["valid_findings"], 1)
        self.assertEqual(metrics["invalid_findings"], 0)
        self.assertEqual(metrics["missed_findings"], 0)
        self.assertEqual(metrics["false_positive_rate"], 0.0)
        self.assertEqual(metrics["policy_violations"], 0)
        self.assertEqual(result["denied"], [])
        self.assertEqual(result["elevation_requests"], [])


if __name__ == "__main__":
    unittest.main()
