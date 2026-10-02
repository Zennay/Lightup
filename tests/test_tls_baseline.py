from __future__ import annotations

import ssl
import subprocess
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
from lightup.state import StateStore
from lightup.workers import tls_baseline


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        return


class TlsBaselineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        cls.cert = base / "cert.pem"
        cls.key = base / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(cls.key), "-out", str(cls.cert), "-days", "2",
             "-subj", "/CN=127.0.0.1"],
            check=True, capture_output=True,
        )
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cls.cert), str(cls.key))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_port
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def test_refuses_non_lab_hosts(self):
        with self.assertRaises(LabIsolationError):
            tls_baseline.observe("example.com", 443)
        with self.assertRaises(ValueError):
            tls_baseline.observe("127.0.0.1", 70000)

    def test_self_signed_lab_endpoint_flagged_untrusted(self):
        observation = tls_baseline.observe("127.0.0.1", self.port)
        self.assertFalse(observation.chain_trusted)
        found = {issue.check_id for issue in observation.issues}
        self.assertIn("untrusted-certificate-chain", found)
        # A modern local stack should not negotiate a legacy protocol.
        self.assertNotIn("legacy-tls-protocol", found)
        self.assertIn(observation.protocol, {"TLSv1.2", "TLSv1.3"})

    def test_executor_path_lab_only(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        state = StateStore(Path(tmp.name) / "state.db")
        registry = ToolRegistry()
        tls_baseline.register(registry)
        executor = ToolExecutor(registry, state)

        lab = RunContext.for_lab(run_id=str(uuid4()))
        result = executor.execute(lab, ToolCall(
            tls_baseline.TOOL_ID, "127.0.0.1",
            arguments=(("host", "127.0.0.1"), ("port", self.port)),
        ))
        self.assertEqual(result.capability_id, "cryptography")
        self.assertIn("untrusted-certificate-chain",
                      dict(result.metadata)["issues"])

        from datetime import datetime, timezone
        real = RunContext(
            run_id=str(uuid4()), client_id="c", engagement_id="e",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD, authorization=None,
            is_lab=False, created_at=datetime.now(timezone.utc),
        )
        with self.assertRaises(ToolDenied):
            executor.execute(real, ToolCall(
                tls_baseline.TOOL_ID, "127.0.0.1",
                arguments=(("host", "127.0.0.1"), ("port", self.port)),
            ))


if __name__ == "__main__":
    unittest.main()
