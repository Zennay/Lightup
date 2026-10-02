from __future__ import annotations

import json
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from lightup.ai.gateway import ModelGateway, ModelRole, ScriptedProvider
from lightup.domain import AccessContext, DomainStore, Role, TenantIsolationError
from lightup.labeval import ExpectedFinding, LabScenario
from lightup.labrun import FIXTURE_EXPECTED, run_planned_assessment
from lightup.labsync import ensure_lab_engagement, persist_coverage, persist_lab_findings
from lightup.workers import http_baseline, service_inventory, tls_baseline


class _PlainHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        return


class PlannedAssessmentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_class = tempfile.TemporaryDirectory()
        base = Path(cls.tmp_class.name)
        cert, key = base / "cert.pem", base / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "2",
             "-subj", "/CN=127.0.0.1"],
            check=True, capture_output=True,
        )
        cls.http_server = ThreadingHTTPServer(("127.0.0.1", 0), _PlainHandler)
        cls.http_port = cls.http_server.server_port
        threading.Thread(target=cls.http_server.serve_forever, daemon=True).start()

        cls.tls_server = ThreadingHTTPServer(("127.0.0.1", 0), _PlainHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        cls.tls_server.socket = context.wrap_socket(cls.tls_server.socket,
                                                    server_side=True)
        cls.tls_port = cls.tls_server.server_port
        threading.Thread(target=cls.tls_server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.http_server, cls.tls_server):
            server.shutdown()
            server.server_close()
        cls.tmp_class.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _gateway(self) -> ModelGateway:
        plan = json.dumps([
            {"tool_id": http_baseline.TOOL_ID, "asset": "127.0.0.1",
             "arguments": {"url": f"http://127.0.0.1:{self.http_port}/"}},
            {"tool_id": service_inventory.TOOL_ID, "asset": "127.0.0.1",
             "arguments": {"host": "127.0.0.1",
                           "ports": f"{self.http_port},{self.tls_port}"}},
            {"tool_id": tls_baseline.TOOL_ID, "asset": "127.0.0.1",
             "arguments": {"host": "127.0.0.1", "port": self.tls_port}},
        ])
        gateway = ModelGateway()
        gateway.register_provider(
            ScriptedProvider("scripted", {ModelRole.PLANNER: [plan]}))
        gateway.bind_role(ModelRole.PLANNER, "scripted", "lab-model")
        return gateway

    def test_multi_lane_assessment_end_to_end(self):
        expected = FIXTURE_EXPECTED + (
            ExpectedFinding("untrusted-certificate-chain",
                            "Certificate chain not trusted",
                            tls_baseline.CAPABILITY_ID, "medium"),
        )
        scenario = LabScenario("multi-1", "multi-lane", targets=("127.0.0.1",),
                               expected_findings=expected)
        result = run_planned_assessment(self._gateway(), scenario,
                                        self.base / "state.db")
        self.assertEqual(len(result["plan"]), 3)
        self.assertEqual(result["denied"], [])
        self.assertEqual(result["elevation_requests"], [])
        metrics = result["evaluation"]["metrics"]
        self.assertEqual(metrics["policy_violations"], 0)
        self.assertEqual(metrics["tool_calls"], 3)
        self.assertEqual(metrics["invalid_findings"], 0)
        self.assertEqual(metrics["missed_findings"], 0)
        self.assertEqual(metrics["valid_findings"], len(expected))
        self.assertEqual(metrics["coverage_assessed"], 3)
        capabilities = {f["capability_id"] for f in result["findings"]}
        self.assertEqual(capabilities, {"web-baseline", "cryptography"})
        self.assertEqual(result["coverage"]["domains"]["network-services"], "assessed")

    def test_coverage_persists_to_domain_and_is_tenant_scoped(self):
        scenario = LabScenario("multi-2", "multi-lane", targets=("127.0.0.1",))
        result = run_planned_assessment(self._gateway(), scenario,
                                        self.base / "state.db")
        store = DomainStore(self.base / "domain.db")
        operator = AccessContext("op-1", Role.OPERATOR)
        engagement = ensure_lab_engagement(store, operator)
        persist_lab_findings(store, operator, engagement.engagement_id, result)
        written = persist_coverage(store, operator, engagement.engagement_id,
                                   result["coverage"]["domains"])
        self.assertEqual(written, 3)
        stored = store.get_coverage(operator, engagement.engagement_id)
        self.assertEqual(stored["cryptography"], "assessed")
        self.assertNotIn("cloud-iam", stored)  # unknown stays unwritten
        # Tenant scope: another client's context cannot read it.
        other = store.create_client(operator, "Other BV")
        other_ctx = AccessContext("u", Role.CLIENT_ADMIN, other.client_id)
        with self.assertRaises(TenantIsolationError):
            store.get_coverage(other_ctx, engagement.engagement_id)
        # And the client portal page shows the coverage summary.
        from lightup.webapp import create_app
        lab_user = store.create_user(operator, "lab@lightup.test", "Lab",
                                     Role.CLIENT_ADMIN, engagement.client_id)
        store.set_password(operator, lab_user.user_id, "lab-user-password")
        token, _ = store.create_session(lab_user.user_id)
        app = create_app(store)
        import io
        environ = {"REQUEST_METHOD": "GET",
                   "PATH_INFO": f"/portal/{engagement.client_id}",
                   "wsgi.input": io.BytesIO(b""),
                   "HTTP_COOKIE": f"lightup_session={token}"}
        out: dict = {}
        body = b"".join(app(environ, lambda s, h: out.update(status=s))).decode()
        self.assertEqual(out["status"], "200 OK")
        self.assertIn("What has been assessed", body)
        self.assertIn("3 assessed", body)
        self.assertIn("not</strong> a clean bill of health", body)


if __name__ == "__main__":
    unittest.main()
