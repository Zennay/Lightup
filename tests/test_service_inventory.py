from __future__ import annotations

import json
import socket
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
from lightup.coverage import CoverageReport, CoverageStatus
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.labeval import LabIsolationError
from lightup.state import StateStore
from lightup.workers import service_inventory


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        return


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ServiceInventoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.open_port = cls.server.server_port
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_refuses_non_lab_hosts(self):
        with self.assertRaises(LabIsolationError):
            service_inventory.inventory("example.com", (80,))
        with self.assertRaises(LabIsolationError):
            service_inventory.inventory("8.8.8.8", (53,))

    def test_port_spec_validation(self):
        self.assertEqual(service_inventory.parse_ports("80, 443,80"), (80, 443))
        with self.assertRaises(ValueError):
            service_inventory.parse_ports("")
        with self.assertRaises(ValueError):
            service_inventory.parse_ports("70000")
        with self.assertRaises(ValueError):
            service_inventory.parse_ports(",".join(str(p) for p in range(1, 40)))

    def test_detects_open_and_closed_ports(self):
        closed = _free_port()
        results = service_inventory.inventory("127.0.0.1", (self.open_port, closed))
        self.assertTrue(results[self.open_port])
        self.assertFalse(results[closed])

    def test_executor_path_and_evidence(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        state = StateStore(Path(tmp.name) / "state.db")
        registry = ToolRegistry()
        service_inventory.register(registry)
        executor = ToolExecutor(registry, state)

        lab = RunContext.for_lab(run_id=str(uuid4()))
        result = executor.execute(lab, ToolCall(
            service_inventory.TOOL_ID, "127.0.0.1",
            arguments=(("host", "127.0.0.1"), ("ports", str(self.open_port))),
        ))
        self.assertEqual(result.capability_id, "network-services")
        self.assertEqual(dict(result.metadata)["open_ports"], str(self.open_port))
        with state.connect() as con:
            row = con.execute("SELECT * FROM evidence WHERE evidence_id=?",
                              (result.evidence_id,)).fetchone()
        payload = json.loads(row["metadata_json"])
        self.assertEqual(payload["asset"], "127.0.0.1")

        from datetime import datetime, timezone
        real = RunContext(
            run_id=str(uuid4()), client_id="c", engagement_id="e",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD, authorization=None,
            is_lab=False, created_at=datetime.now(timezone.utc),
        )
        with self.assertRaises(ToolDenied):
            executor.execute(real, ToolCall(
                service_inventory.TOOL_ID, "127.0.0.1",
                arguments=(("host", "127.0.0.1"), ("ports", "80")),
            ))


class CoverageTest(unittest.TestCase):
    def test_defaults_to_unknown_and_flags_it(self):
        report = CoverageReport.build()
        counts = report.counts()
        self.assertEqual(counts[CoverageStatus.ASSESSED.value], 0)
        self.assertGreater(counts[CoverageStatus.UNKNOWN.value], 20)
        self.assertTrue(report.is_materially_unknown)
        data = report.to_dict()
        self.assertIs(data["clean_bill_of_health"], False)
        self.assertIn("clean bill of health", data["note"])

    def test_assessed_domains_tracked(self):
        report = CoverageReport.build({"web-baseline": CoverageStatus.ASSESSED,
                                       "network-services": CoverageStatus.PARTIALLY_ASSESSED})
        data = report.to_dict()
        self.assertEqual(data["domains"]["web-baseline"], "assessed")
        self.assertEqual(data["domains"]["network-services"], "partially_assessed")
        self.assertEqual(data["domains"]["cloud-iam"], "unknown")

    def test_unknown_capability_rejected(self):
        with self.assertRaises(ValueError):
            CoverageReport.build({"nonexistent": CoverageStatus.ASSESSED})


if __name__ == "__main__":
    unittest.main()
