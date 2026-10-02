from __future__ import annotations

import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

from lightup.ai.gateway import ModelGateway, ModelRole, ScriptedProvider
from lightup.ai.orchestration import (
    RunContext,
    ToolDefinition,
    ToolExecutor,
    ToolOutput,
    ToolRegistry,
)
from lightup.ai.planner import (
    PlanRejected,
    execute_plan,
    parse_plan,
    request_plan,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.labeval import LabScenario
from lightup.state import StateStore
from lightup.workers import http_baseline, service_inventory


class _Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        return


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    http_baseline.register(registry)
    service_inventory.register(registry)
    # A real-target tool and a destructive lab tool, to prove the gate holds
    # even when the planner proposes them.
    registry.register(
        ToolDefinition("real-target-probe", "network-services",
                       InteractionKind.TARGET_ACTIVE, RiskLevel.STANDARD,
                       "Real-target probe (must never run in a lab)"),
        lambda context, arguments: ToolOutput("x", "note", b"x"),
    )
    registry.register(
        ToolDefinition("destructive-sim", "web-baseline",
                       InteractionKind.LAB_ACTIVE, RiskLevel.DESTRUCTIVE_LAB_ONLY,
                       "Destructive lab simulation"),
        lambda context, arguments: ToolOutput("boom", "note", b"x"),
    )
    return registry


class PlannerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Fixture)
        cls.port = cls.server.server_port
        cls.url = f"http://127.0.0.1:{cls.port}/"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.registry = _registry()
        self.scenario = LabScenario("s1", "multi-lane lab", targets=("127.0.0.1",))

    def _plan_json(self, items) -> str:
        return json.dumps(items)

    def test_valid_plan_parses(self):
        raw = self._plan_json([
            {"tool_id": http_baseline.TOOL_ID, "asset": "127.0.0.1",
             "arguments": {"url": self.url}},
            {"tool_id": service_inventory.TOOL_ID, "asset": "127.0.0.1",
             "arguments": {"host": "127.0.0.1", "ports": str(self.port)}},
        ])
        plan = parse_plan(raw, self.registry, self.scenario)
        self.assertEqual(len(plan), 2)
        self.assertEqual(plan[0].tool_id, http_baseline.TOOL_ID)

    def test_invalid_plans_rejected(self):
        bad_plans = [
            "do whatever you want",                             # prose
            self._plan_json([]),                                 # empty
            self._plan_json([{"tool_id": "rm-rf", "asset": "127.0.0.1"}]),
            self._plan_json([{"tool_id": http_baseline.TOOL_ID,
                              "asset": "example.com",
                              "arguments": {"url": "http://example.com/"}}]),
            self._plan_json([{"tool_id": http_baseline.TOOL_ID,
                              "asset": "127.0.0.1",
                              "arguments": {"url": 42}}]),
            self._plan_json([{"tool_id": service_inventory.TOOL_ID,
                              "asset": "127.0.0.1",
                              "arguments": {"host": "127.0.0.1", "ports": "80",
                                            "extra": "x"}}]),
        ]
        for raw in bad_plans:
            with self.assertRaises(Exception, msg=raw):
                parse_plan(raw, self.registry, self.scenario)
        with self.assertRaises(PlanRejected):
            parse_plan(self._plan_json([
                {"tool_id": http_baseline.TOOL_ID, "asset": "127.0.0.1",
                 "arguments": {"url": self.url}},
                {"tool_id": http_baseline.TOOL_ID, "asset": "127.0.0.1",
                 "arguments": {"url": self.url}},
            ]), self.registry, self.scenario)

    def test_planner_role_via_gateway_and_gated_execution(self):
        plan_payload = self._plan_json([
            {"tool_id": http_baseline.TOOL_ID, "asset": "127.0.0.1",
             "arguments": {"url": self.url}},
            {"tool_id": service_inventory.TOOL_ID, "asset": "127.0.0.1",
             "arguments": {"host": "127.0.0.1", "ports": str(self.port)}},
            {"tool_id": "real-target-probe", "asset": "127.0.0.1"},
            {"tool_id": "destructive-sim", "asset": "127.0.0.1"},
        ])
        gateway = ModelGateway()
        gateway.register_provider(
            ScriptedProvider("scripted", {ModelRole.PLANNER: [plan_payload]}))
        gateway.bind_role(ModelRole.PLANNER, "scripted", "lab-model")
        plan = request_plan(gateway, self.registry, self.scenario)
        self.assertEqual(len(plan), 4)

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        executor = ToolExecutor(self.registry, StateStore(Path(tmp.name) / "s.db"))
        # Lab context with a deliberately low approved risk: the destructive
        # simulation needs an elevation, the real-target probe must be denied.
        context = RunContext(
            run_id=str(uuid4()), client_id="lab", engagement_id="s1",
            mode=AssessmentMode.LAB_AUTONOMOUS, approved_risk=RiskLevel.LOW_IMPACT,
            authorization=None, is_lab=True,
            created_at=datetime.now(timezone.utc),
        )
        execution = execute_plan(executor, context, plan)
        self.assertEqual(len(execution.results), 2)
        self.assertEqual(execution.assessed_capabilities(),
                         ("web-baseline", "network-services"))
        self.assertEqual(execution.policy_violations, 1)
        self.assertEqual(execution.denied[0][0], "real-target-probe")
        self.assertEqual(len(execution.elevation_requests), 1)
        self.assertIn("destructive-sim", execution.elevation_requests[0])

    def test_planner_receives_endpoint_port_and_path_without_changing_scope(self):
        from types import SimpleNamespace
        from unittest.mock import Mock

        endpoint = self.url + "fixture?profile=exposed"
        scenario = LabScenario("endpoint", "endpoint preservation", (endpoint,))
        gateway = Mock()
        gateway.complete.return_value = SimpleNamespace(content=self._plan_json([
            {"tool_id": http_baseline.TOOL_ID, "asset": "127.0.0.1",
             "arguments": {"url": endpoint}}]))
        plan = request_plan(gateway, self.registry, scenario)
        messages = gateway.complete.call_args.args[1]
        payload = json.loads(messages[1].content)["scenario"]
        self.assertEqual(payload["endpoints"], [endpoint])
        self.assertEqual(payload["targets"], ["127.0.0.1"])
        self.assertEqual(dict(plan[0].arguments)["url"], endpoint)

    def test_rejected_plan_never_executes(self):
        gateway = ModelGateway()
        gateway.register_provider(ScriptedProvider(
            "scripted",
            {ModelRole.PLANNER: [self._plan_json(
                [{"tool_id": "rm-rf", "asset": "127.0.0.1"}])]}))
        gateway.bind_role(ModelRole.PLANNER, "scripted", "lab-model")
        with self.assertRaises(PlanRejected):
            request_plan(gateway, self.registry, self.scenario)


if __name__ == "__main__":
    unittest.main()
