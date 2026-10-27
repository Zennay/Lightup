from __future__ import annotations

import json
import unittest

from lightup.ai.orchestration import (
    ParamKind,
    ToolDefinition,
    ToolOutput,
    ToolParameter,
    ToolRegistry,
)
from lightup.ai.planner import PlanRejected, parse_plan
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.labeval import LabScenario


def _handler(context, arguments):
    return ToolOutput("unused", "note", b"unused")


class PlannerArgumentScopeBindingTest(unittest.TestCase):
    def setUp(self):
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                "lab-url-probe",
                "web-baseline",
                InteractionKind.LAB_ACTIVE,
                RiskLevel.LOW_IMPACT,
                "Lab URL probe",
                parameters=(ToolParameter("url", ParamKind.STRING, required=True),),
            ),
            _handler,
        )
        self.registry.register(
            ToolDefinition(
                "lab-host-probe",
                "network-services",
                InteractionKind.LAB_ACTIVE,
                RiskLevel.LOW_IMPACT,
                "Lab host probe",
                parameters=(ToolParameter("host", ParamKind.STRING, required=True),),
            ),
            _handler,
        )
        self.registry.register(
            ToolDefinition(
                "analysis-host-label",
                "network-services",
                InteractionKind.ANALYSIS,
                RiskLevel.ANALYSIS_ONLY,
                "Analysis metadata containing a host-shaped field",
                parameters=(ToolParameter("host", ParamKind.STRING, required=True),),
            ),
            _handler,
        )

    def _parse(self, scenario, tool_id, asset, arguments):
        return parse_plan(
            json.dumps(
                [{"tool_id": tool_id, "asset": asset, "arguments": arguments}]
            ),
            self.registry,
            scenario,
        )

    def test_lab_url_argument_may_preserve_port_path_and_query(self):
        scenario = LabScenario("url", "URL binding", ("127.0.0.1",))
        plan = self._parse(
            scenario,
            "lab-url-probe",
            "127.0.0.1",
            {"url": "http://127.0.0.1:18080/fixture?profile=exposed"},
        )
        self.assertEqual(len(plan), 1)

    def test_lab_url_argument_cannot_move_to_another_loopback_host(self):
        scenario = LabScenario("url", "URL binding", ("127.0.0.1",))
        with self.assertRaisesRegex(PlanRejected, "not scenario asset"):
            self._parse(
                scenario,
                "lab-url-probe",
                "127.0.0.1",
                {"url": "http://127.0.0.2:18080/"},
            )

    def test_lab_host_argument_cannot_move_to_another_private_host(self):
        scenario = LabScenario("host", "Host binding", ("10.23.0.5",))
        with self.assertRaisesRegex(PlanRejected, "not scenario asset"):
            self._parse(
                scenario,
                "lab-host-probe",
                "10.23.0.5",
                {"host": "10.23.0.6"},
            )

    def test_public_network_argument_is_rejected_before_execution(self):
        scenario = LabScenario("url", "URL binding", ("127.0.0.1",))
        with self.assertRaisesRegex(PlanRejected, "not an isolated lab target"):
            self._parse(
                scenario,
                "lab-url-probe",
                "127.0.0.1",
                {"url": "https://example.com/"},
            )

    def test_analysis_host_metadata_is_not_treated_as_network_scope(self):
        scenario = LabScenario("analysis", "Analysis binding", ("127.0.0.1",))
        plan = self._parse(
            scenario,
            "analysis-host-label",
            "127.0.0.1",
            {"host": "display-only-label"},
        )
        self.assertEqual(len(plan), 1)


if __name__ == "__main__":
    unittest.main()
