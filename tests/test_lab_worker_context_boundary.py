from __future__ import annotations

import dataclasses
import unittest
from unittest.mock import patch

from lightup.ai.orchestration import RunContext
from lightup.engagements import AssessmentMode
from lightup.labeval import LabIsolationError
from lightup.workers import http_baseline, service_inventory, tls_baseline


class LabWorkerContextBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.lab = RunContext.for_lab("run-1", engagement_id="lab-1", client_id="client-1")

    def _handlers(self):
        return (
            (
                http_baseline.run_http_baseline,
                {"url": "http://127.0.0.1:1/"},
                "lightup.workers.http_baseline.observe",
            ),
            (
                service_inventory.run_service_inventory,
                {"host": "127.0.0.1", "ports": "1"},
                "lightup.workers.service_inventory.inventory",
            ),
            (
                tls_baseline.run_tls_baseline,
                {"host": "127.0.0.1", "port": 1},
                "lightup.workers.tls_baseline.observe",
            ),
        )

    def _assert_rejected_before_network(self, context):
        for handler, arguments, network_symbol in self._handlers():
            with self.subTest(handler=handler.__name__):
                with patch(network_symbol) as network_call:
                    with self.assertRaises(LabIsolationError):
                        handler(context, arguments)
                    network_call.assert_not_called()

    def test_non_lab_mode_cannot_masquerade_with_lab_marker(self):
        forged = dataclasses.replace(
            self.lab,
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            is_lab=True,
        )
        self._assert_rejected_before_network(forged)

    def test_truthy_non_boolean_lab_marker_is_rejected(self):
        forged = dataclasses.replace(self.lab, is_lab=1)
        self._assert_rejected_before_network(forged)

    def test_lab_context_cannot_carry_target_authorization(self):
        forged = dataclasses.replace(self.lab, authorization=object())
        self._assert_rejected_before_network(forged)

    def test_low_risk_lab_context_remains_semantically_valid(self):
        # Risk ceilings are enforced by ToolExecutor. Direct worker context
        # validation intentionally checks lab provenance, not risk elevation.
        from lightup.engagements import RiskLevel

        low_risk_lab = dataclasses.replace(
            self.lab,
            approved_risk=RiskLevel.LOW_IMPACT,
        )
        with patch("lightup.workers.http_baseline.observe") as observe:
            observe.return_value = http_baseline.BaselineObservation(
                url="http://127.0.0.1:1/",
                status=200,
                headers=(),
                issues=(),
            )
            result = http_baseline.run_http_baseline(
                low_risk_lab,
                {"url": "http://127.0.0.1:1/"},
            )
        self.assertEqual(result.evidence_kind, "http-baseline-observation")


if __name__ == "__main__":
    unittest.main()
