from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, Role
from lightup.labeval import LabIsolationError
from lightup.labsync import (
    ensure_lab_engagement,
    persist_coverage,
    persist_lab_findings,
    retest_finding,
)
from lightup.models import RetestStatus, Severity
from lightup.workers import http_baseline


class LabSyncProvenanceBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-scope", Role.OPERATOR)
        self.known_title = http_baseline.BASELINE_CHECKS[0][2]

    def _record(self, engagement_id: str, asset: str = "http://127.0.0.1/"):
        return self.store.record_finding(
            self.operator,
            engagement_id,
            self.known_title,
            Severity.MEDIUM,
            asset,
            "Lab impact",
            "Lab remediation",
        )

    def test_lab_persistence_rejects_normal_client_engagement(self):
        client = self.store.create_client(self.operator, "Customer A")
        engagement = self.store.create_engagement(
            self.operator, client.client_id, "Customer assessment"
        )

        with self.assertRaises(LabIsolationError):
            persist_lab_findings(
                self.store,
                self.operator,
                engagement.engagement_id,
                {"findings": []},
            )
        with self.assertRaises(LabIsolationError):
            persist_coverage(
                self.store,
                self.operator,
                engagement.engagement_id,
                {"web-baseline": "assessed"},
            )

    def test_retest_rejects_non_lab_finding_before_observation(self):
        client = self.store.create_client(self.operator, "Customer B")
        engagement = self.store.create_engagement(
            self.operator, client.client_id, "Customer retest"
        )
        finding = self._record(engagement.engagement_id)

        with patch("lightup.labsync.http_baseline.observe") as observe:
            with self.assertRaises(LabIsolationError):
                retest_finding(self.store, self.operator, finding)
            observe.assert_not_called()

    def test_retest_rejects_forged_lab_finding_before_observation(self):
        engagement = ensure_lab_engagement(self.store, self.operator)
        finding = self._record(engagement.engagement_id)
        forged = dataclasses.replace(finding, asset="http://127.0.0.2/")

        with patch("lightup.labsync.http_baseline.observe") as observe:
            with self.assertRaises(LabIsolationError):
                retest_finding(self.store, self.operator, forged)
            observe.assert_not_called()

    def test_retest_rejects_stale_lab_finding_before_observation(self):
        engagement = ensure_lab_engagement(self.store, self.operator)
        finding = self._record(engagement.engagement_id)
        self.store.set_retest_status(
            self.operator, finding.finding_id, RetestStatus.FIXED
        )

        with patch("lightup.labsync.http_baseline.observe") as observe:
            with self.assertRaises(LabIsolationError):
                retest_finding(self.store, self.operator, finding)
            observe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
