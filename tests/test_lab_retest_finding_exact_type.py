from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, FindingRecord, Role
from lightup.labeval import LabIsolationError
from lightup.labsync import ensure_lab_engagement, retest_finding
from lightup.models import RetestStatus, Severity
from lightup.workers import http_baseline


class EqualitySpoofFinding(FindingRecord):
    def __getattribute__(self, name: str):
        if name == "title":
            reads = object.__getattribute__(self, "__dict__").get("_title_reads", 0)
            object.__setattr__(self, "_title_reads", reads + 1)
        return super().__getattribute__(name)

    @property
    def title_reads(self) -> int:
        return object.__getattribute__(self, "__dict__").get("_title_reads", 0)

    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False


class LabRetestFindingExactTypeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-1", Role.OPERATOR)
        self.engagement = ensure_lab_engagement(self.store, self.operator)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_polymorphic_finding_rejects_before_check_selection_or_observation(self):
        first_check_id, _first_header, first_title, *_ = http_baseline.BASELINE_CHECKS[0]
        second_check_id, _second_header, second_title, *_ = http_baseline.BASELINE_CHECKS[1]
        self.assertNotEqual(first_check_id, second_check_id)
        self.assertNotEqual(first_title, second_title)

        persisted = self.store.record_finding(
            self.operator,
            self.engagement.engagement_id,
            title=first_title,
            severity=Severity.MEDIUM,
            asset="http://127.0.0.1:18080/",
            impact="Fixture impact",
            remediation="Fixture remediation",
        )
        before_rows = self.store.list_findings(
            self.operator, engagement_id=self.engagement.engagement_id
        )

        forged = EqualitySpoofFinding(
            finding_id=persisted.finding_id,
            client_id=persisted.client_id,
            engagement_id=persisted.engagement_id,
            title=second_title,
            severity=persisted.severity,
            asset=persisted.asset,
            impact=persisted.impact,
            remediation=persisted.remediation,
            retest_status=persisted.retest_status,
            evidence_ids=persisted.evidence_ids,
            created_at=persisted.created_at,
        )
        forged_snapshot = tuple(
            object.__getattribute__(forged, field)
            for field in FindingRecord.__dataclass_fields__
        )
        self.assertEqual(forged.title_reads, 0)

        observation = SimpleNamespace(
            issues=(SimpleNamespace(check_id=second_check_id),)
        )
        with patch(
            "lightup.labsync.http_baseline.observe", return_value=observation
        ) as observe:
            with self.assertRaises(LabIsolationError):
                retest_finding(self.store, self.operator, forged)

        observe.assert_not_called()
        self.assertEqual(forged.title_reads, 0)
        self.assertEqual(
            tuple(
                object.__getattribute__(forged, field)
                for field in FindingRecord.__dataclass_fields__
            ),
            forged_snapshot,
        )
        self.assertEqual(
            self.store.list_findings(
                self.operator, engagement_id=self.engagement.engagement_id
            ),
            before_rows,
        )
        self.assertIs(before_rows[0].retest_status, RetestStatus.NOT_TESTED)


if __name__ == "__main__":
    unittest.main()
