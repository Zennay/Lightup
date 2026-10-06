from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class BlankDurableAssetAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-blank-asset", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Blank asset client")
        self.engagement = self.store.create_engagement(
            self.operator,
            self.client.client_id,
            "Blank asset acceptance",
        )
        now = datetime.now(timezone.utc)
        self.valid_from = now - timedelta(minutes=5)
        self.valid_until = now + timedelta(days=1)

    def tearDown(self):
        self.tmp.cleanup()

    def _record(self, scope: ScopeDefinition, reference: str) -> None:
        self.store.record_authorization_grant(
            self.operator,
            self.engagement.engagement_id,
            "Scope approver",
            reference,
            scope,
            self.valid_from,
            self.valid_until,
        )

    def test_whitespace_only_allow_asset_is_rejected_before_persistence(self):
        scope = ScopeDefinition(
            assets=("   ",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        with self.assertRaises(ValueError):
            self._record(scope, "AUTH-BLANK-ALLOW")

    def test_mixed_valid_and_blank_allow_assets_fail_closed(self):
        scope = ScopeDefinition(
            assets=("app.example.test", "  "),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        with self.assertRaises(ValueError):
            self._record(scope, "AUTH-MIXED-BLANK-ALLOW")

    def test_blank_excluded_asset_is_rejected_before_persistence(self):
        scope = ScopeDefinition(
            assets=("app.example.test",),
            excluded_assets=("\t",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        with self.assertRaises(ValueError):
            self._record(scope, "AUTH-BLANK-EXCLUDE")

    def test_non_string_allow_asset_is_rejected_before_persistence(self):
        scope = ScopeDefinition(
            assets=(123,),  # type: ignore[arg-type]
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        with self.assertRaises((TypeError, ValueError)):
            self._record(scope, "AUTH-NONSTRING-ALLOW")

    def test_non_string_excluded_asset_is_rejected_before_persistence(self):
        scope = ScopeDefinition(
            assets=("app.example.test",),
            excluded_assets=(123,),  # type: ignore[arg-type]
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        with self.assertRaises((TypeError, ValueError)):
            self._record(scope, "AUTH-NONSTRING-EXCLUDE")

    def test_invalid_scope_writes_no_grant_rows(self):
        scope = ScopeDefinition(
            assets=(" ",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        with self.assertRaises(ValueError):
            self._record(scope, "AUTH-NO-ROW")
        self.assertEqual(
            self.store.list_authorization_grants(
                self.operator,
                self.engagement.engagement_id,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
