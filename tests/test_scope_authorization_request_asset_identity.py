from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import AssessmentMode, RiskLevel


class _SwitchingStripAsset(str):
    def __new__(cls, underlying: str, *strip_values: str):
        obj = super().__new__(cls, underlying)
        obj.strip_values = strip_values
        obj.calls = 0
        return obj

    def strip(self, chars=None):
        value = self.strip_values[min(self.calls, len(self.strip_values) - 1)]
        self.calls += 1
        return value


class AssessmentRequestAssetIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("op-request-assets", Role.OPERATOR)
        self.client = self.store.create_client(
            self.operator, "Assessment Request Asset Client"
        )
        self.client_ctx = AccessContext(
            "client-request-assets",
            Role.CLIENT_MEMBER,
            self.client.client_id,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _submit(self, assets):
        return self.store.submit_assessment_request(
            self.client_ctx,
            requested_assets=assets,
            requested_mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            requested_risk=RiskLevel.STANDARD,
            notes="asset identity acceptance",
        )

    def _request_rows(self) -> list[tuple[str, ...]]:
        return [
            record.requested_assets
            for record in self.store.list_assessment_requests(self.client_ctx)
        ]

    def test_exact_builtin_assets_persist_one_trimmed_snapshot(self) -> None:
        request = self._submit(
            ("  app.request-assets.example  ", "   ", "api.request-assets.example")
        )
        self.assertEqual(
            request.requested_assets,
            ("app.request-assets.example", "api.request-assets.example"),
        )
        self.assertEqual(self._request_rows(), [request.requested_assets])

    def test_polymorphic_asset_cannot_switch_filter_and_persisted_identity(self) -> None:
        asset = _SwitchingStripAsset(
            "foreign-underlying.example",
            "approved-at-filter.example",
            "different-at-persistence.example",
        )
        before = self._request_rows()

        with self.assertRaises(
            ValueError,
            msg="assessment-request assets must be canonical built-in strings",
        ):
            self._submit((asset,))

        self.assertEqual(
            asset.calls,
            0,
            "non-canonical asset must be rejected before overridable strip() is called",
        )
        self.assertEqual(
            self._request_rows(),
            before,
            "rejected asset identity must not create an assessment-request row",
        )

    def test_matching_text_string_subclass_is_still_noncanonical(self) -> None:
        asset = _SwitchingStripAsset(
            "app.request-assets.example",
            "app.request-assets.example",
            "app.request-assets.example",
        )
        before = self._request_rows()

        with self.assertRaises(ValueError):
            self._submit((asset,))

        self.assertEqual(asset.calls, 0)
        self.assertEqual(self._request_rows(), before)


if __name__ == "__main__":
    unittest.main()
