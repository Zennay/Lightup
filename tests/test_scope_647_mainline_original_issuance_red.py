"""Actual current-main original DomainStore issuance regression canaries (#647).

Four formerly expected-RED original-source defects are now fixed:
DomainStore issuance rejects datetime subclasses that could be checked using
one instant and serialized with a different one. This module never patches production, contacts a target, or
writes beyond a disposable temporary SQLite fixture.

The witness class below keeps these cases green and decorator-free.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition
from lightup.grant_issuance_window_snapshot_647 import (
    WindowRejected, snapshot_grant_issuance_window,
)


class _WideExpiry(datetime):
    def isoformat(self, *args, **kwargs):
        normal = datetime(
            self.year, self.month, self.day, self.hour, self.minute,
            self.second, self.microsecond, tzinfo=self.tzinfo,
        )
        return (normal + timedelta(days=365)).isoformat()


class _BackdatedStart(datetime):
    def isoformat(self, *args, **kwargs):
        normal = datetime(
            self.year, self.month, self.day, self.hour, self.minute,
            self.second, self.microsecond, tzinfo=self.tzinfo,
        )
        return (normal - timedelta(days=365)).isoformat()


def _spoof(kind, dt):
    return kind(
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second,
        dt.microsecond, tzinfo=dt.tzinfo
    )


class OriginalMainlineIssuanceRedTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-647-source-red-")
        self.addCleanup(temp.cleanup)
        self.store = DomainStore(Path(temp.name) / "fixture-only.sqlite")
        self.ctx = AccessContext("synthetic-admin", Role.OPERATOR)
        client = self.store.create_client(self.ctx, "Fixture Tenant (NOT REAL)")
        self.eng = self.store.create_engagement(
            self.ctx, client.client_id, "Offline Fixture Engagement"
        )
        self.scope = ScopeDefinition(
            assets=("fixture.example.test",),
            max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("web-baseline",),
        )
        self.start = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
        self.end = self.start + timedelta(hours=2)

    def _issue_raw(self, start=None, end=None):
        return self.store.record_authorization_grant(
            self.ctx, self.eng.engagement_id, "Fictional Operator",
            "NOT_REAL_CONSENT", self.scope,
            self.start if start is None else start,
            self.end if end is None else end,
        )

    def _raw_window(self, grant_id):
        with self.store._connect() as con:
            return con.execute(
                "SELECT valid_from, valid_until FROM authorization_grants "
                "WHERE grant_id=?", (grant_id,),
            ).fetchone()

    def _count(self):
        with self.store._connect() as con:
            return con.execute(
                "SELECT COUNT(*) FROM authorization_grants"
            ).fetchone()[0]

    def test_normal_canonical_utc_grant_persists_exact_instants(self):
        grant = self._issue_raw()
        row = self._raw_window(grant.grant_id)
        self.assertEqual(row["valid_from"], self.start.isoformat())
        self.assertEqual(row["valid_until"], self.end.isoformat())

    def test_optin_snapshot_defends_end_before_original_source_is_called(self):
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(self.start, _spoof(_WideExpiry, self.end))
        self.assertEqual(self._count(), 0)

    def test_optin_snapshot_defends_start_before_original_source_is_called(self):
        with self.assertRaises(WindowRejected):
            snapshot_grant_issuance_window(
                _spoof(_BackdatedStart, self.start), self.end
            )
        self.assertEqual(self._count(), 0)

    def test_optin_safe_path_stores_actual_utc_when_explicitly_applied(self):
        offset = timezone(timedelta(hours=5, minutes=30))
        source = snapshot_grant_issuance_window(
            self.start.astimezone(offset), self.end.astimezone(offset)
        )
        grant = self._issue_raw(source.starts_at_utc, source.expires_at_utc)
        row = self._raw_window(grant.grant_id)
        self.assertEqual(row["valid_from"], self.start.isoformat())
        self.assertEqual(row["valid_until"], self.end.isoformat())

    def test_red_issuer_must_reject_subclassed_future_expiry_before_grant(self):
        with self.assertRaises(ValueError):
            self._issue_raw(end=_spoof(_WideExpiry, self.end))

    def test_red_issuer_must_reject_subclassed_backdated_start_before_grant(self):
        with self.assertRaises(ValueError):
            self._issue_raw(start=_spoof(_BackdatedStart, self.start))

    def test_red_persisted_expiry_must_equal_original_approved_instant(self):
        # Fixed by rejecting the spoof before persistence: no widened row exists.
        with self.assertRaises(ValueError):
            self._issue_raw(end=_spoof(_WideExpiry, self.end))
        self.assertEqual(self._count(), 0)

    def test_red_persisted_start_must_equal_original_approved_instant(self):
        # Fixed by rejecting the spoof before persistence: no backdated row exists.
        with self.assertRaises(ValueError):
            self._issue_raw(start=_spoof(_BackdatedStart, self.start))
        self.assertEqual(self._count(), 0)

    def test_falsey_invalid_timestamp_must_not_masquerade_as_safe_snapshot(self):
        for candidate in (False, 0, "", None, {}):
            with self.subTest(value=repr(candidate)):
                with self.assertRaises(WindowRejected):
                    snapshot_grant_issuance_window(self.start, candidate)
        self.assertEqual(self._count(), 0)

    def test_no_network_access_in_disposable_issuance_fixture(self):
        with patch("socket.socket", side_effect=AssertionError("network")), \
             patch("socket.create_connection", side_effect=AssertionError("network")):
            self._issue_raw()
            self.assertEqual(self._count(), 1)


class OriginalMainlineRedWitnessIntegrityTests(unittest.TestCase):
    RED_CASES = (
        "test_red_issuer_must_reject_subclassed_future_expiry_before_grant",
        "test_red_issuer_must_reject_subclassed_backdated_start_before_grant",
        "test_red_persisted_expiry_must_equal_original_approved_instant",
        "test_red_persisted_start_must_equal_original_approved_instant",
    )

    def test_formerly_red_cases_now_pass_without_expected_failure(self):
        for case in self.RED_CASES:
            fn = OriginalMainlineIssuanceRedTests.__dict__[case]
            self.assertFalse(getattr(fn, "__unittest_expecting_failure__", False))
        result = unittest.TestResult()
        suite = unittest.TestSuite([
            OriginalMainlineIssuanceRedTests(case) for case in self.RED_CASES
        ])
        suite.run(result)
        self.assertEqual(result.testsRun, 4)
        self.assertFalse(result.errors)
        self.assertFalse(result.failures)
        self.assertFalse(result.expectedFailures)
        self.assertTrue(result.wasSuccessful())


if __name__ == "__main__":
    unittest.main()
