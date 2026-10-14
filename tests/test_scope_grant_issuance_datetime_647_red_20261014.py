"""Expected-RED issue #647: synthetic durable-grant datetime subclass spoofing.

Pinned to original #554 source-owner HEAD. Source under src/lightup is untouched.
Each test uses a freshly created disposable SQLite database with .test assets,
never actual customer data or any target/network interaction.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class _WideExpiry(datetime):
    def isoformat(self, *args, **kwargs):
        return (_exact_datetime(self) + timedelta(days=365)).isoformat(*args, **kwargs)


class _EarlyStart(datetime):
    def isoformat(self, *args, **kwargs):
        return (_exact_datetime(self) - timedelta(days=365)).isoformat(*args, **kwargs)


def _exact_datetime(value):
    return datetime(
        value.year, value.month, value.day, value.hour, value.minute,
        value.second, value.microsecond, tzinfo=value.tzinfo, fold=value.fold,
    )


def _cast_datetime(cls, value):
    return cls(
        value.year, value.month, value.day, value.hour, value.minute,
        value.second, value.microsecond, tzinfo=value.tzinfo, fold=value.fold,
    )


class PersistedGrantDatetimeIssuanceRedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "synthetic-only.db")
        self.operator = AccessContext("synthetic-operator", Role.OPERATOR)
        self.client = self.store.create_client(self.operator, "Fictional Client")
        self.engagement = self.store.create_engagement(
            self.operator, self.client.client_id, "Synthetic scope"
        )
        self.scope = ScopeDefinition(
            assets=("fixture.example.test",),
            max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("web-baseline",),
        )
        self.now = datetime.now(timezone.utc)
        self.start = self.now - timedelta(hours=1)
        self.end = self.now + timedelta(hours=1)

    def _issue(self, start=None, end=None):
        return self.store.record_authorization_grant(
            self.operator, self.engagement.engagement_id,
            "Synthetic operator", "NON-AUTHORIZING-TEST-ONLY",
            self.scope, self.start if start is None else start,
            self.end if end is None else end,
        )

    def _stored_window(self, grant_id):
        with self.store._connect() as con:
            row = con.execute(
                "SELECT valid_from, valid_until FROM authorization_grants WHERE grant_id=?",
                (grant_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return row["valid_from"], row["valid_until"]

    def test_exact_builtin_aware_datetimes_roundtrip_without_widening(self):
        grant = self._issue()
        self.assertIs(type(grant.valid_from), datetime)
        self.assertIs(type(grant.valid_until), datetime)
        self.assertEqual(self._stored_window(grant.grant_id),
                         (self.start.isoformat(), self.end.isoformat()))

    def test_naive_expiry_denied_without_row(self):
        with self.assertRaises(ValueError):
            self._issue(end=self.end.replace(tzinfo=None))
        with self.store._connect() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM authorization_grants").fetchone()[0], 0)

    def test_empty_window_denied_without_row(self):
        with self.assertRaises(ValueError):
            self._issue(start=self.end, end=self.start)
        with self.store._connect() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM authorization_grants").fetchone()[0], 0)

    @unittest.expectedFailure
    def test_red_overridden_expiry_serializer_must_be_refused_at_issuance(self):
        with self.assertRaises(ValueError):
            self._issue(end=_cast_datetime(_WideExpiry, self.end))

    @unittest.expectedFailure
    def test_red_overridden_start_serializer_must_be_refused_at_issuance(self):
        with self.assertRaises(ValueError):
            self._issue(start=_cast_datetime(_EarlyStart, self.start))

    @unittest.expectedFailure
    def test_red_durable_expiry_must_not_exceed_original_exact_instant(self):
        grant = self._issue(end=_cast_datetime(_WideExpiry, self.end))
        _, stored_until = self._stored_window(grant.grant_id)
        self.assertEqual(stored_until, self.end.isoformat())

    @unittest.expectedFailure
    def test_red_durable_start_must_not_predate_original_exact_instant(self):
        grant = self._issue(start=_cast_datetime(_EarlyStart, self.start))
        stored_start, _ = self._stored_window(grant.grant_id)
        self.assertEqual(stored_start, self.start.isoformat())

    def test_normal_issued_grant_resolver_denies_after_canonical_expiry(self):
        from unittest.mock import patch
        grant = self._issue()
        with patch("lightup.domain.utcnow", return_value=self.end + timedelta(days=7)):
            self.assertIsNone(self.store.resolve_authorization_for_execution(grant))

    def test_normal_issued_grant_resolver_denies_before_canonical_start(self):
        from unittest.mock import patch
        grant = self._issue()
        with patch("lightup.domain.utcnow", return_value=self.start - timedelta(days=7)):
            self.assertIsNone(self.store.resolve_authorization_for_execution(grant))

    @unittest.expectedFailure
    def test_red_post_expiry_live_resolver_must_not_trust_widened_durable_until(self):
        # Control lives in disposable SQLite; no real executor or target I/O.
        from unittest.mock import patch
        grant = self._issue(end=_cast_datetime(_WideExpiry, self.end))
        with patch("lightup.domain.utcnow", return_value=self.end + timedelta(days=7)):
            self.assertIsNone(self.store.resolve_authorization_for_execution(grant))

    @unittest.expectedFailure
    def test_red_pre_start_live_resolver_must_not_trust_widened_durable_from(self):
        from unittest.mock import patch
        grant = self._issue(start=_cast_datetime(_EarlyStart, self.start))
        with patch("lightup.domain.utcnow", return_value=self.start - timedelta(days=7)):
            self.assertIsNone(self.store.resolve_authorization_for_execution(grant))


if __name__ == "__main__":
    unittest.main()
