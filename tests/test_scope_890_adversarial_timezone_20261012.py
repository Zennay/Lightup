"""#890 W3: exceptions from caller-provided tzinfo must not touch grant store.

The uninstalled adapter is non-authorizing and does not change DomainStore.
All real persistence is disposable synthetic SQLite.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from unittest.mock import Mock

from lightup.current_grant_instant_optin import checked_current_grant_at
from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition


class RaisingTz(tzinfo):
    def __init__(self, failure):
        self.failure = failure

    def utcoffset(self, dt):
        raise self.failure


class NullOffsetTz(tzinfo):
    def utcoffset(self, dt):
        return None


class ValidCustomTz(tzinfo):
    def utcoffset(self, dt):
        return timedelta(hours=2)

    def dst(self, dt):
        return timedelta(0)


class GrantTimezoneFaultW3(unittest.TestCase):
    def setUp(self):
        self.fake = Mock()
        self.ctx = AccessContext("test-operator", Role.OPERATOR)
        self.engagement_id = "synthetic-engagement"

    def assert_rejected_before_store(self, zone):
        instant = datetime(2026, 10, 12, 22, 30, tzinfo=zone)
        with self.assertRaises(ValueError):
            checked_current_grant_at(
                self.fake, self.ctx, self.engagement_id, now=instant,
            )
        self.fake.get_current_grant.assert_not_called()

    def test_runtime_error_tz_offset_is_controlled_denial(self):
        self.assert_rejected_before_store(RaisingTz(RuntimeError("private fixture token")))

    def test_keyerror_tz_offset_is_controlled_denial(self):
        self.assert_rejected_before_store(RaisingTz(KeyError("opaque-state")))

    def test_typeerror_tz_offset_is_controlled_denial(self):
        self.assert_rejected_before_store(RaisingTz(TypeError("bad offset")))

    def test_overflow_tz_offset_is_controlled_denial(self):
        self.assert_rejected_before_store(RaisingTz(OverflowError("overflow")))

    def test_null_offset_tz_is_controlled_denial(self):
        self.assert_rejected_before_store(NullOffsetTz())

    def test_exception_text_is_not_echoed_to_caller(self):
        with self.assertRaises(ValueError) as caught:
            checked_current_grant_at(
                self.fake, self.ctx, self.engagement_id,
                now=datetime(2026, 10, 12, tzinfo=RaisingTz(
                    RuntimeError("sensitive-internal-input-canary")
                )),
            )
        self.assertNotIn("sensitive-internal-input-canary", str(caught.exception))

    def test_aware_exact_builtin_datetime_is_delegated_unmodified(self):
        instant = datetime(2026, 10, 12, 22, 30, tzinfo=ValidCustomTz())
        self.fake.get_current_grant.return_value = None
        self.assertIsNone(checked_current_grant_at(
            self.fake, self.ctx, self.engagement_id, now=instant,
        ))
        self.fake.get_current_grant.assert_called_once_with(
            self.ctx, self.engagement_id, now=instant,
        )

    def test_builtin_fixed_offset_is_still_accepted(self):
        instant = datetime(
            2026, 10, 12, 22, 30,
            tzinfo=timezone(timedelta(hours=-7)),
        )
        self.fake.get_current_grant.return_value = None
        self.assertIsNone(checked_current_grant_at(
            self.fake, self.ctx, self.engagement_id, now=instant,
        ))
        self.fake.get_current_grant.assert_called_once_with(
            self.ctx, self.engagement_id, now=instant,
        )

    def test_naive_datetime_denied_before_selector(self):
        with self.assertRaises(ValueError):
            checked_current_grant_at(
                self.fake, self.ctx, self.engagement_id,
                now=datetime(2026, 10, 12, 22, 30),
            )
        self.fake.get_current_grant.assert_not_called()

    def test_real_sqlite_grant_rows_unchanged_after_adversarial_timezone(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "w3.db"
        store = DomainStore(path)
        client = store.create_client(self.ctx, "Synthetic tenant")
        engagement = store.create_engagement(
            self.ctx, client.client_id, "Synthetic engagement",
        )
        now = datetime.now(timezone.utc)
        grant = store.record_authorization_grant(
            self.ctx, engagement.engagement_id, "Synthetic approver", "LAB-890-W3",
            ScopeDefinition(("w3.example.test",), RiskLevel.PASSIVE),
            now - timedelta(hours=1), now + timedelta(hours=1),
        )
        with sqlite3.connect(path) as connection:
            before = connection.execute(
                "SELECT * FROM authorization_grants ORDER BY grant_id"
            ).fetchall()
        for failure in (RuntimeError("private"), TypeError("private"), KeyError("private")):
            with self.subTest(type=type(failure).__name__), self.assertRaises(ValueError):
                checked_current_grant_at(
                    store, self.ctx, engagement.engagement_id,
                    now=datetime(2026, 10, 12, tzinfo=RaisingTz(failure)),
                )
        with sqlite3.connect(path) as connection:
            after = connection.execute(
                "SELECT * FROM authorization_grants ORDER BY grant_id"
            ).fetchall()
        self.assertEqual(before, after)
        self.assertEqual(
            checked_current_grant_at(
                store, self.ctx, engagement.engagement_id, now=now,
            ).grant_id, grant.grant_id,
        )


if __name__ == "__main__":
    unittest.main()
