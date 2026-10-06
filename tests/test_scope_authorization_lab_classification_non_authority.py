import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeAuthorizationLabClassificationNonAuthorityTests(unittest.TestCase):
    @staticmethod
    def _current():
        return Authorization(owner="owner", reference="AUTH-CURRENT")

    @staticmethod
    def _future():
        now = datetime.now(timezone.utc)
        return Authorization(
            owner="owner",
            reference="AUTH-FUTURE",
            valid_from=now + timedelta(days=1),
            valid_until=now + timedelta(days=2),
        )

    @staticmethod
    def _expired():
        now = datetime.now(timezone.utc)
        return Authorization(
            owner="owner",
            reference="AUTH-EXPIRED",
            valid_from=now - timedelta(days=2),
            valid_until=now - timedelta(days=1),
        )

    def test_loopback_classification_ignores_legacy_authorization_state(self):
        policy = ScopePolicy()

        for authorization in (None, self._current(), self._future(), self._expired()):
            with self.subTest(authorization=authorization):
                decision = policy.decide(
                    Target("127.0.0.1", authorization=authorization)
                )
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.LOOPBACK)

    def test_localhost_classification_ignores_expired_authorization(self):
        decision = ScopePolicy().decide(
            Target("localhost", authorization=self._expired())
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)

    def test_private_lab_classification_ignores_legacy_authorization_state(self):
        policy = ScopePolicy(allow_private_lab=True)

        for authorization in (None, self._current(), self._future(), self._expired()):
            with self.subTest(authorization=authorization):
                decision = policy.decide(
                    Target("10.20.30.40", authorization=authorization)
                )
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.PRIVATE_LAB)

    def test_current_authorization_cannot_bypass_disabled_private_lab_policy(self):
        policy = ScopePolicy(allow_private_lab=False)

        for target in ("10.20.30.40", "169.254.10.20"):
            with self.subTest(target=target):
                decision = policy.decide(
                    Target(target, authorization=self._current())
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
