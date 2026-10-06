import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


UTC = timezone.utc


class ScopeRevocationPrecedenceTests(unittest.TestCase):
    def _authorization(
        self,
        *,
        asset: str,
        revoked: bool,
        expired: bool = False,
    ) -> Authorization:
        return Authorization(
            owner="scope-precedence-fixture",
            reference="AUTH-REVOCATION-PRECEDENCE",
            valid_from=datetime(2000, 1, 1, tzinfo=UTC),
            valid_until=datetime(2001, 1, 1, tzinfo=UTC) if expired else datetime(2100, 1, 1, tzinfo=UTC),
            assets=(asset,),
            revoked_at=datetime(2020, 1, 1, tzinfo=UTC) if revoked else None,
            revoked_by="operator-1" if revoked else None,
            revocation_reason="authorization withdrawn" if revoked else None,
        )

    def test_revoked_current_host_authorization_is_terminal(self):
        host = "security.example.test"
        policy = ScopePolicy(explicit_hosts=frozenset({host}))
        decision = policy.decide(
            Target(host, authorization=self._authorization(asset=host, revoked=True))
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, host)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_REVOKED)

    def test_revoked_and_expired_host_still_reports_revocation(self):
        host = "security.example.test"
        policy = ScopePolicy(explicit_hosts=frozenset({host}))
        decision = policy.decide(
            Target(
                host,
                authorization=self._authorization(
                    asset=host,
                    revoked=True,
                    expired=True,
                ),
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_REVOKED)

    def test_revoked_network_authorization_is_terminal(self):
        asset = "8.8.8.8"
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24",))
        decision = policy.decide(
            Target(asset, authorization=self._authorization(asset=asset, revoked=True))
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, asset)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_REVOKED)

    def test_revocation_precedes_asset_mismatch(self):
        host = "security.example.test"
        policy = ScopePolicy(explicit_hosts=frozenset({host}))
        decision = policy.decide(
            Target(
                host,
                authorization=self._authorization(
                    asset="different.example.test",
                    revoked=True,
                ),
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_REVOKED)

    def test_non_revoked_expired_authorization_keeps_expiry_reason(self):
        host = "security.example.test"
        policy = ScopePolicy(explicit_hosts=frozenset({host}))
        decision = policy.decide(
            Target(
                host,
                authorization=self._authorization(
                    asset=host,
                    revoked=False,
                    expired=True,
                ),
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)


if __name__ == "__main__":
    unittest.main()
