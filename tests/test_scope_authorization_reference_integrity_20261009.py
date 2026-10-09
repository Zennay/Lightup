"""Offline RED contracts: an authorization object needs nonblank provenance.

These tests never perform network I/O or issue real grants. The expected failures
are tracked security requirements, not evidence of production enforcement.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


_HOST = "scope-reference.example.invalid"
_POLICY = ScopePolicy(allow_private_lab=False, explicit_hosts=frozenset({_HOST}))


class ScopeAuthorizationReferenceIntegrity(unittest.TestCase):
    def _decision(self, owner: str, reference: str):
        grant = Authorization(owner=owner, reference=reference)
        return _POLICY.decide(Target(_HOST, authorization=grant))

    def test_missing_grant_is_denied(self):
        outcome = _POLICY.decide(Target(_HOST))
        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_nonblank_reference_is_not_sufficient_for_unlisted_host(self):
        grant = Authorization(owner="test-owner", reference="test-consent")
        outcome = _POLICY.decide(Target("unlisted.example.invalid", authorization=grant))
        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.reason, ScopeReason.OUT_OF_SCOPE)

    @unittest.expectedFailure
    def test_empty_owner_must_not_authorize_public_host(self):
        outcome = self._decision("", "test-consent")
        self.assertFalse(outcome.allowed)

    @unittest.expectedFailure
    def test_whitespace_owner_must_not_authorize_public_host(self):
        outcome = self._decision(" \t ", "test-consent")
        self.assertFalse(outcome.allowed)

    @unittest.expectedFailure
    def test_empty_reference_must_not_authorize_public_host(self):
        outcome = self._decision("test-owner", "")
        self.assertFalse(outcome.allowed)

    @unittest.expectedFailure
    def test_whitespace_reference_must_not_authorize_public_host(self):
        outcome = self._decision("test-owner", "\n\t ")
        self.assertFalse(outcome.allowed)

    def test_expired_authorization_is_denied(self):
        now = datetime.now(timezone.utc)
        grant = Authorization(
            owner="test-owner",
            reference="test-consent",
            valid_until=now - timedelta(days=1),
        )
        outcome = _POLICY.decide(Target(_HOST, authorization=grant))
        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.reason, ScopeReason.AUTHORIZATION_EXPIRED)


if __name__ == "__main__":
    unittest.main()
