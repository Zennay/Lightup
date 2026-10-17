"""Issue #1563: legacy grants cannot manufacture public scope membership.

Pure in-memory, negative-only acceptance. This intentionally does not specify
the positive grant shape (owned by the active scope source owner).
"""

from __future__ import annotations

import os
import sys
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


def _grant_variants():
    now = datetime.now(timezone.utc)
    return (
        ("absent", None),
        ("current", Authorization(owner="synthetic-owner", reference="SYN-ONLY")),
        (
            "expired",
            Authorization(
                owner="synthetic-owner",
                reference="SYN-EXPIRED",
                valid_until=now - timedelta(days=1),
            ),
        ),
        (
            "future",
            Authorization(
                owner="synthetic-owner",
                reference="SYN-FUTURE",
                valid_from=now + timedelta(days=1),
            ),
        ),
    )


def _block_all_external_and_grant_admission(stack: ExitStack) -> None:
    def unexpected(*_args, **_kwargs):
        raise AssertionError(
            "Scope membership rejection must not perform I/O or evaluate grant validity"
        )

    for path in (
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.create_connection",
        "urllib.request.urlopen",
    ):
        stack.enter_context(patch(path, side_effect=unexpected))

    stack.enter_context(patch.object(Authorization, "is_current", unexpected))


class ScopeMembershipMetamorphicTests(unittest.TestCase):
    """Membership-negative fixtures only: no positive grants, execution or targets."""

    def _reject_off_scope(self, policy: ScopePolicy, target: Target) -> None:
        before = (target.value, target.authorization, target.labels)
        with ExitStack() as stack:
            _block_all_external_and_grant_admission(stack)
            decision = policy.decide(target)
        self.assertIs(decision.allowed, False)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertEqual((target.value, target.authorization, target.labels), before)

    def _reject_invalid(self, policy: ScopePolicy, target: Target) -> None:
        before = (target.value, target.authorization, target.labels)
        with ExitStack() as stack:
            _block_all_external_and_grant_admission(stack)
            decision = policy.decide(target)
        self.assertIs(decision.allowed, False)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
        self.assertIsNone(decision.normalized_host)
        self.assertEqual((target.value, target.authorization, target.labels), before)

    def test_undeclared_public_hostname_is_invariant_under_grant_substitution(self):
        for require_auth in (True, False):
            policy = ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"declared.example.test"}),
                explicit_networks=("8.8.8.0/24",),
                require_authorization_for_public=require_auth,
            )
            for value in (
                "unknown.example.test",
                "https://unknown.example.test/limited/path",
                "sub.declared.example.test",
            ):
                for grant_name, grant in _grant_variants():
                    with self.subTest(flag=require_auth, value=value, grant=grant_name):
                        self._reject_off_scope(
                            policy,
                            Target(value=value, authorization=grant, labels=("fictional",)),
                        )

    def test_undeclared_public_network_is_invariant_under_grant_substitution(self):
        # 8.8.8.0/24 is declared, 8.8.4.4, 1.1.1.1 and 9.9.9.9 are not.
        for require_auth in (True, False):
            policy = ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"declared.example.test"}),
                explicit_networks=("8.8.8.0/24",),
                require_authorization_for_public=require_auth,
            )
            for value in ("8.8.4.4", "1.1.1.1", "https://9.9.9.9/"):
                for grant_name, grant in _grant_variants():
                    with self.subTest(flag=require_auth, value=value, grant=grant_name):
                        self._reject_off_scope(policy, Target(value, authorization=grant))

    def test_invalid_target_cannot_be_rescued_by_grant_or_auth_flag(self):
        for require_auth in (True, False):
            policy = ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"declared.example.test"}),
                explicit_networks=("8.8.8.0/24",),
                require_authorization_for_public=require_auth,
            )
            for invalid in ("", "  ", "https://", "https:///"):
                for grant_name, grant in _grant_variants():
                    with self.subTest(flag=require_auth, invalid=invalid, grant=grant_name):
                        self._reject_invalid(policy, Target(invalid, authorization=grant))

    def test_unrelated_declared_hosts_cannot_change_membership(self):
        for other in (
            frozenset(),
            frozenset({"allowed.example.test"}),
            frozenset({"allowed.example.test", "other.example.test"}),
        ):
            for require_auth in (True, False):
                for _, grant in _grant_variants():
                    with self.subTest(other=sorted(other), flag=require_auth):
                        self._reject_off_scope(
                            ScopePolicy(
                                allow_private_lab=False,
                                explicit_hosts=other,
                                require_authorization_for_public=require_auth,
                            ),
                            Target("never-declared.example.test", authorization=grant),
                        )

    def test_unrelated_declared_networks_cannot_change_membership(self):
        for networks in ((), ("8.8.8.0/24",), ("8.8.8.0/24", "1.1.1.0/24")):
            for require_auth in (True, False):
                for _, grant in _grant_variants():
                    with self.subTest(networks=networks, flag=require_auth):
                        self._reject_off_scope(
                            ScopePolicy(
                                allow_private_lab=False,
                                explicit_networks=networks,
                                require_authorization_for_public=require_auth,
                            ),
                            Target("9.9.9.9", authorization=grant),
                        )


if __name__ == "__main__":
    unittest.main()
