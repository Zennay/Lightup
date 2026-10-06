import os
import socket
import sys
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeDnsIndependenceTests(unittest.TestCase):
    def _forbid_dns_and_socket_io(self):
        stack = ExitStack()
        for name in (
            "getaddrinfo",
            "gethostbyname",
            "gethostbyname_ex",
            "getnameinfo",
            "create_connection",
        ):
            stack.enter_context(
                patch.object(
                    socket,
                    name,
                    side_effect=AssertionError(
                        f"scope classification must not call socket.{name}"
                    ),
                )
            )
        return stack

    def test_unknown_hostname_cannot_gain_loopback_scope_from_dns(self):
        policy = ScopePolicy()

        with self._forbid_dns_and_socket_io():
            decision = policy.decide(Target("rebinding.example.test"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "rebinding.example.test")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_explicit_hostname_authorization_is_syntactic_and_offline(self):
        auth = Authorization(owner="example-owner", reference="AUTH-DNS-001")
        policy = ScopePolicy(explicit_hosts=frozenset({"security.example.test"}))

        with self._forbid_dns_and_socket_io():
            decision = policy.decide(
                Target(
                    "https://Security.Example.Test./status",
                    authorization=auth,
                )
            )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "security.example.test")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_explicit_hostname_still_requires_current_authorization_offline(self):
        expired = Authorization(
            owner="example-owner",
            reference="AUTH-DNS-OLD",
            valid_until=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        policy = ScopePolicy(explicit_hosts=frozenset({"security.example.test"}))

        with self._forbid_dns_and_socket_io():
            decision = policy.decide(
                Target("security.example.test", authorization=expired)
            )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_literal_ip_network_scope_is_decided_without_dns(self):
        auth = Authorization(owner="example-owner", reference="AUTH-NET-001")
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("203.0.113.0/24",),
        )

        with self._forbid_dns_and_socket_io():
            decision = policy.decide(
                Target("203.0.113.42", authorization=auth)
            )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "203.0.113.42")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_localhost_is_a_syntactic_special_case_without_dns(self):
        with self._forbid_dns_and_socket_io():
            decision = ScopePolicy().decide(Target("LOCALHOST."))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "localhost")
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)


if __name__ == "__main__":
    unittest.main()
