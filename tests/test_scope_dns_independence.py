import ast
import os
import socket
import sys
import unittest
from pathlib import Path
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
            "gethostbyaddr",
            "getfqdn",
            "getnameinfo",
            "create_connection",
            "socket",
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

    def test_scope_module_has_no_network_or_dns_client_imports(self):
        scope_path = (
            Path(__file__).resolve().parents[1] / "src" / "lightup" / "scope.py"
        )
        tree = ast.parse(scope_path.read_text(encoding="utf-8"))
        forbidden_modules = (
            "socket",
            "http.client",
            "urllib.request",
            "requests",
            "httpx",
            "dns",
        )
        found = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(
                        alias.name == module or alias.name.startswith(f"{module}.")
                        for module in forbidden_modules
                    ):
                        found.append(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                if any(
                    node.module == module or node.module.startswith(f"{module}.")
                    for module in forbidden_modules
                ):
                    found.append(node.module)

        self.assertEqual(
            found,
            [],
            "scope policy must stay syntactic/local and import no network clients",
        )

    def test_unknown_hostname_cannot_gain_loopback_scope_from_dns(self):
        policy = ScopePolicy()

        with self._forbid_dns_and_socket_io():
            decision = policy.decide(Target("rebinding.example.test"))

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "rebinding.example.test")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_resolver_answers_cannot_convert_unknown_hostname_to_local_authority(self):
        fake_answers = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 443),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("10.20.30.40", 443),
            ),
        ]
        with patch.object(socket, "getaddrinfo", return_value=fake_answers) as resolver:
            decision = ScopePolicy().decide(Target("mutable.example.test"))

        resolver.assert_not_called()
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "mutable.example.test")
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
