import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeAuthorizationOfflineResolutionContractTests(unittest.TestCase):
    @staticmethod
    def _authorization_for(*assets: str) -> Authorization:
        kwargs = {
            "owner": "security-team",
            "reference": "AUTH-OFFLINE-SCOPE",
        }
        if "assets" in Authorization.__dataclass_fields__:
            kwargs["assets"] = tuple(assets)
        return Authorization(**kwargs)

    def _decide_without_network(self, policy: ScopePolicy, target: Target):
        forbidden = AssertionError("scope classification must not perform DNS or socket I/O")
        with (
            patch("socket.getaddrinfo", side_effect=forbidden) as getaddrinfo,
            patch("socket.gethostbyname", side_effect=forbidden) as gethostbyname,
            patch("socket.gethostbyname_ex", side_effect=forbidden) as gethostbyname_ex,
            patch("socket.gethostbyaddr", side_effect=forbidden) as gethostbyaddr,
            patch("socket.getnameinfo", side_effect=forbidden) as getnameinfo,
            patch("socket.getfqdn", side_effect=forbidden) as getfqdn,
            patch("socket.create_connection", side_effect=forbidden) as create_connection,
            patch("socket.socket", side_effect=forbidden) as socket_ctor,
        ):
            decision = policy.decide(target)

        for mocked in (
            getaddrinfo,
            gethostbyname,
            gethostbyname_ex,
            gethostbyaddr,
            getnameinfo,
            getfqdn,
            create_connection,
            socket_ctor,
        ):
            mocked.assert_not_called()

        return decision

    def test_unknown_hostname_cannot_gain_scope_from_dns(self):
        decision = self._decide_without_network(
            ScopePolicy(),
            Target("rebind.example.test"),
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "rebind.example.test")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_loopback_looking_hostname_is_not_resolver_promoted(self):
        decision = self._decide_without_network(
            ScopePolicy(),
            Target("127.0.0.1.rebind.example.test"),
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.normalized_host,
            "127.0.0.1.rebind.example.test",
        )
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_explicit_authorized_host_is_decided_without_dns(self):
        decision = self._decide_without_network(
            ScopePolicy(explicit_hosts=frozenset({"security.example.test"})),
            Target(
                "https://security.example.test/path",
                authorization=self._authorization_for("security.example.test"),
            ),
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "security.example.test")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_explicit_public_network_literal_is_decided_without_dns(self):
        decision = self._decide_without_network(
            ScopePolicy(
                allow_private_lab=False,
                explicit_networks=("203.0.113.0/24",),
            ),
            Target(
                "203.0.113.17",
                authorization=self._authorization_for("203.0.113.17"),
            ),
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "203.0.113.17")
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_localhost_is_a_syntactic_local_case_not_a_dns_case(self):
        decision = self._decide_without_network(
            ScopePolicy(),
            Target("localhost"),
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "localhost")
        self.assertEqual(decision.reason, ScopeReason.LOOPBACK)


if __name__ == "__main__":
    unittest.main()
