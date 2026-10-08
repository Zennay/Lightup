"""Offline regression: URL parser must not erase embedded ASCII controls before scope admission.

Expected RED on current main for tab/CR/LF in an otherwise exact allowlisted host.
No DNS, sockets, active execution or real destinations.
"""
import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class HostControlCharacterAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"authorized.example.test"}),
            require_authorization_for_public=True,
        )
        self.authorization = Authorization(owner="fixture", reference="offline-only")

    def _decide(self, value):
        return self.policy.decide(Target(value, authorization=self.authorization))

    def test_exact_host_positive_control(self):
        decision = self._decide("https://authorized.example.test/")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_tab_in_url_host_must_not_inherit_allowlist(self):
        self.assertFalse(self._decide("https://author\tized.example.test/").allowed)

    def test_cr_in_url_host_must_not_inherit_allowlist(self):
        self.assertFalse(self._decide("https://author\rized.example.test/").allowed)

    def test_lf_in_url_host_must_not_inherit_allowlist(self):
        self.assertFalse(self._decide("https://author\nized.example.test/").allowed)

    def test_embedded_control_without_url_scheme_must_not_inherit_allowlist(self):
        self.assertFalse(self._decide("author\tized.example.test").allowed)

    def test_embedded_tab_must_not_promote_to_loopback_hostname(self):
        self.assertFalse(ScopePolicy().decide(Target("local\thost")).allowed)

    def test_embedded_tab_must_not_promote_to_loopback_address(self):
        self.assertFalse(ScopePolicy().decide(Target("127.0.0.\t1")).allowed)

    def test_embedded_tab_must_not_promote_to_private_lab_address(self):
        self.assertFalse(ScopePolicy().decide(Target("10.\t0.0.1")).allowed)

    def test_exact_loopback_still_allowed(self):
        self.assertTrue(ScopePolicy().decide(Target("127.0.0.1")).allowed)


if __name__ == "__main__":
    unittest.main()
