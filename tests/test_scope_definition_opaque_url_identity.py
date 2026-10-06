import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel, ScopeDefinition


class DurableAssetOpaqueUrlTests(unittest.TestCase):
    def _scope_or_reject(self, assets, excluded_assets=()):
        try:
            return ScopeDefinition(
                assets=tuple(assets),
                excluded_assets=tuple(excluded_assets),
                allowed_capabilities=("web-baseline",),
                max_risk=RiskLevel.LOW_IMPACT,
            )
        except (TypeError, ValueError):
            return None

    def _assert_decorated_entry_cannot_authorize_host(self, entry):
        scope = self._scope_or_reject((entry,))
        if scope is None:
            return
        self.assertFalse(scope.allows_asset("security.example.test"))

    def test_scheme_bearing_entry_does_not_authorize_embedded_host(self):
        self._assert_decorated_entry_cannot_authorize_host(
            "https://security.example.test"
        )

    def test_userinfo_entry_does_not_authorize_embedded_host(self):
        self._assert_decorated_entry_cannot_authorize_host(
            "operator@security.example.test"
        )

    def test_port_entry_does_not_authorize_plain_host(self):
        self._assert_decorated_entry_cannot_authorize_host(
            "security.example.test:8443"
        )

    def test_path_query_fragment_entries_do_not_authorize_plain_host(self):
        decorated = (
            "security.example.test/path",
            "security.example.test?mode=scan",
            "security.example.test#fragment",
        )
        for entry in decorated:
            with self.subTest(entry=entry):
                self._assert_decorated_entry_cannot_authorize_host(entry)

    def test_network_path_entry_does_not_authorize_plain_host(self):
        self._assert_decorated_entry_cannot_authorize_host(
            "//security.example.test"
        )

    def test_url_like_exclusion_never_parse_excludes_plain_host(self):
        scope = self._scope_or_reject(
            ("security.example.test",),
            ("https://security.example.test",),
        )
        if scope is None:
            return
        self.assertTrue(scope.allows_asset("security.example.test"))

    def test_plain_host_exact_membership_remains_unchanged(self):
        scope = self._scope_or_reject((" Security.Example.Test ",))
        self.assertIsNotNone(scope)
        self.assertTrue(scope.allows_asset("security.example.test"))


if __name__ == "__main__":
    unittest.main()
