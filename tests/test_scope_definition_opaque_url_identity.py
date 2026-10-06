import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel, ScopeDefinition


class DurableAssetOpaqueUrlTests(unittest.TestCase):
    def _scope(self, assets, excluded_assets=()):
        return ScopeDefinition(
            assets=tuple(assets),
            excluded_assets=tuple(excluded_assets),
            allowed_capabilities=("web-baseline",),
            max_risk=RiskLevel.LOW_IMPACT,
        )

    def test_scheme_bearing_entry_does_not_authorize_embedded_host(self):
        scope = self._scope(("https://security.example.test",))
        self.assertFalse(scope.allows_asset("security.example.test"))
        self.assertTrue(scope.allows_asset("https://security.example.test"))

    def test_userinfo_entry_does_not_authorize_embedded_host(self):
        scope = self._scope(("operator@security.example.test",))
        self.assertFalse(scope.allows_asset("security.example.test"))
        self.assertTrue(scope.allows_asset("operator@security.example.test"))

    def test_port_entry_does_not_authorize_plain_host(self):
        scope = self._scope(("security.example.test:8443",))
        self.assertFalse(scope.allows_asset("security.example.test"))
        self.assertTrue(scope.allows_asset("security.example.test:8443"))

    def test_path_query_fragment_entries_do_not_authorize_plain_host(self):
        decorated = (
            "security.example.test/path",
            "security.example.test?mode=scan",
            "security.example.test#fragment",
        )
        for entry in decorated:
            with self.subTest(entry=entry):
                scope = self._scope((entry,))
                self.assertFalse(scope.allows_asset("security.example.test"))
                self.assertTrue(scope.allows_asset(entry))

    def test_network_path_entry_does_not_authorize_plain_host(self):
        scope = self._scope(("//security.example.test",))
        self.assertFalse(scope.allows_asset("security.example.test"))
        self.assertTrue(scope.allows_asset("//security.example.test"))

    def test_url_like_exclusion_does_not_parse_exclude_plain_host(self):
        scope = self._scope(
            ("security.example.test",),
            ("https://security.example.test",),
        )
        self.assertTrue(scope.allows_asset("security.example.test"))

    def test_plain_host_exact_membership_remains_unchanged(self):
        scope = self._scope((" Security.Example.Test ",))
        self.assertTrue(scope.allows_asset("security.example.test"))


if __name__ == "__main__":
    unittest.main()
