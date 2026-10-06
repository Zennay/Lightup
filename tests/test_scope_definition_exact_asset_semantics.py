import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel, ScopeDefinition


class DurableAssetExactnessTests(unittest.TestCase):
    def _scope(self, assets, excluded_assets=()):
        return ScopeDefinition(
            assets=tuple(assets),
            excluded_assets=tuple(excluded_assets),
            allowed_capabilities=("web-baseline",),
            max_risk=RiskLevel.LOW_IMPACT,
        )

    def test_parent_asset_does_not_authorize_child_host(self):
        scope = self._scope(("example.test",))
        self.assertFalse(scope.allows_asset("api.example.test"))

    def test_wildcard_looking_asset_is_literal_not_pattern(self):
        scope = self._scope(("*.example.test",))
        self.assertFalse(scope.allows_asset("api.example.test"))
        self.assertTrue(scope.allows_asset("*.example.test"))

    def test_leading_dot_asset_does_not_authorize_subdomain(self):
        scope = self._scope((".example.test",))
        self.assertFalse(scope.allows_asset("api.example.test"))
        self.assertTrue(scope.allows_asset(".example.test"))

    def test_child_asset_does_not_authorize_parent(self):
        scope = self._scope(("api.example.test",))
        self.assertFalse(scope.allows_asset("example.test"))

    def test_suffix_lookalike_remains_out_of_scope(self):
        scope = self._scope(("example.test",))
        self.assertFalse(scope.allows_asset("example.test.attacker.test"))

    def test_exact_asset_keeps_case_and_whitespace_normalization(self):
        scope = self._scope(("  Security.Example.Test  ",))
        self.assertTrue(scope.allows_asset(" security.example.test "))

    def test_wildcard_looking_exclusion_is_literal_not_pattern(self):
        scope = self._scope(
            ("api.example.test",),
            excluded_assets=("*.example.test",),
        )
        self.assertTrue(scope.allows_asset("api.example.test"))
        self.assertFalse(scope.allows_asset("*.example.test"))


if __name__ == "__main__":
    unittest.main()
