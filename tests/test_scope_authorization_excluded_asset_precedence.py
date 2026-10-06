import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel, ScopeDefinition


class ScopeAuthorizationExcludedAssetPrecedenceTests(unittest.TestCase):
    def test_excluded_asset_overrides_allowed_asset(self):
        scope = ScopeDefinition(
            assets=("app.example.test", "api.example.test"),
            excluded_assets=("app.example.test",),
            max_risk=RiskLevel.STANDARD,
        )

        self.assertFalse(scope.allows_asset("app.example.test"))
        self.assertTrue(scope.allows_asset("api.example.test"))

    def test_exclusion_matching_uses_same_case_and_whitespace_normalization(self):
        scope = ScopeDefinition(
            assets=("  App.Example.Test  ",),
            excluded_assets=(" app.example.test ",),
            max_risk=RiskLevel.STANDARD,
        )

        self.assertFalse(scope.allows_asset(" APP.EXAMPLE.TEST "))

    def test_unrelated_exclusion_does_not_block_allowed_asset(self):
        scope = ScopeDefinition(
            assets=("app.example.test",),
            excluded_assets=("legacy.example.test",),
            max_risk=RiskLevel.STANDARD,
        )

        self.assertTrue(scope.allows_asset("APP.EXAMPLE.TEST"))

    def test_excluded_entry_never_grants_unlisted_asset(self):
        scope = ScopeDefinition(
            assets=("app.example.test",),
            excluded_assets=("legacy.example.test",),
            max_risk=RiskLevel.STANDARD,
        )

        self.assertFalse(scope.allows_asset("legacy.example.test"))
        self.assertFalse(scope.allows_asset("unknown.example.test"))


if __name__ == "__main__":
    unittest.main()
