import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel, ScopeDefinition


class DurableAssetSetSemanticsTests(unittest.TestCase):
    def _scope(self, assets, excluded_assets=()):
        return ScopeDefinition(
            assets=tuple(assets),
            excluded_assets=tuple(excluded_assets),
            allowed_capabilities=("web-baseline",),
            max_risk=RiskLevel.LOW_IMPACT,
        )

    def test_allowlist_order_does_not_change_membership(self):
        first = self._scope(("alpha.example.test", "beta.example.test"))
        second = self._scope(("beta.example.test", "alpha.example.test"))
        self.assertEqual(
            first.allows_asset("alpha.example.test"),
            second.allows_asset("alpha.example.test"),
        )
        self.assertTrue(first.allows_asset("alpha.example.test"))

    def test_duplicate_allowed_entries_do_not_authorize_unlisted_asset(self):
        scope = self._scope(
            ("alpha.example.test", "alpha.example.test", "alpha.example.test")
        )
        self.assertTrue(scope.allows_asset("alpha.example.test"))
        self.assertFalse(scope.allows_asset("beta.example.test"))

    def test_exclusion_order_does_not_change_precedence(self):
        first = self._scope(
            ("alpha.example.test", "beta.example.test"),
            ("alpha.example.test", "unrelated.example.test"),
        )
        second = self._scope(
            ("alpha.example.test", "beta.example.test"),
            ("unrelated.example.test", "alpha.example.test"),
        )
        self.assertFalse(first.allows_asset("alpha.example.test"))
        self.assertFalse(second.allows_asset("alpha.example.test"))

    def test_duplicate_exclusions_remain_terminal_for_exact_asset(self):
        scope = self._scope(
            ("alpha.example.test",),
            ("alpha.example.test", "alpha.example.test"),
        )
        self.assertFalse(scope.allows_asset("alpha.example.test"))

    def test_unrelated_duplicates_do_not_change_other_asset_decision(self):
        baseline = self._scope(("alpha.example.test", "beta.example.test"))
        duplicated = self._scope(
            (
                "alpha.example.test",
                "beta.example.test",
                "beta.example.test",
                "beta.example.test",
            )
        )
        self.assertEqual(
            baseline.allows_asset("alpha.example.test"),
            duplicated.allows_asset("alpha.example.test"),
        )
        self.assertTrue(duplicated.allows_asset("alpha.example.test"))

    def test_normalized_duplicates_have_same_set_semantics(self):
        scope = self._scope(
            (" Alpha.Example.Test ", "alpha.example.test"),
            (" Beta.Example.Test ", "beta.example.test"),
        )
        self.assertTrue(scope.allows_asset(" ALPHA.EXAMPLE.TEST "))
        self.assertFalse(scope.allows_asset(" beta.example.test "))


if __name__ == "__main__":
    unittest.main()
