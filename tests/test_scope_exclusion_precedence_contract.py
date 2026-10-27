"""Offline scope allowlist/exclusion precedence contract.

No network or target interaction; tests only the pure ScopeDefinition predicate.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel, ScopeDefinition


class ScopeExclusionPrecedenceTests(unittest.TestCase):
    def scope(self, assets, exclusions):
        return ScopeDefinition(
            assets=tuple(assets),
            excluded_assets=tuple(exclusions),
            max_risk=RiskLevel.ANALYSIS_ONLY,
        )

    def test_exact_allowlisted_asset_is_allowed(self):
        self.assertTrue(self.scope(("app.example.test",), ()).allows_asset("app.example.test"))

    def test_exclusion_overrides_explicit_allowlist(self):
        scope = self.scope(("app.example.test",), ("app.example.test",))
        self.assertFalse(scope.allows_asset("app.example.test"))

    def test_exclusion_precedence_survives_whitespace_and_case(self):
        scope = self.scope((" APP.EXAMPLE.TEST ",), (" app.example.test ",))
        for candidate in ("app.example.test", " APP.EXAMPLE.TEST ", "App.Example.Test"):
            with self.subTest(candidate=candidate):
                self.assertFalse(scope.allows_asset(candidate))

    def test_unlisted_asset_is_denied_even_without_exclusion(self):
        self.assertFalse(self.scope(("app.example.test",), ()).allows_asset("other.example.test"))

    def test_parent_or_subdomain_is_not_implicitly_authorized(self):
        scope = self.scope(("app.example.test",), ())
        for candidate in ("example.test", "deep.app.example.test", "notapp.example.test"):
            with self.subTest(candidate=candidate):
                self.assertFalse(scope.allows_asset(candidate))

    def test_sibling_exclusion_does_not_remove_allowed_asset(self):
        scope = self.scope(("a.example.test", "b.example.test"), ("b.example.test",))
        self.assertTrue(scope.allows_asset("a.example.test"))
        self.assertFalse(scope.allows_asset("b.example.test"))

    def test_empty_allowlist_never_authorizes_excluded_or_unlisted_assets(self):
        scope = self.scope((), ("app.example.test",))
        for candidate in ("app.example.test", "other.example.test", ""):
            with self.subTest(candidate=candidate):
                self.assertFalse(scope.allows_asset(candidate))

    def test_duplicate_allow_entries_cannot_override_an_exclusion(self):
        scope = self.scope(
            ("app.example.test", "APP.EXAMPLE.TEST", "app.example.test"),
            (" app.example.test ",),
        )
        self.assertFalse(scope.allows_asset("app.example.test"))

    def test_lookalike_prefix_suffix_and_trailing_dot_are_not_granted(self):
        scope = self.scope(("app.example.test",), ())
        for candidate in (
            "app.example.test.evil.test",
            "not-app.example.test",
            "app.example.test.",
        ):
            with self.subTest(candidate=candidate):
                self.assertFalse(scope.allows_asset(candidate))

    def test_repeated_evaluation_does_not_mutate_scope(self):
        assets = (" APP.EXAMPLE.TEST ", "other.example.test")
        exclusions = (" app.example.test ",)
        scope = self.scope(assets, exclusions)
        before = (scope.assets, scope.excluded_assets, scope.max_risk)
        for _ in range(3):
            self.assertFalse(scope.allows_asset("app.example.test"))
            self.assertTrue(scope.allows_asset("other.example.test"))
        self.assertEqual((scope.assets, scope.excluded_assets, scope.max_risk), before)


if __name__ == "__main__":
    unittest.main()
