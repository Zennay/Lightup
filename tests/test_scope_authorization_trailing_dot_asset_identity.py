from __future__ import annotations

import unittest

from lightup.engagements import RiskLevel, ScopeDefinition


class DurableTrailingDotAssetIdentityTest(unittest.TestCase):
    def test_allowed_fqdn_with_terminal_dot_matches_bare_hostname(self) -> None:
        scope = ScopeDefinition(
            assets=("example.test.",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        self.assertTrue(scope.allows_asset("example.test"))

    def test_bare_allowed_hostname_matches_terminal_dot_request(self) -> None:
        scope = ScopeDefinition(
            assets=("example.test",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        self.assertTrue(scope.allows_asset("example.test."))

    def test_exclusion_without_dot_blocks_dotted_allowed_identity(self) -> None:
        scope = ScopeDefinition(
            assets=("example.test.",),
            excluded_assets=("example.test",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        self.assertFalse(scope.allows_asset("example.test."))
        self.assertFalse(scope.allows_asset("example.test"))

    def test_dotted_exclusion_blocks_bare_allowed_identity(self) -> None:
        scope = ScopeDefinition(
            assets=("example.test",),
            excluded_assets=("example.test.",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        self.assertFalse(scope.allows_asset("example.test"))
        self.assertFalse(scope.allows_asset("example.test."))

    def test_existing_case_and_whitespace_normalization_remains(self) -> None:
        scope = ScopeDefinition(
            assets=("  Example.Test  ",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        self.assertTrue(scope.allows_asset(" example.test "))

    def test_multiple_terminal_dots_do_not_collapse_into_authority(self) -> None:
        scope = ScopeDefinition(
            assets=("example.test.",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        self.assertFalse(scope.allows_asset("example.test.."))

    def test_unrelated_host_remains_denied(self) -> None:
        scope = ScopeDefinition(
            assets=("example.test.",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        )
        self.assertFalse(scope.allows_asset("api.example.test"))


if __name__ == "__main__":
    unittest.main()
