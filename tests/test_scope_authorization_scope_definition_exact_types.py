import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import RiskLevel, ScopeDefinition


class _IterSpoofTuple(tuple):
    def __iter__(self):
        return iter(("app.example",))


class _EmptyIterTuple(tuple):
    def __iter__(self):
        return iter(())


class _ContainsAllTuple(tuple):
    def __contains__(self, item):
        return True


class _SpoofAsset(str):
    def strip(self, *args, **kwargs):
        return "app.example"


class _SpoofCapability(str):
    def __eq__(self, other):
        return True

    def __hash__(self):
        return hash("web-baseline")


class ScopeDefinitionExactTypeAcceptanceTests(unittest.TestCase):
    def test_exact_tuple_and_string_scope_control_remains_canonical(self):
        scope = ScopeDefinition(
            assets=("app.example",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
            excluded_assets=("blocked.example",),
        )

        self.assertTrue(scope.allows_asset("app.example"))
        self.assertFalse(scope.allows_asset("blocked.example"))
        self.assertTrue(scope.allows_capability("web-baseline"))
        self.assertFalse(scope.allows_capability("other-capability"))

    def test_assets_tuple_subclass_is_rejected_at_construction(self):
        with self.assertRaisesRegex(ValueError, "assets must be an exact tuple"):
            ScopeDefinition(
                assets=_IterSpoofTuple(("foreign.example",)),  # type: ignore[arg-type]
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            )

    def test_excluded_assets_tuple_subclass_is_rejected_at_construction(self):
        with self.assertRaisesRegex(ValueError, "excluded_assets must be an exact tuple"):
            ScopeDefinition(
                assets=("app.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
                excluded_assets=_EmptyIterTuple(("app.example",)),  # type: ignore[arg-type]
            )

    def test_allowed_capabilities_tuple_subclass_is_rejected_at_construction(self):
        with self.assertRaisesRegex(ValueError, "allowed_capabilities must be an exact tuple"):
            ScopeDefinition(
                assets=("app.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=_ContainsAllTuple(("safe-capability",)),  # type: ignore[arg-type]
            )

    def test_asset_string_subclass_is_rejected_at_construction(self):
        with self.assertRaisesRegex(ValueError, "asset entries must be exact strings"):
            ScopeDefinition(
                assets=(_SpoofAsset("foreign.example"),),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            )

    def test_excluded_asset_string_subclass_is_rejected_at_construction(self):
        with self.assertRaisesRegex(ValueError, "excluded asset entries must be exact strings"):
            ScopeDefinition(
                assets=("app.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
                excluded_assets=(_SpoofAsset("app.example"),),
            )

    def test_capability_string_subclass_is_rejected_at_construction(self):
        with self.assertRaisesRegex(ValueError, "capability entries must be exact strings"):
            ScopeDefinition(
                assets=("app.example",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=(_SpoofCapability("foreign-capability"),),
            )


if __name__ == "__main__":
    unittest.main()
