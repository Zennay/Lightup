from __future__ import annotations

import unittest

from lightup.engagements import RiskLevel, ScopeDefinition


class _IterationSpoofTuple(tuple):
    def __iter__(self):
        return iter(("allowed.example",))


class _ContainmentSpoofTuple(tuple):
    def __contains__(self, item):
        return True


class _StripSpoofStr(str):
    def strip(self, *args, **kwargs):
        return "allowed.example"


class ScopeDefinitionCollectionTypeTest(unittest.TestCase):
    def test_canonical_exact_tuple_and_string_scope_remains_valid(self):
        scope = ScopeDefinition(
            assets=("allowed.example",),
            excluded_assets=("blocked.example",),
            allowed_capabilities=("web-baseline",),
            max_risk=RiskLevel.STANDARD,
        )

        self.assertTrue(scope.allows_asset("allowed.example"))
        self.assertFalse(scope.allows_asset("blocked.example"))
        self.assertTrue(scope.allows_capability("web-baseline"))
        self.assertFalse(scope.allows_capability("other-capability"))

    def test_assets_requires_exact_builtin_tuple(self):
        with self.assertRaises((TypeError, ValueError)):
            ScopeDefinition(
                assets=_IterationSpoofTuple(("foreign.example",)),
                excluded_assets=(),
                allowed_capabilities=("web-baseline",),
                max_risk=RiskLevel.STANDARD,
            )

    def test_excluded_assets_requires_exact_builtin_tuple(self):
        with self.assertRaises((TypeError, ValueError)):
            ScopeDefinition(
                assets=("allowed.example",),
                excluded_assets=_IterationSpoofTuple(("allowed.example",)),
                allowed_capabilities=("web-baseline",),
                max_risk=RiskLevel.STANDARD,
            )

    def test_allowed_capabilities_requires_exact_builtin_tuple(self):
        with self.assertRaises((TypeError, ValueError)):
            ScopeDefinition(
                assets=("allowed.example",),
                excluded_assets=(),
                allowed_capabilities=_ContainmentSpoofTuple(("different-capability",)),
                max_risk=RiskLevel.STANDARD,
            )

    def test_scope_collection_entries_require_exact_builtin_strings(self):
        cases = (
            {
                "assets": (_StripSpoofStr("foreign.example"),),
                "excluded_assets": (),
                "allowed_capabilities": ("web-baseline",),
            },
            {
                "assets": ("allowed.example",),
                "excluded_assets": (_StripSpoofStr("foreign.example"),),
                "allowed_capabilities": ("web-baseline",),
            },
            {
                "assets": ("allowed.example",),
                "excluded_assets": (),
                "allowed_capabilities": (_StripSpoofStr("foreign-capability"),),
            },
        )

        for index, kwargs in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises((TypeError, ValueError)):
                    ScopeDefinition(max_risk=RiskLevel.STANDARD, **kwargs)


if __name__ == "__main__":
    unittest.main()
