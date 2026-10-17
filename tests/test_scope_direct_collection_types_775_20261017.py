"""#775: exact ScopeDefinition collection containers and identity text.

Non-authorizing direct in-memory source acceptance, pinned to original #554.
No grant issuance, database, network, assets, scanners, handlers or disk writes.
"""
from __future__ import annotations

import os
import unittest

from lightup.engagements import RiskLevel, ScopeDefinition


_SOURCE_CONTRACT = (
    (lambda method: method)
    if os.environ.get("LIGHTUP_SCOPE775_REQUIRE_SOURCE_FIX") == "1"
    else unittest.expectedFailure
)


class SpoofedAssetTuple(tuple):
    def __iter__(self):
        # Underlying tuple stores another asset; public iteration lies.
        return iter(("allowed.invalid",))


class HiddenExclusionTuple(tuple):
    def __iter__(self):
        return iter(())


class ForgedCapabilityTuple(tuple):
    def __contains__(self, candidate):
        return True


class ForgedAssetText(str):
    def strip(self, *args, **kwargs):
        return "allowed.invalid"


class ForgedExclusionText(str):
    def strip(self, *args, **kwargs):
        return "other.invalid"


class ForgedCapabilityText(str):
    def __eq__(self, other):
        return other == "ot-lab"

    def __hash__(self):
        return hash("ot-lab")


class HostileTuple(tuple):
    reads = 0

    def __iter__(self):
        type(self).reads += 1
        raise RuntimeError("hostile iterator executed")


class DirectScopeCollectionIdentityAcceptance(unittest.TestCase):
    @staticmethod
    def scope(*, assets=("allowed.invalid",), excluded_assets=(),
              allowed_capabilities=("web-baseline",)):
        return ScopeDefinition(
            assets=assets,
            excluded_assets=excluded_assets,
            allowed_capabilities=allowed_capabilities,
            max_risk=RiskLevel.STANDARD,
        )

    def test_canonical_exact_tuple_string_baseline_remains_supported(self):
        scope = self.scope(
            assets=("allowed.invalid", "blocked.invalid"),
            excluded_assets=("blocked.invalid",),
            allowed_capabilities=("web-baseline", "api-baseline"),
        )
        for value in (scope.assets, scope.excluded_assets,
                      scope.allowed_capabilities):
            self.assertIs(type(value), tuple)
            for entry in value:
                self.assertIs(type(entry), str)
        self.assertTrue(scope.allows_asset("allowed.invalid"))
        self.assertFalse(scope.allows_asset("blocked.invalid"))
        self.assertFalse(scope.allows_asset("outside.invalid"))
        self.assertTrue(scope.allows_capability("web-baseline"))
        self.assertFalse(scope.allows_capability("ot-lab"))

    def test_empty_canonical_exclusion_and_capability_semantics_unchanged(self):
        scope = self.scope(excluded_assets=(), allowed_capabilities=())
        self.assertTrue(scope.allows_asset("allowed.invalid"))
        self.assertFalse(scope.allows_asset("outside.invalid"))
        # Historical ScopeDefinition deliberately interprets empty caps as
        # all capabilities; this test only preserves API behavior, not consent.
        self.assertTrue(scope.allows_capability("web-baseline"))

    @_SOURCE_CONTRACT
    def test_source_red_asset_tuple_subclass_rejected_before_iteration(self):
        fake = SpoofedAssetTuple(("outside.invalid",))
        with self.assertRaises((ValueError, TypeError)):
            self.scope(assets=fake)

    @_SOURCE_CONTRACT
    def test_source_red_exclusion_tuple_subclass_rejected_before_iteration(self):
        fake = HiddenExclusionTuple(("blocked.invalid",))
        with self.assertRaises((ValueError, TypeError)):
            self.scope(assets=("blocked.invalid",), excluded_assets=fake)

    @_SOURCE_CONTRACT
    def test_source_red_capability_tuple_subclass_rejected_before_membership(self):
        fake = ForgedCapabilityTuple(("web-baseline",))
        with self.assertRaises((ValueError, TypeError)):
            self.scope(allowed_capabilities=fake)

    @_SOURCE_CONTRACT
    def test_source_red_asset_str_subclass_cannot_spoof_strip(self):
        with self.assertRaises((ValueError, TypeError)):
            self.scope(assets=(ForgedAssetText("outside.invalid"),))

    @_SOURCE_CONTRACT
    def test_source_red_exclusion_str_subclass_cannot_hide_denial(self):
        with self.assertRaises((ValueError, TypeError)):
            self.scope(
                assets=("blocked.invalid",),
                excluded_assets=(ForgedExclusionText("blocked.invalid"),),
            )

    @_SOURCE_CONTRACT
    def test_source_red_capability_str_subclass_cannot_spoof_comparison(self):
        with self.assertRaises((ValueError, TypeError)):
            self.scope(allowed_capabilities=(ForgedCapabilityText("web-baseline"),))

    @_SOURCE_CONTRACT
    def test_source_red_hostile_container_rejected_without_callback(self):
        HostileTuple.reads = 0
        fake = HostileTuple(("outside.invalid",))
        with self.assertRaises((ValueError, TypeError)):
            self.scope(assets=fake)
        self.assertEqual(HostileTuple.reads, 0)


if __name__ == "__main__":
    unittest.main()
