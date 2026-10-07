from __future__ import annotations

import unittest

from lightup.models import Authorization


class _PermitAllTuple(tuple):
    def __contains__(self, item: object) -> bool:
        return True


class _SpoofCapability(str):
    def __eq__(self, other: object) -> bool:
        return other == "web-baseline"

    def __hash__(self) -> int:
        return hash("web-baseline")


class LegacyAuthorizationCapabilityScopeTypeAcceptanceTest(unittest.TestCase):
    def test_tuple_subclass_cannot_override_capability_membership(self):
        authorization = Authorization(
            owner="client-owner",
            reference="AUTH-728-CONTAINER",
            assets=("security.example.test",),
            capabilities=_PermitAllTuple(("web-baseline",)),  # type: ignore[arg-type]
        )

        try:
            allowed = authorization.allows_capability("api-baseline")
        except (TypeError, ValueError):
            return
        self.assertFalse(allowed)

    def test_polymorphic_scope_entry_cannot_spoof_canonical_capability(self):
        forged = _SpoofCapability("ot-lab")
        authorization = Authorization(
            owner="client-owner",
            reference="AUTH-728-ENTRY",
            assets=("security.example.test",),
            capabilities=(forged,),
        )

        try:
            allowed = authorization.allows_capability("web-baseline")
        except (TypeError, ValueError):
            return
        self.assertFalse(allowed)

    def test_exact_builtin_tuple_and_entries_keep_current_behavior(self):
        authorization = Authorization(
            owner="client-owner",
            reference="AUTH-728-CONTROL",
            assets=("security.example.test",),
            capabilities=("web-baseline",),
        )

        self.assertTrue(authorization.allows_capability("web-baseline"))
        self.assertFalse(authorization.allows_capability("api-baseline"))


if __name__ == "__main__":
    unittest.main()
