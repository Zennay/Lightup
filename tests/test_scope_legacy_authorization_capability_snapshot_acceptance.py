from __future__ import annotations

import unittest

from lightup.models import Authorization


class LegacyAuthorizationCapabilitySnapshotAcceptanceTest(unittest.TestCase):
    def test_caller_owned_capability_list_cannot_widen_authority_after_creation(self):
        caller_capabilities = ["web-baseline"]
        authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=("security.example.test",),
            capabilities=caller_capabilities,  # type: ignore[arg-type]
        )

        self.assertTrue(authorization.allows_capability("web-baseline"))
        self.assertFalse(authorization.allows_capability("api-baseline"))

        caller_capabilities.append("api-baseline")

        self.assertTrue(authorization.allows_capability("web-baseline"))
        self.assertFalse(authorization.allows_capability("api-baseline"))

    def test_caller_owned_capability_list_cannot_narrow_authority_after_creation(self):
        caller_capabilities = ["web-baseline"]
        authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=("security.example.test",),
            capabilities=caller_capabilities,  # type: ignore[arg-type]
        )

        caller_capabilities.clear()

        self.assertTrue(authorization.allows_capability("web-baseline"))

    def test_exact_tuple_scope_remains_stable(self):
        authorization = Authorization(
            owner="client-owner",
            reference="client-auth-ref",
            assets=("security.example.test",),
            capabilities=("web-baseline",),
        )

        self.assertTrue(authorization.allows_capability("web-baseline"))
        self.assertFalse(authorization.allows_capability("api-baseline"))


if __name__ == "__main__":
    unittest.main()
