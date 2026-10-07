import unittest

from lightup.models import Authorization


class LegacyAuthorizationTerminalDotIdentityTests(unittest.TestCase):
    def test_single_dns_root_dot_remains_equivalent(self):
        canonical = Authorization(
            owner="CISO Acme",
            reference="AUTH-721-CANONICAL",
            assets=(" Example.Test ",),
        )
        rooted = Authorization(
            owner="CISO Acme",
            reference="AUTH-721-ROOTED",
            assets=(" Example.Test. ",),
        )

        self.assertTrue(canonical.allows_asset("example.test."))
        self.assertTrue(rooted.allows_asset("example.test"))
        self.assertTrue(rooted.allows_asset("  EXAMPLE.TEST.  "))

    def test_multiple_terminal_dots_do_not_inherit_canonical_authority(self):
        authorization = Authorization(
            owner="CISO Acme",
            reference="AUTH-721-MALFORMED-TARGET",
            assets=("example.test",),
        )

        self.assertFalse(authorization.allows_asset("example.test.."))
        self.assertFalse(authorization.allows_asset("EXAMPLE.TEST.."))

    def test_malformed_allowlist_entry_does_not_authorize_canonical_host(self):
        authorization = Authorization(
            owner="CISO Acme",
            reference="AUTH-721-MALFORMED-SCOPE",
            assets=("example.test..",),
        )

        self.assertFalse(authorization.allows_asset("example.test"))
        self.assertFalse(authorization.allows_asset("example.test."))


if __name__ == "__main__":
    unittest.main()
