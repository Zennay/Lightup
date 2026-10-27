"""Offline reference: DNS aliases and redirects never expand authorization.

This intentionally does not import production adapters or make network calls.
"""
import unittest


def within_literal_authorized_hosts(approved_hosts, requested_host, aliases=(), redirects=()):
    """Fail closed: each identity seen must be literally approved, without inference."""
    if type(approved_hosts) not in (tuple, list) or not approved_hosts:
        return False
    if type(aliases) not in (tuple, list) or type(redirects) not in (tuple, list):
        return False

    def canonical_literal(value):
        if type(value) is not str or not value or len(value) > 253:
            return None
        if value != value.lower() or value.endswith(".") or "://" in value:
            return None
        labels = value.split(".")
        if any(not (0 < len(label) <= 63) or label[0] == "-" or label[-1] == "-"
               or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label)
               for label in labels):
            return None
        return value

    approved = [canonical_literal(host) for host in approved_hosts]
    if None in approved or len(set(approved)) != len(approved):
        return False
    observed = (requested_host, *aliases, *redirects)
    return all(canonical_literal(host) in approved for host in observed)


class DNSRedirectAuthorityReference(unittest.TestCase):
    def test_literal_host_is_allowed(self):
        self.assertTrue(within_literal_authorized_hosts(("app.example.test",), "app.example.test"))

    def test_redirect_to_unapproved_sibling_denied(self):
        self.assertFalse(within_literal_authorized_hosts(
            ("app.example.test",), "app.example.test", redirects=("login.example.test",)))

    def test_cname_to_unapproved_host_denied(self):
        self.assertFalse(within_literal_authorized_hosts(
            ("app.example.test",), "app.example.test", aliases=("vendor.example.test",)))

    def test_explicitly_approved_hop_allowed(self):
        self.assertTrue(within_literal_authorized_hosts(
            ("app.example.test", "login.example.test"),
            "app.example.test", redirects=("login.example.test",)))

    def test_unapproved_intermediate_hop_denied(self):
        self.assertFalse(within_literal_authorized_hosts(
            ("app.example.test", "login.example.test"), "app.example.test",
            redirects=("external.example.test", "login.example.test")))

    def test_suffix_is_not_permission(self):
        self.assertFalse(within_literal_authorized_hosts(
            ("example.test",), "api.example.test"))

    def test_malformed_alias_and_redirect_rejected(self):
        for hop in ("https://app.example.test", "APP.EXAMPLE.TEST", "app.example.test.",
                    "app.example.test:443", "*.example.test", "", None, 1, True):
            with self.subTest(hop=hop):
                self.assertFalse(within_literal_authorized_hosts(
                    ("app.example.test",), "app.example.test", aliases=(hop,)))
                self.assertFalse(within_literal_authorized_hosts(
                    ("app.example.test",), "app.example.test", redirects=(hop,)))

    def test_malformed_grant_set_rejected(self):
        for hosts in ((), ("app.example.test", "app.example.test"), ("*.example.test",),
                      ("APP.EXAMPLE.TEST",), ("app.example.test", None), "app.example.test"):
            with self.subTest(hosts=hosts):
                self.assertFalse(within_literal_authorized_hosts(hosts, "app.example.test"))

    def test_wrong_container_types_denied(self):
        self.assertFalse(within_literal_authorized_hosts(
            ("app.example.test",), "app.example.test", aliases="app.example.test"))
        self.assertFalse(within_literal_authorized_hosts(
            ("app.example.test",), "app.example.test", redirects="app.example.test"))


if __name__ == "__main__":
    unittest.main()
