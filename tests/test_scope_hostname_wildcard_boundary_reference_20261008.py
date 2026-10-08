"""Offline authorization hostname selector reference: no network or target I/O.

This is a conservative *reference* validator, not executable authorization.
The production scope owner must decide whether and how to integrate it.
"""
import re
import ipaddress
import unittest

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\Z", re.ASCII)


def exact_dns_selector(value: object) -> bool:
    """Accept only lower-case ASCII DNS names with no wildcard or URL syntax.

    No suffix matching, URL parsing, DNS resolution, or implicit canonicalization.
    """
    if type(value) is not str or not 1 <= len(value) <= 253:
        return False
    labels = value.split(".")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return False
    return len(labels) >= 2 and all(_LABEL.fullmatch(label) for label in labels)


def authorized_exact_dns(requested: object, allowed: object) -> bool:
    return exact_dns_selector(requested) and exact_dns_selector(allowed) and requested == allowed


class ExactHostnameReferenceTests(unittest.TestCase):
    def test_exact_bound_match(self):
        self.assertTrue(authorized_exact_dns("api.example.test", "api.example.test"))

    def test_subdomain_not_implicitly_included(self):
        self.assertFalse(authorized_exact_dns("child.api.example.test", "api.example.test"))

    def test_suffix_confusion_not_included(self):
        self.assertFalse(authorized_exact_dns("api.example.test.evil.test", "api.example.test"))

    def test_wildcard_not_authorized(self):
        for selector in ("*.example.test", "api.*.test", "*", ".example.test"):
            with self.subTest(selector=selector):
                self.assertFalse(authorized_exact_dns("api.example.test", selector))

    def test_ambiguous_or_noncanonical_forms_denied(self):
        bad = ("API.example.test", "api.example.test.", "api..example.test",
               "-api.example.test", "api-.example.test", "api_example.test",
               "https://api.example.test", "api.example.test:443",
               "user@api.example.test", "api.example.test/path",
               "api.example.test\\n", "äpi.example.test", "127.0.0.1",
               "localhost", "")
        for value in bad:
            with self.subTest(value=value):
                self.assertFalse(authorized_exact_dns(value))

    def test_exact_types_only(self):
        for value in (None, True, 5, b"api.example.test", ["api.example.test"]):
            with self.subTest(value=value):
                self.assertFalse(authorized_exact_dns(value))

    def test_label_and_total_length_bounds(self):
        self.assertTrue(exact_dns_selector("a" * 63 + ".example.test"))
        self.assertFalse(exact_dns_selector("a" * 64 + ".example.test"))
        self.assertFalse(exact_dns_selector(("a" * 60 + ".") * 5 + "test"))

    def test_valid_name_does_not_grant_cross_identity(self):
        self.assertFalse(authorized_exact_dns("api.example.test", "other.example.test"))


if __name__ == "__main__":
    unittest.main()
