"""Offline contract: backslash-bearing URLs are never authorization evidence.

No network, DNS, credentials or trusted grants. Production integration remains
owned by the pre-I/O source owner; this reference cannot authorize execution.
"""
import unittest
from unittest.mock import Mock
from urllib.parse import urlsplit


def raw_url_safe_for_authorization(value):
    """Conservative *raw-input* reference guard, not a URL allowlist/grant."""
    if type(value) is not str:
        return False
    if not value or "\\" in value:
        return False
    if any(ord(character) < 0x20 or ord(character) == 0x7f for character in value):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme.lower() in {"http", "https"} and bool(parts.hostname)


def reference_dispatch(target, downstream_policy):
    """Reject ambiguous syntax before any downstream authorization call."""
    if not raw_url_safe_for_authorization(target):
        return "INVALID_TARGET"
    return downstream_policy(target)


class BackslashNonauthorityTests(unittest.TestCase):
    def test_backslashes_across_url_boundaries_never_reach_policy(self):
        candidates = (
            r"https:\\example.test\admin",
            r"https://example.test\@other.test/admin",
            r"https://other.test@safe.test\bad.test/",
            r"https://example.test/path\..\admin",
            r"https://example.test/?next=\\other.test",
            r"https://example.test/#\\other.test",
            "\\\\example.test\\",
            r"http:\\example.test",
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                policy = Mock(return_value="ALLOW")
                self.assertEqual(reference_dispatch(candidate, policy), "INVALID_TARGET")
                policy.assert_not_called()

    def test_nonstring_input_must_not_invoke_user_string_conversion(self):
        class Hostile:
            def __str__(self):
                raise AssertionError("untrusted conversion was called")

        policy = Mock(return_value="ALLOW")
        self.assertEqual(reference_dispatch(Hostile(), policy), "INVALID_TARGET")
        policy.assert_not_called()

    def test_clean_raw_url_delegates_but_does_not_self_authorize(self):
        url = "https://example.test/safe?next=%5Cexample"
        policy = Mock(return_value="DENY")
        self.assertEqual(reference_dispatch(url, policy), "DENY")
        policy.assert_called_once_with(url)

    def test_policy_not_called_for_backslash_even_if_parser_accepts_it(self):
        raw = r"https://example.test\@other.test/"
        # Parser behavior is explicitly not trusted authorization evidence.
        self.assertTrue(urlsplit(raw).scheme)
        policy = Mock(return_value="ALLOW")
        self.assertEqual(reference_dispatch(raw, policy), "INVALID_TARGET")
        policy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
