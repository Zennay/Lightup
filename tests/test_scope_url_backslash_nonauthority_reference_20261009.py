"""Offline contract: backslash-bearing URLs are never authorization evidence.

No network, DNS, credentials or trusted grants. Production integration remains
owned by the pre-I/O source owner; this reference cannot authorize execution.
"""
import unittest
from unittest.mock import Mock, patch
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


    def test_backslash_at_every_character_boundary_is_denied_without_policy(self):
        baseline = "https://example.test/path?next=value#fragment"
        # Include insertion before scheme, in authority, and after the fragment.
        for offset in range(len(baseline) + 1):
            candidate = baseline[:offset] + chr(92) + baseline[offset:]
            with self.subTest(offset=offset):
                policy = Mock(return_value="ALLOW")
                self.assertEqual(reference_dispatch(candidate, policy), "INVALID_TARGET")
                policy.assert_not_called()

    def test_string_subclass_cannot_override_authorization_identity(self):
        class MisleadingURL(str):
            def __str__(self):
                raise AssertionError("untrusted __str__ invoked")

            def __contains__(self, item):
                raise AssertionError("untrusted membership invoked")

        policy = Mock(return_value="ALLOW")
        self.assertEqual(
            reference_dispatch(MisleadingURL("https://example.test/"), policy),
            "INVALID_TARGET",
        )
        policy.assert_not_called()


    def test_literal_and_percent_encoded_backslash_have_distinct_boundaries(self):
        examples = (
            ("https://example.test/\\admin", True),
            ("https://example.test/%5Cadmin", False),
            ("https://example.test/%5cadmin", False),
            ("https://example.test/?next=%5Cother.test", False),
        )
        for target, literal_backslash in examples:
            with self.subTest(target=target):
                policy = Mock(return_value="DENY")
                self.assertEqual(
                    reference_dispatch(target, policy),
                    "INVALID_TARGET" if literal_backslash else "DENY",
                )
                if literal_backslash:
                    policy.assert_not_called()
                else:
                    policy.assert_called_once_with(target)

    def test_non_http_schemes_cannot_reach_policy(self):
        for target in (
            "file:///etc/hosts",
            "data:text/plain,hello",
            "javascript:alert(1)",
            "//example.test/path",
            "https:/missing-authority",
        ):
            with self.subTest(target=target):
                policy = Mock(return_value="ALLOW")
                self.assertEqual(reference_dispatch(target, policy), "INVALID_TARGET")
                policy.assert_not_called()


    def test_raw_ascii_controls_deny_before_policy_invocation(self):
        baseline = "https://example.test/path"
        for codepoint in (*range(32), 127):
            for insertion in (0, 8, len(baseline)):
                candidate = baseline[:insertion] + chr(codepoint) + baseline[insertion:]
                with self.subTest(codepoint=codepoint, insertion=insertion):
                    policy = Mock(return_value="ALLOW")
                    self.assertEqual(reference_dispatch(candidate, policy), "INVALID_TARGET")
                    policy.assert_not_called()

    def test_policy_exception_is_not_converted_into_authorization(self):
        policy = Mock(side_effect=RuntimeError("policy unavailable"))
        with self.assertRaisesRegex(RuntimeError, "policy unavailable"):
            reference_dispatch("https://example.test/path", policy)
        policy.assert_called_once_with("https://example.test/path")


    def test_literal_backslash_rejected_before_parser_or_policy(self):
        cases = (
            r"https://example.test\\admin",
            r"https:\\example.test/path",
            "https://example.test/" + chr(92),
        )
        for target in cases:
            with self.subTest(target=target):
                downstream = Mock(return_value="ALLOW")
                with patch(__name__ + ".urlsplit", side_effect=AssertionError("parser called")) as parser:
                    self.assertEqual(reference_dispatch(target, downstream), "INVALID_TARGET")
                parser.assert_not_called()
                downstream.assert_not_called()

    def test_hostile_nonstring_rejected_before_parser_and_policy(self):
        class Trap:
            def __bool__(self):
                raise AssertionError("untrusted truthiness")

            def __str__(self):
                raise AssertionError("untrusted coercion")

        downstream = Mock(return_value="ALLOW")
        with patch(__name__ + ".urlsplit", side_effect=AssertionError("parser called")) as parser:
            self.assertEqual(reference_dispatch(Trap(), downstream), "INVALID_TARGET")
        parser.assert_not_called()
        downstream.assert_not_called()


    def test_parser_value_error_is_a_denial_with_no_policy_call(self):
        policy = Mock(return_value="ALLOW")
        with patch(__name__ + ".urlsplit", side_effect=ValueError("invalid authority")) as parser:
            self.assertEqual(reference_dispatch("https://example.test/", policy), "INVALID_TARGET")
        parser.assert_called_once_with("https://example.test/")
        policy.assert_not_called()

    def test_control_bytes_never_reach_parser_or_policy(self):
        baseline = "https://example.test/path"
        for control in (0, 9, 10, 13, 31, 127):
            candidate = baseline[:8] + chr(control) + baseline[8:]
            with self.subTest(control=control):
                policy = Mock(return_value="ALLOW")
                with patch(__name__ + ".urlsplit", side_effect=AssertionError("parser called")) as parser:
                    self.assertEqual(reference_dispatch(candidate, policy), "INVALID_TARGET")
                parser.assert_not_called()
                policy.assert_not_called()


    def test_parser_generic_error_is_not_silently_authorized(self):
        policy = Mock(return_value="ALLOW")
        with patch(__name__ + ".urlsplit", side_effect=RuntimeError("parser failure")):
            with self.assertRaisesRegex(RuntimeError, "parser failure"):
                reference_dispatch("https://example.test/", policy)
        policy.assert_not_called()

    def test_policy_receives_exact_original_string_once(self):
        target = "HTTPS://Example.TEST/a/%5c?q=%5C#frag"
        policy = Mock(return_value="DENY")
        self.assertEqual(reference_dispatch(target, policy), "DENY")
        policy.assert_called_once_with(target)


    def test_parser_result_with_missing_hostname_must_not_reach_policy(self):
        from types import SimpleNamespace

        for hostname in (None, ""):
            with self.subTest(hostname=hostname):
                policy = Mock(return_value="ALLOW")
                with patch(
                    __name__ + ".urlsplit",
                    return_value=SimpleNamespace(scheme="https", hostname=hostname),
                ):
                    self.assertEqual(reference_dispatch("https://example.test/", policy), "INVALID_TARGET")
                policy.assert_not_called()

    def test_downstream_denial_is_preserved_without_reinterpretation(self):
        for denied in ("DENY", "REVOKED", "OUT_OF_SCOPE"):
            with self.subTest(denied=denied):
                policy = Mock(return_value=denied)
                self.assertEqual(reference_dispatch("https://example.test/", policy), denied)
                policy.assert_called_once_with("https://example.test/")


    def test_malformed_ipv6_authority_denies_without_policy_call(self):
        targets = (
            "https://[::1/path",
            "https://[invalid]/",
            "https://user@[::1/path",
        )
        for target in targets:
            with self.subTest(target=target):
                policy = Mock(return_value="ALLOW")
                self.assertEqual(reference_dispatch(target, policy), "INVALID_TARGET")
                policy.assert_not_called()

    def test_parser_value_error_cannot_trigger_policy_fallback(self):
        target = "https://[::1/path"
        policy = Mock(return_value="ALLOW")
        self.assertEqual(reference_dispatch(target, policy), "INVALID_TARGET")
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
