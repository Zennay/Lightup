"""Offline fail-closed reference for raw URL input validation.

Pure stdlib reference only: NOT wired to production dispatch, does not
authenticate customer consent, and makes no network calls.
"""
import os
import sys
import unittest
import unicodedata

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


def validate_raw_target(value: object) -> bool:
    """Reject malformed raw input before urllib.parse can remove controls."""
    if type(value) is not str or not value:
        return False
    return not any(
        char.isspace() or unicodedata.category(char) in {"Cc", "Cf", "Cs"}
        for char in value
    )


def reference_decide(policy: ScopePolicy, target: Target):
    if not validate_raw_target(target.value):
        from lightup.scope import ScopeDecision
        return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
    return policy.decide(target)


class RawInputPreparserReferenceTests(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"authorized.example.test"}),
        )
        self.auth = Authorization(owner="synthetic-only", reference="NOT-CONSENT")

    def test_all_ascii_controls_fail_closed_before_parser(self):
        for codepoint in list(range(32)) + [127]:
            for position in ("leading", "authority", "path", "query"):
                with self.subTest(codepoint=codepoint, position=position):
                    char = chr(codepoint)
                    host = "authorized.example.test"
                    values = {
                        "leading": char + "https://" + host,
                        "authority": "https://auth" + char + "orized.example.test/",
                        "path": "https://" + host + "/a" + char + "b",
                        "query": "https://" + host + "/?a=" + char,
                    }
                    decision = reference_decide(
                        self.policy, Target(values[position], authorization=self.auth)
                    )
                    self.assertFalse(decision.allowed)
                    self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_leading_whitespace_fails_closed(self):
        for char in (" ", "\t", "\n", "\r", "\u00a0", "\u2003"):
            with self.subTest(char=repr(char)):
                result = reference_decide(
                    self.policy,
                    Target(char + "https://authorized.example.test", authorization=self.auth),
                )
                self.assertEqual(result.reason, ScopeReason.INVALID_TARGET)

    def test_clean_authorized_fixture_reaches_legacy_policy(self):
        result = reference_decide(
            self.policy,
            Target("https://authorized.example.test/path", authorization=self.auth),
        )
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_HOST)

    def test_missing_grant_still_denied(self):
        result = reference_decide(self.policy, Target("https://authorized.example.test"))
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_unlisted_host_remains_denied(self):
        result = reference_decide(
            self.policy, Target("https://unlisted.example.test", authorization=self.auth)
        )
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_invalid_non_str_input_rejected(self):
        for value in (None, b"https://authorized.example.test", 1, [], {}, ""):
            with self.subTest(value=repr(value)):
                self.assertFalse(validate_raw_target(value))


    def test_invalid_raw_target_never_calls_policy_decide(self):
        from unittest.mock import Mock
        sentinel_policy = Mock(spec=ScopePolicy)
        for raw in ("https://authorized.example.test/a\nb", "\thttps://authorized.example.test", "https://authorized.example.test/\x7f"):
            with self.subTest(raw=repr(raw)):
                decision = reference_decide(
                    sentinel_policy, Target(raw, authorization=self.auth)
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
        sentinel_policy.decide.assert_not_called()

    def test_clean_raw_target_calls_policy_exactly_once(self):
        from unittest.mock import Mock
        sentinel_policy = Mock(spec=ScopePolicy)
        sentinel_policy.decide.return_value = "delegated"
        target = Target("https://authorized.example.test/", authorization=self.auth)
        self.assertEqual(reference_decide(sentinel_policy, target), "delegated")
        sentinel_policy.decide.assert_called_once_with(target)


    def test_input_is_not_mutated_or_rewritten(self):
        from unittest.mock import Mock
        policy = Mock(spec=ScopePolicy)
        policy.decide.return_value = "delegated"
        target = Target("https://authorized.example.test/a%09b", authorization=self.auth, labels=("original",))
        original = (target.value, target.authorization, target.labels)
        self.assertEqual(reference_decide(policy, target), "delegated")
        self.assertEqual((target.value, target.authorization, target.labels), original)
        policy.decide.assert_called_once_with(target)

    def test_percent_encoded_controls_are_not_equivalent_to_raw_controls(self):
        from unittest.mock import Mock
        policy = Mock(spec=ScopePolicy)
        policy.decide.return_value = "delegated"
        for suffix in ("/%0A", "/%0d", "/%09", "/%7F"):
            with self.subTest(suffix=suffix):
                policy.reset_mock()
                target = Target("https://authorized.example.test" + suffix, authorization=self.auth)
                self.assertEqual(reference_decide(policy, target), "delegated")
                policy.decide.assert_called_once_with(target)


    def test_invisible_unicode_format_characters_are_rejected(self):
        for char in ("\u200b", "\u200c", "\u200d", "\u202e", "\u2066", "\ufeff"):
            for position in ("hostname", "path", "query"):
                with self.subTest(char=repr(char), position=position):
                    values = {
                        "hostname": "https://auth" + char + "orized.example.test/",
                        "path": "https://authorized.example.test/a" + char + "b",
                        "query": "https://authorized.example.test/?q=" + char,
                    }
                    result = reference_decide(
                        self.policy, Target(values[position], authorization=self.auth)
                    )
                    self.assertFalse(result.allowed)
                    self.assertEqual(result.reason, ScopeReason.INVALID_TARGET)

    def test_internal_unicode_whitespace_rejected(self):
        for char in (" ", "\u00a0", "\u2003", "\u2028", "\u2029"):
            with self.subTest(char=repr(char)):
                result = reference_decide(
                    self.policy,
                    Target("https://authorized.example.test/p" + char + "ath", authorization=self.auth),
                )
                self.assertEqual(result.reason, ScopeReason.INVALID_TARGET)

    def test_encoded_unicode_remains_uninterpreted_at_preparser(self):
        from unittest.mock import Mock
        policy = Mock(spec=ScopePolicy)
        policy.decide.return_value = "delegated"
        for suffix in ("/%E2%80%8B", "/%E2%80%AE", "/%C2%A0"):
            with self.subTest(suffix=suffix):
                policy.reset_mock()
                target = Target("https://authorized.example.test" + suffix, authorization=self.auth)
                self.assertEqual(reference_decide(policy, target), "delegated")
                policy.decide.assert_called_once_with(target)


    def test_unicode_controls_never_reach_scope_policy(self):
        from unittest.mock import Mock
        policy = Mock(spec=ScopePolicy)
        for character in ("\u200b", "\u202e", "\u2066", "\ufeff", "\ud800"):
            for position in ("authority", "path"):
                with self.subTest(character=ascii(character), position=position):
                    raw = (
                        "https://auth" + character + "orized.example.test/"
                        if position == "authority"
                        else "https://authorized.example.test/p" + character + "ath"
                    )
                    decision = reference_decide(policy, Target(raw, authorization=self.auth))
                    self.assertFalse(decision.allowed)
                    self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
        policy.decide.assert_not_called()

    def test_unicode_normalization_does_not_rewrite_raw_input(self):
        from unittest.mock import Mock
        policy = Mock(spec=ScopePolicy)
        policy.decide.return_value = "delegated"
        for raw in (
            "https://authorized.example.test/caf\u00e9",
            "https://authorized.example.test/cafe\u0301",
        ):
            with self.subTest(raw=ascii(raw)):
                policy.reset_mock()
                target = Target(raw, authorization=self.auth)
                self.assertEqual(reference_decide(policy, target), "delegated")
                policy.decide.assert_called_once_with(target)
                self.assertEqual(target.value, raw)


if __name__ == "__main__":
    unittest.main()
