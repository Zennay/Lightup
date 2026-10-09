"""Offline fail-closed reference for raw URL input validation.

Pure stdlib reference only: NOT wired to production dispatch, does not
authenticate customer consent, and makes no network calls.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


def validate_raw_target(value: object) -> bool:
    """Reject malformed raw input before urllib.parse can remove controls."""
    if type(value) is not str or not value:
        return False
    if value[0].isspace():
        return False
    return not any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)


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


if __name__ == "__main__":
    unittest.main()
