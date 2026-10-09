"""Pure offline malformed-authority denial reference; NOT a production gate.

No target requests, DNS, grant persistence, or executor calls are performed.
The reference models parser-exception isolation only. It is intentionally
separate from source-owner integration in src/lightup/scope.py.
"""
import os
import sys
import unittest
from unittest.mock import Mock
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from lightup.models import Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


def reference_preflight(policy, target, handler):
    """Deny parser errors before any downstream policy/handler invocation."""
    if type(target.value) is not str:
        return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
    try:
        parsed = urlparse(target.value if "://" in target.value else "//" + target.value)
        # The authority is netloc, not a raw split which can include query or fragment.
        authority = parsed.netloc
        if authority.count("[") != authority.count("]") or authority.count("[") > 1:
            return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
    except ValueError:
        return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
    # Policy failures are not parser failures: never relabel them as safe denies.
    decision = policy.decide(target)
    if not decision.allowed:
        return decision
    handler(target)
    return decision


class MalformedAuthorityNoHandlerReference(unittest.TestCase):
    def test_malformed_authority_never_calls_policy_or_handler(self):
        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        for raw in ("http://[::1", "https://[2001:db8::1/path",
                    "https://[authorized.example.test/path",
                    "https://2001:db8::1]/path",
                    "https://[[::1]]/",
                    "http://[::1]]/"):
            with self.subTest(raw=raw):
                result = reference_preflight(policy, Target(raw), handler)
                self.assertFalse(result.allowed)
                self.assertIsNone(result.normalized_host)
                self.assertEqual(result.reason, ScopeReason.INVALID_TARGET)
        policy.decide.assert_not_called()
        handler.assert_not_called()

    def test_hostile_nonstring_fails_without_coercion_or_downstream_calls(self):
        class HostileValue:
            def __str__(self):
                raise AssertionError("must not coerce raw input")

            def __bool__(self):
                raise AssertionError("must not truth-test raw input")

        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        decision = reference_preflight(policy, Target(HostileValue()), handler)
        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.normalized_host)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
        policy.decide.assert_not_called()
        handler.assert_not_called()

    def test_policy_valueerror_is_not_disguised_as_invalid_target(self):
        policy = Mock(spec=ScopePolicy)
        policy.decide.side_effect = ValueError("policy infrastructure failed")
        handler = Mock()
        with self.assertRaisesRegex(ValueError, "policy infrastructure failed"):
            reference_preflight(policy, Target("https://authorized.example.test/"), handler)
        policy.decide.assert_called_once()
        handler.assert_not_called()

    def test_path_brackets_do_not_change_authority_identity(self):
        policy = Mock(spec=ScopePolicy)
        policy.decide.return_value = ScopeDecision(
            False, "unlisted.example.test", ScopeReason.OUT_OF_SCOPE
        )
        handler = Mock()
        target = Target("https://unlisted.example.test/path[fragment]")
        decision = reference_preflight(policy, target, handler)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)
        policy.decide.assert_called_once_with(target)
        handler.assert_not_called()

    def test_query_and_fragment_brackets_never_poison_authority(self):
        for raw in (
            "https://unlisted.example.test?lookup=[a",
            "https://unlisted.example.test#fragment=[a",
            "https://unlisted.example.test/path?lookup=]a",
        ):
            with self.subTest(raw=raw):
                policy = Mock(spec=ScopePolicy)
                policy.decide.return_value = ScopeDecision(
                    False, "unlisted.example.test", ScopeReason.OUT_OF_SCOPE
                )
                handler = Mock()
                target = Target(raw)
                result = reference_preflight(policy, target, handler)
                self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)
                policy.decide.assert_called_once_with(target)
                handler.assert_not_called()

    def test_authority_brackets_still_rejected_with_query_and_fragment(self):
        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        for raw in ("https://[::1?x=1", "https://[::1#frag"):
            with self.subTest(raw=raw):
                result = reference_preflight(policy, Target(raw), handler)
                self.assertEqual(result.reason, ScopeReason.INVALID_TARGET)
        policy.decide.assert_not_called()
        handler.assert_not_called()

    def test_normal_denial_preserves_zero_handler_calls(self):
        policy = Mock(spec=ScopePolicy)
        policy.decide.return_value = ScopeDecision(
            False, "unlisted.example.test", ScopeReason.OUT_OF_SCOPE
        )
        handler = Mock()
        result = reference_preflight(
            policy, Target("https://unlisted.example.test/"), handler
        )
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)
        policy.decide.assert_called_once()
        handler.assert_not_called()

    def test_valid_loopback_reference_dispatch_is_not_customer_consent(self):
        policy = Mock(spec=ScopePolicy)
        policy.decide.return_value = ScopeDecision(True, "::1", ScopeReason.LOOPBACK)
        handler = Mock()
        target = Target("http://[::1]/")
        result = reference_preflight(policy, target, handler)
        self.assertEqual(result.reason, ScopeReason.LOOPBACK)
        policy.decide.assert_called_once_with(target)
        handler.assert_called_once_with(target)


if __name__ == "__main__":
    unittest.main()
