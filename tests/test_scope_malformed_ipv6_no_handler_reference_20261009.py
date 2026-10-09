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
        urlparse(target.value if "://" in target.value else "//" + target.value)
        # Enforce authority bracket balance BEFORE delegating the real policy.
        authority = target.value.split("://", 1)[-1].split("/", 1)[0]
        if authority.count("[") != authority.count("]") or authority.count("[") > 1:
            return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
        decision = policy.decide(target)
    except ValueError:
        return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
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
