"""Pure offline malformed-authority denial reference; NOT a production gate.

No target requests, DNS, grant persistence, or executor calls are performed.
The reference models parser-exception isolation only. It is intentionally
separate from source-owner integration in src/lightup/scope.py.
"""
import os
import sys
import unittest
import unicodedata
from unittest.mock import Mock
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from lightup.models import Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


def reference_preflight(policy, target, handler):
    """Deny parser errors before any downstream policy/handler invocation."""
    if type(target.value) is not str or not target.value or any(
        char.isspace() or unicodedata.category(char) in {"Cc", "Cf", "Cs"}
        for char in target.value
    ):
        return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
    try:
        parsed = urlparse(target.value if "://" in target.value else "//" + target.value)
        # The authority is netloc, not a raw split which can include query or fragment.
        authority = parsed.netloc
        # Force authority validation; urlparse alone can defer errors to hostname.
        hostname = parsed.hostname
        # Invalid/out-of-range ports are evaluated lazily by urllib.parse.
        port = parsed.port
        # A trailing colon is not a valid explicit port, even when .port is None.
        if authority.endswith(":"):
            return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
        if not authority or not hostname:
            return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
        if authority.count("[") != authority.count("]") or authority.count("[") > 1:
            return ScopeDecision(False, None, ScopeReason.INVALID_TARGET)
        if authority.startswith("[") and "]" in authority:
            suffix = authority.split("]", 1)[1]
            if suffix and not suffix.startswith(":"):
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

    def test_missing_authority_does_not_reach_policy_or_handler(self):
        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        for raw in ("https:///path", "https://", "", "//"):
            with self.subTest(raw=raw):
                decision = reference_preflight(policy, Target(raw), handler)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
                self.assertFalse(decision.allowed)
        policy.decide.assert_not_called()
        handler.assert_not_called()

    def test_valid_hostname_delegation_does_not_authorize_target(self):
        policy = Mock(spec=ScopePolicy)
        policy.decide.return_value = ScopeDecision(
            False, "unlisted.example.test", ScopeReason.OUT_OF_SCOPE
        )
        handler = Mock()
        target = Target("https://unlisted.example.test/?q=1")
        decision = reference_preflight(policy, target, handler)
        self.assertFalse(decision.allowed)
        policy.decide.assert_called_once_with(target)
        handler.assert_not_called()

    def test_malformed_ports_are_denied_before_policy_or_handler(self):
        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        for raw in (
            "https://unlisted.example.test:abc/",
            "https://unlisted.example.test:65536/",
            "https://[::1]:-1/",
            "https://[::1]:99999/",
        ):
            with self.subTest(raw=raw):
                result = reference_preflight(policy, Target(raw), handler)
                self.assertFalse(result.allowed)
                self.assertIsNone(result.normalized_host)
                self.assertEqual(result.reason, ScopeReason.INVALID_TARGET)
        policy.decide.assert_not_called()
        handler.assert_not_called()

    def test_empty_explicit_port_denied_without_policy_or_handler(self):
        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        for raw in (
            "https://unlisted.example.test:/",
            "https://[::1]:/",
            "https://unlisted.example.test:",
        ):
            with self.subTest(raw=raw):
                decision = reference_preflight(policy, Target(raw), handler)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
                self.assertFalse(decision.allowed)
        policy.decide.assert_not_called()
        handler.assert_not_called()

    def test_bracketed_non_ip_authority_denied_without_policy_or_handler(self):
        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        for raw in (
            "https://[authorized.example.test]/",
            "https://[not-an-ip]/",
            "https://[127.0.0.1]/",
        ):
            with self.subTest(raw=raw):
                decision = reference_preflight(policy, Target(raw), handler)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
                self.assertIsNone(decision.normalized_host)
        policy.decide.assert_not_called()
        handler.assert_not_called()

    def test_malformed_authority_rejected_across_schemes(self):
        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        for scheme in ("http", "https", "ftp"):
            for authority in ("[::1", "[[::1]]", "2001:db8::1]"):
                raw = scheme + "://" + authority + "/"
                with self.subTest(raw=raw):
                    decision = reference_preflight(policy, Target(raw), handler)
                    self.assertFalse(decision.allowed)
                    self.assertIsNone(decision.normalized_host)
                    self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
        policy.decide.assert_not_called()
        handler.assert_not_called()

    def test_parser_failure_does_not_mask_policy_no_call_contract(self):
        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        cases = (
            "https://[::1",
            "https://unlisted.example.test:65536/",
            "https://unlisted.example.test:",
            "https://[not-an-ip]/",
        )
        for raw in cases:
            with self.subTest(raw=raw):
                policy.reset_mock()
                handler.reset_mock()
                decision = reference_preflight(policy, Target(raw), handler)
                self.assertEqual(
                    (decision.allowed, decision.normalized_host, decision.reason),
                    (False, None, ScopeReason.INVALID_TARGET),
                )
                policy.decide.assert_not_called()
                handler.assert_not_called()

    def test_trailing_text_after_bracketed_ipv6_is_never_delegated(self):
        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        for raw in ("https://[::1]evil/", "https://[::1]@host/", "https://[::1]suffix:443/"):
            with self.subTest(raw=raw):
                decision = reference_preflight(policy, Target(raw), handler)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
                self.assertIsNone(decision.normalized_host)
        policy.decide.assert_not_called()
        handler.assert_not_called()

    def test_userinfo_before_bracketed_ipv6_does_not_bypass_validation(self):
        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        for raw in (
            "https://user@[::1]evil/",
            "https://user:pass@[::1]suffix/",
        ):
            with self.subTest(raw=raw):
                decision = reference_preflight(policy, Target(raw), handler)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
                self.assertIsNone(decision.normalized_host)
        policy.decide.assert_not_called()
        handler.assert_not_called()

    def test_valid_explicit_port_preserves_denial(self):
        policy = Mock(spec=ScopePolicy)
        policy.decide.return_value = ScopeDecision(
            False, "unlisted.example.test", ScopeReason.OUT_OF_SCOPE
        )
        handler = Mock()
        target = Target("https://unlisted.example.test:8443/path")
        decision = reference_preflight(policy, target, handler)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)
        policy.decide.assert_called_once_with(target)
        handler.assert_not_called()

    def test_raw_control_and_unicode_format_characters_never_reach_policy(self):
        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        for character in tuple(map(chr, (10, 9, 13, 0x200B, 0x202E, 0xD800))):
            self.assertEqual(len(character), 1, "fixture must be a real Unicode codepoint")
            for placement in ("prefix", "authority", "path"):
                raw = {
                    "prefix": character + "https://unlisted.example.test/",
                    "authority": "https://unlisted" + character + ".example.test/",
                    "path": "https://unlisted.example.test/a" + character,
                }[placement]
                with self.subTest(character=ascii(character), placement=placement):
                    decision = reference_preflight(policy, Target(raw), handler)
                    self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
                    self.assertFalse(decision.allowed)
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

    def test_handler_failure_is_not_disguised_as_parser_denial(self):
        policy = Mock(spec=ScopePolicy)
        policy.decide.return_value = ScopeDecision(True, "::1", ScopeReason.LOOPBACK)
        handler = Mock(side_effect=ValueError("handler failed"))
        target = Target("http://[::1]/")
        with self.assertRaisesRegex(ValueError, "handler failed"):
            reference_preflight(policy, target, handler)
        policy.decide.assert_called_once_with(target)
        handler.assert_called_once_with(target)

    def test_malformed_authority_leaves_untrusted_metadata_untouched(self):
        class PoisonMetadata:
            def __getattribute__(self, name):
                raise AssertionError("metadata must never be read")

            def __bool__(self):
                raise AssertionError("metadata must never be coerced")

        policy = Mock(spec=ScopePolicy)
        handler = Mock()
        target = Target(
            "https://[::1/path",
            authorization=PoisonMetadata(),
            labels=PoisonMetadata(),
        )
        decision = reference_preflight(policy, target, handler)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
        policy.decide.assert_not_called()
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
