"""Offline strict target identity regression suite for #1289.

No DNS calls, real HTTP, external targets, scanners or activation side effects.
Uses the existing ActivationGate only to prove synthetic permit admission.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason
from lightup.strict_target_scope_optin import StrictTargetScopePolicy


class StrictTargetIdentity1289Tests(unittest.TestCase):
    def setUp(self):
        self.base = ScopePolicy()
        self.strict = StrictTargetScopePolicy(self.base)

    def test_original_parser_silently_rewrites_newline_hostname(self):
        # Demonstrates a current regression; it is not a real network exploit.
        legacy = self.base.decide(Target("http://lo\ncalhost"))
        self.assertTrue(legacy.allowed)
        self.assertEqual(legacy.normalized_host, "localhost")
        strict = self.strict.decide(Target("http://lo\ncalhost"))
        self.assertFalse(strict.allowed)
        self.assertEqual(strict.reason, ScopeReason.INVALID_TARGET)

    def test_original_parser_ignores_invalid_port_and_userinfo(self):
        samples = ("http://localhost:notaport", "http://localhost:65536",
                   "http://operator@localhost")
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(self.base.decide(Target(sample)).allowed)
                strict = self.strict.decide(Target(sample))
                self.assertFalse(strict.allowed)
                self.assertEqual(strict.reason, ScopeReason.INVALID_TARGET)

    def test_control_characters_refused_before_urlparse(self):
        for bad in ("http://lo\rcalhost", "http://lo\tcalhost",
                    "http://lo\ncalhost", "http://localhost\x00",
                    "http://localhost\x7f", "127.0.0.1\n",
                    "\tlocalhost", "localhost\r", "localhost\v"):
            with self.subTest(bad=repr(bad)):
                decision = self.strict.decide(Target(bad))
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
                self.assertFalse(decision.allowed)

    def test_parser_and_authority_ambiguities_refused(self):
        for bad in (
            "http://operator@localhost",
            "https://name:password@localhost:443/",
            "http://localhost:abc",
            "http://localhost:0",
            "http://localhost:65536",
            "http://localhost:",
            "http://[::1]junk",
            "http://[::1]:65536",
            "http://[::1]:abc",
            "http://[::1",
            "http://localhost%2e",
            "http://localhost\\@evil.example",
            "http://localhost,evil.test",
            "https://localhost#fragment",
            "//localhost",
            "localhost/accidental-path",
            "localhost?query=value",
            "localhost#fragment",
            "localhost:8080/hidden-path",
            "ftp://localhost",
            "javascript://localhost",
            "http:///localhost",
            "https://",
        ):
            with self.subTest(bad=bad):
                decision = self.strict.decide(Target(bad))
                self.assertFalse(decision.allowed, bad)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET, bad)

    def test_invalid_dns_authorities_refused(self):
        for host in (
            "foo..example.test", "-foo.example.test", "foo-.example.test",
            "bad_name.example.test", "*.example.test", "ü.example.test",
            "a" * 64 + ".example.test", "a" * 254,
        ):
            with self.subTest(host=host):
                result = self.strict.decide(Target(host))
                self.assertEqual(result.reason, ScopeReason.INVALID_TARGET)

    def test_invalid_python_types_fail_closed(self):
        for value in (None, 127, b"localhost", ("localhost",), {}, object()):
            with self.subTest(value=repr(value)):
                result = self.strict.decide(Target(value))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.INVALID_TARGET)
        self.assertEqual(self.strict.decide(None).reason, ScopeReason.INVALID_TARGET)

    def test_valid_loopback_lexical_variants_unchanged(self):
        for good in ("localhost", "LOCALHOST.", "127.0.0.1", "http://localhost",
                     "https://localhost:443/path?q=value",
                     "localhost:8766", "http://127.0.0.1:8080/",
                     "[::1]", "http://[::1]:8766/"):
            with self.subTest(good=good):
                orig = self.base.decide(Target(good))
                actual = self.strict.decide(Target(good))
                self.assertTrue(actual.allowed, good)
                self.assertEqual(actual.reason, ScopeReason.LOOPBACK)
                self.assertEqual(actual.allowed, orig.allowed)
                self.assertEqual(actual.normalized_host, orig.normalized_host)

    def test_bare_ipv6_not_granted_until_explicitly_bracketed(self):
        # Legacy URL authority interpretation does not accept bare ::1.
        original = self.base.decide(Target("::1"))
        self.assertFalse(original.allowed)
        denied = self.strict.decide(Target("::1"))
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, ScopeReason.INVALID_TARGET)
        granted = self.strict.decide(Target("[::1]"))
        self.assertTrue(granted.allowed)
        self.assertEqual(granted.normalized_host, "::1")

    def test_private_lab_and_public_ip_decisions_are_not_widened(self):
        for addr, reason, allowed in (
            ("10.20.30.40", ScopeReason.PRIVATE_LAB, True),
            ("http://192.168.1.33/", ScopeReason.PRIVATE_LAB, True),
            ("172.16.10.3", ScopeReason.PRIVATE_LAB, True),
            ("8.8.8.8", ScopeReason.OUT_OF_SCOPE, False),
            ("https://8.8.4.4:443/", ScopeReason.OUT_OF_SCOPE, False),
        ):
            with self.subTest(addr=addr):
                result = self.strict.decide(Target(addr))
                self.assertEqual(result.allowed, allowed)
                self.assertEqual(result.reason, reason)

    def test_disabling_implicit_private_labs_is_preserved(self):
        strict = StrictTargetScopePolicy(ScopePolicy(allow_private_lab=False))
        self.assertFalse(strict.decide(Target("10.20.30.40")).allowed)

    def test_explicit_public_host_missing_expired_and_current_auth(self):
        now = datetime.now(timezone.utc)
        strict = StrictTargetScopePolicy(
            ScopePolicy(explicit_hosts=frozenset({"app.example.test"})))
        missing = strict.decide(Target("https://APP.EXAMPLE.TEST:443/"))
        self.assertFalse(missing.allowed)
        self.assertEqual(missing.reason, ScopeReason.AUTHORIZATION_MISSING)
        expired = Authorization(
            "owner", "EXPIRED", valid_until=now - timedelta(seconds=20))
        result = strict.decide(Target("app.example.test", authorization=expired))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_EXPIRED)
        current = Authorization(
            "owner", "LAB-ONLY-SYNTHETIC",
            valid_until=now + timedelta(days=1))
        result = strict.decide(
            Target("https://APP.EXAMPLE.TEST:443/path", authorization=current))
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_HOST)

    def test_explicit_public_network_preserves_authorization(self):
        strict = StrictTargetScopePolicy(
            ScopePolicy(explicit_networks=("8.8.8.0/24",)))
        self.assertEqual(strict.decide(Target("8.8.8.8")).reason,
                         ScopeReason.AUTHORIZATION_MISSING)
        authorized = Authorization("synthetic", "LAB-REF")
        result = strict.decide(Target("8.8.8.8", authorization=authorized))
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_NETWORK)

    def test_arbitrary_host_is_never_added_to_allowlist(self):
        authorization = Authorization("synthetic", "LAB-REF")
        bad = self.strict.decide(
            Target("https://example.test/", authorization=authorization))
        self.assertFalse(bad.allowed)
        self.assertEqual(bad.reason, ScopeReason.OUT_OF_SCOPE)

    def test_activation_gate_lab_only_rejects_malformed_before_permit(self):
        gate = ActivationGate(
            self.strict, ActivationPolicy(mode=ActivationMode.LAB_ONLY))
        for invalid in ("http://lo\ncalhost", "http://user@localhost",
                        "http://localhost:65536", "https://[::1]ignored"):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaises(PermissionError):
                    gate.issue(Target(invalid), "synthetic-offline-capability")
        allowed = gate.issue(Target("http://[::1]:8766"), "synthetic-offline-capability")
        self.assertEqual(allowed.target, "::1")
        self.assertEqual(allowed.mode, ActivationMode.LAB_ONLY)

    def test_activation_gate_plan_only_still_denies_valid_localhost(self):
        gate = ActivationGate(
            self.strict, ActivationPolicy(mode=ActivationMode.PLAN_ONLY))
        with self.assertRaises(PermissionError):
            gate.issue(Target("http://localhost:8766"), "synthetic-only")

    def test_exact_legacy_policy_type_required(self):
        with self.assertRaises(TypeError):
            StrictTargetScopePolicy(object())
        class Subclass(ScopePolicy):
            pass
        with self.assertRaises(TypeError):
            StrictTargetScopePolicy(Subclass())

    def test_well_formed_http_url_with_query_remains_eligible(self):
        result = self.strict.decide(Target("https://localhost:443/path?q=foo%20bar"))
        self.assertEqual(result.reason, ScopeReason.LOOPBACK)
        self.assertTrue(result.allowed)

    def test_no_url_encoding_can_smuggle_authority(self):
        for candidate in ("https://lo%63alhost", "localhost%00", "http://%6cocalhost",
                          "http://localhost%0a.evil.example"):
            with self.subTest(candidate=candidate):
                decision = self.strict.decide(Target(candidate))
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)


if __name__ == "__main__":
    unittest.main()
