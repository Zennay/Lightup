"""Current-main terminal-dot authority contract for LightUp issue #723.

Deliberate source RED tests use expectedFailure while src/lightup/scope.py is
owned by another worker. A passing test run is NOT evidence of safe policy.
No target I/O, grants, or production state are modified.
"""
from __future__ import annotations

import os
import socket
import subprocess
import urllib.request
from urllib.parse import urlparse
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


_HOST = "terminal-dot.example.test"
_SYNTHETIC_ONLY = Authorization(owner="synthetic-unit-test", reference="FAKE-NOT-CONSENT")


def _decision(value: str, declared_host: str = _HOST):
    return ScopePolicy(
        allow_private_lab=False,
        explicit_hosts=frozenset((declared_host,)),
    ).decide(Target(value, authorization=_SYNTHETIC_ONLY))


def _reference_terminal_root_identity(host: str | None) -> str | None:
    """Pure review oracle: zero/one root dot only; NEVER issues scope rights."""
    if not host or host.endswith(".."):
        return None
    normalized = host[:-1] if host.endswith(".") else host
    return normalized.lower() or None


def _reference_target_host(value: str) -> str | None:
    """Mirror only installed URL host extraction, then apply strict root-dot rule."""
    raw = value.strip()
    if not raw:
        return None
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
    return _reference_terminal_root_identity(parsed.hostname)


def _reference_bad_root_cases() -> tuple[str, ...]:
    """240 differently spelled hosts plus four dot-only host identities."""
    hosts = (_HOST, "localhost", "127.0.0.1", "10.42.43.44", "198.51.100.23")
    cases = tuple(
        variant
        for host in hosts
        for dots in range(2, 18)
        for variant in (
            host + "." * dots,
            "http://" + host + "." * dots + "/synthetic-only",
            "https://" + host + "." * dots + ":8443/synthetic-only",
        )
    )
    return cases + ("..", "...", "http://../synthetic-only", "https://.../synthetic-only")


class TerminalDotCurrentMainSourceRed(unittest.TestCase):
    """Installed-source deny expectations; every XFAIL is an UNFIXED defect."""

    @unittest.expectedFailure
    def test_double_terminal_dot_target_must_not_inherit_explicit_host(self):
        decision = _decision(_HOST + "..")
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    @unittest.expectedFailure
    def test_triple_terminal_dot_target_must_not_inherit_explicit_host(self):
        decision = _decision(_HOST + "...")
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    @unittest.expectedFailure
    def test_double_terminal_dot_policy_must_not_authorize_plain_target(self):
        decision = _decision(_HOST, _HOST + "..")
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    @unittest.expectedFailure
    def test_triple_terminal_dot_policy_must_not_authorize_rooted_target(self):
        decision = _decision(_HOST + ".", _HOST + "...")
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    @unittest.expectedFailure
    def test_double_terminal_dot_localhost_must_not_inherit_loopback(self):
        decision = ScopePolicy().decide(Target("localhost.."))
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.LOOPBACK)

    @unittest.expectedFailure
    def test_triple_terminal_dot_localhost_must_not_inherit_loopback(self):
        decision = ScopePolicy().decide(Target("LOCALHOST..."))
        self.assertFalse(decision.allowed)
        self.assertNotEqual(decision.reason, ScopeReason.LOOPBACK)

    @unittest.expectedFailure
    def test_malformed_target_without_auth_and_explicit_policy_optout_must_deny(self):
        # Synthetic opt-out demonstrates the parser bug independently of
        # fake Authorization fixtures; never a real consent configuration.
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset((_HOST,)),
            require_authorization_for_public=False,
        )
        values = tuple(
            value
            for dots in range(2, 18)
            for value in (_HOST + "." * dots, "https://" + _HOST + "." * dots + "/lab-only")
        )
        decisions = tuple(policy.decide(Target(value)) for value in values)
        self.assertEqual(len(decisions), 32)
        self.assertFalse(any(decision.allowed for decision in decisions))

    @unittest.expectedFailure
    def test_malformed_config_without_auth_and_policy_optout_must_deny(self):
        pairs = tuple(
            (value, _HOST + "." * dots)
            for dots in range(2, 18)
            for value in (_HOST, _HOST + ".")
        )
        decisions = tuple(
            ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset((entry,)),
                require_authorization_for_public=False,
            ).decide(Target(target))
            for target, entry in pairs
        )
        self.assertEqual(len(decisions), 32)
        self.assertFalse(any(decision.allowed for decision in decisions))

    @unittest.expectedFailure
    def test_only_dots_and_empty_config_without_auth_optout_must_deny(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(("",)),
            require_authorization_for_public=False,
        )
        values = ("..", "...", "http://../lab-only", "https://.../lab-only")
        decisions = tuple(policy.decide(Target(value)) for value in values)
        self.assertEqual(len(decisions), 4)
        self.assertFalse(any(decision.allowed for decision in decisions))

    @unittest.expectedFailure
    def test_all_dots_target_must_not_match_empty_declared_hostname(self):
        # Additional #723/#297 interaction: rstrip('.') turns only-dots
        # target text into the empty string and silently matches an invalid
        # empty explicit_hosts declaration when synthetic auth is present.
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(("",)),
        )
        targets = ("..", "...", "https://../synthetic-only", "http://.../synthetic-only")
        decisions = tuple(
            policy.decide(Target(value, authorization=_SYNTHETIC_ONLY))
            for value in targets
        )
        self.assertEqual(len(decisions), 4)
        self.assertFalse(any(decision.allowed for decision in decisions))

    @unittest.expectedFailure
    def test_installed_normalizer_must_match_pure_fail_closed_root_dot_oracle(self):
        # This compares all 244 actual source parser outputs, not just an
        # aggregate ScopeDecision. It is intentionally RED until source owner
        # changes normalization; no URL is opened or DNS resolved.
        cases = _reference_bad_root_cases()
        actual = tuple(ScopePolicy.normalize_host(value) for value in cases)
        expected = tuple(_reference_target_host(value) for value in cases)
        self.assertEqual(len(cases), 244)
        self.assertFalse(any(left != right for left, right in zip(actual, expected)))

    @unittest.expectedFailure
    def test_port_qualified_multi_root_dot_authorities_must_deny_every_path(self):
        # Explicit ports are entirely lexical here. No TCP/IP connection is
        # made; the trailing dots are inside the host, before ':port'.
        identities = (
            (_HOST, ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset((_HOST,)),
            ), _SYNTHETIC_ONLY),
            ("localhost", ScopePolicy(allow_private_lab=False), None),
            ("127.0.0.1", ScopePolicy(allow_private_lab=False), None),
            ("10.42.43.44", ScopePolicy(allow_private_lab=True), None),
            ("198.51.100.23", ScopePolicy(
                allow_private_lab=False,
                explicit_networks=("198.51.100.0/24",),
            ), _SYNTHETIC_ONLY),
        )
        cases = tuple(
            (f"https://{host}{'.' * dots}:{port}/synthetic-only", policy, auth)
            for host, policy, auth in identities
            for dots in (2, 3, 7, 17)
            for port in (80, 8443)
        )
        decisions = tuple(
            policy.decide(Target(value, authorization=auth))
            for value, policy, auth in cases
        )
        self.assertEqual(len(decisions), 40)
        self.assertFalse(any(decision.allowed for decision in decisions))

    @unittest.expectedFailure
    def test_parser_itself_must_reject_multi_root_dot_identities(self):
        # Failing safely at the *normalizer* is stronger than relying on a
        # later caller to remember an independent deny condition.
        spellings = tuple(
            value
            for dots in range(2, 18)
            for host in (
                _HOST,
                "localhost",
                "127.0.0.1",
                "10.42.43.44",
                "198.51.100.23",
            )
            for value in (
                host + "." * dots,
                "http://" + host + "." * dots + "/synthetic-only",
            )
        )
        normalized = tuple(ScopePolicy.normalize_host(value) for value in spellings)
        self.assertEqual(len(normalized), 160)
        self.assertFalse(any(value is not None for value in normalized))

    @unittest.expectedFailure
    def test_parser_itself_must_reject_dot_only_and_empty_normalized_host(self):
        values = ("..", "...", "http://../synthetic-only", "https://.../synthetic-only")
        normalized = tuple(ScopePolicy.normalize_host(value) for value in values)
        self.assertEqual(len(normalized), 4)
        self.assertFalse(any(value is not None for value in normalized))

    @unittest.expectedFailure
    def test_ipv4_loopback_multi_root_dots_must_not_gain_loopback_trust(self):
        # IP-looking text is parsed through the same rstrip('.') path:
        # the invalid address must never become 127.0.0.1 loopback.
        values = tuple(
            value for dots in range(2, 18)
            for value in (
                "127.0.0.1" + "." * dots,
                "http://127.0.0.1" + "." * dots + "/synthetic-only",
            )
        )
        policy = ScopePolicy(allow_private_lab=False)
        decisions = tuple(policy.decide(Target(value)) for value in values)
        self.assertEqual(len(decisions), 32)
        self.assertFalse(any(decision.allowed for decision in decisions))

    @unittest.expectedFailure
    def test_ipv4_private_lab_multi_root_dots_must_not_gain_private_scope(self):
        # Opt-in synthetic lab flag must not broaden malformed *text*.
        values = tuple(
            value for dots in range(2, 18)
            for value in (
                "10.42.43.44" + "." * dots,
                "http://10.42.43.44" + "." * dots + "/synthetic-only",
            )
        )
        policy = ScopePolicy(allow_private_lab=True)
        decisions = tuple(policy.decide(Target(value)) for value in values)
        self.assertEqual(len(decisions), 32)
        self.assertFalse(any(decision.allowed for decision in decisions))

    @unittest.expectedFailure
    def test_ipv4_declared_cidr_multi_root_dots_must_not_gain_network_scope(self):
        # RFC 5737 TEST-NET-2 only, with fake Authorization never accepted
        # as real permission: the error happens before network membership.
        values = tuple(
            value for dots in range(2, 18)
            for value in (
                "198.51.100.23" + "." * dots,
                "http://198.51.100.23" + "." * dots + "/synthetic-only",
            )
        )
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("198.51.100.0/24",),
        )
        decisions = tuple(
            policy.decide(Target(value, authorization=_SYNTHETIC_ONLY))
            for value in values
        )
        self.assertEqual(len(decisions), 32)
        self.assertFalse(any(decision.allowed for decision in decisions))

    @unittest.expectedFailure
    def test_matrix_32_malformed_target_dot_counts_and_url_forms_must_deny(self):
        # Materialize *all* decisions before the assertion: no early exit
        # silently truncates the 64-case input matrix.
        targets = tuple(
            target
            for count in range(2, 34)
            for target in (
                _HOST + "." * count,
                "https://" + _HOST + "." * count + "/synthetic-only",
            )
        )
        decisions = tuple(_decision(target) for target in targets)
        self.assertEqual(len(decisions), 64)
        self.assertFalse(any(decision.allowed for decision in decisions))

    @unittest.expectedFailure
    def test_matrix_32_malformed_config_dot_counts_and_targets_must_deny(self):
        # The bad *configured* hostname must not gain authority from a
        # plain or singly rooted input target (distinct from target parser).
        pairs = tuple(
            (target, _HOST + "." * count)
            for count in range(2, 34)
            for target in (_HOST, _HOST + ".")
        )
        decisions = tuple(_decision(target, declaration) for target, declaration in pairs)
        self.assertEqual(len(decisions), 64)
        self.assertFalse(any(decision.allowed for decision in decisions))

    @unittest.expectedFailure
    def test_matrix_32_malformed_localhost_dot_counts_and_url_forms_must_deny(self):
        # No synthetic Authorization is supplied: loopback trust alone is
        # enough to reproduce the installed source bypass.
        targets = tuple(
            target
            for count in range(2, 34)
            for target in (
                "LOCALHOST" + "." * count,
                "http://localhost" + "." * count + "/synthetic-only",
            )
        )
        decisions = tuple(ScopePolicy(allow_private_lab=False).decide(Target(target))
                          for target in targets)
        self.assertEqual(len(decisions), 64)
        self.assertFalse(any(decision.allowed for decision in decisions))


_RED_NAMES = (
    "test_double_terminal_dot_target_must_not_inherit_explicit_host",
    "test_triple_terminal_dot_target_must_not_inherit_explicit_host",
    "test_double_terminal_dot_policy_must_not_authorize_plain_target",
    "test_triple_terminal_dot_policy_must_not_authorize_rooted_target",
    "test_double_terminal_dot_localhost_must_not_inherit_loopback",
    "test_triple_terminal_dot_localhost_must_not_inherit_loopback",
    "test_malformed_target_without_auth_and_explicit_policy_optout_must_deny",
    "test_malformed_config_without_auth_and_policy_optout_must_deny",
    "test_only_dots_and_empty_config_without_auth_optout_must_deny",
    "test_all_dots_target_must_not_match_empty_declared_hostname",
    "test_installed_normalizer_must_match_pure_fail_closed_root_dot_oracle",
    "test_port_qualified_multi_root_dot_authorities_must_deny_every_path",
    "test_parser_itself_must_reject_multi_root_dot_identities",
    "test_parser_itself_must_reject_dot_only_and_empty_normalized_host",
    "test_ipv4_loopback_multi_root_dots_must_not_gain_loopback_trust",
    "test_ipv4_private_lab_multi_root_dots_must_not_gain_private_scope",
    "test_ipv4_declared_cidr_multi_root_dots_must_not_gain_network_scope",
    "test_matrix_32_malformed_target_dot_counts_and_url_forms_must_deny",
    "test_matrix_32_malformed_config_dot_counts_and_targets_must_deny",
    "test_matrix_32_malformed_localhost_dot_counts_and_url_forms_must_deny",
)


class _AssertionWitnessResult(unittest.TestResult):
    """Record actual exception types, not TestResult's formatted tracebacks."""

    def __init__(self):
        super().__init__()
        self.real_expected_types = []

    def addExpectedFailure(self, test, err):
        self.real_expected_types.append((err[0], str(err[1])))
        super().addExpectedFailure(test, err)


class TerminalDotCurrentMainControls(unittest.TestCase):
    """Independent green controls + witness integrity (no false RED masking)."""

    def test_canonical_explicit_host_remains_exact(self):
        self.assertEqual(_decision(_HOST).reason, ScopeReason.EXPLICIT_HOST)
        self.assertTrue(_decision(_HOST).allowed)
        self.assertEqual(_decision(_HOST + ".").reason, ScopeReason.EXPLICIT_HOST)
        self.assertTrue(_decision(_HOST + ".").allowed)

    def test_case_fold_with_single_root_dot_stays_equivalent(self):
        decision = _decision(_HOST.upper() + ".")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, _HOST)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_plain_localhost_and_single_root_dot_only(self):
        for name in ("localhost", "localhost.", "LOCALHOST."):
            with self.subTest(host=name):
                decision = ScopePolicy().decide(Target(name))
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.LOOPBACK)

    def test_unlisted_public_host_denied(self):
        for name in ("other.example.test", "other.example.test."):
            with self.subTest(host=name):
                decision = _decision(name)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_original_source_witnesses_are_real_assertions_not_errors(self):
        # @expectedFailure also catches accidental TypeError and ValueError.
        # An independent TestResult must observe exactly twenty AssertionError
        # failures, not silently accept an unrelated crash or unexpected green.
        for name in _RED_NAMES:
            with self.subTest(case=name):
                result = _AssertionWitnessResult()
                TerminalDotCurrentMainSourceRed(name).run(result)
                self.assertEqual(result.testsRun, 1)
                self.assertFalse(result.errors)
                self.assertFalse(result.failures)
                self.assertFalse(result.unexpectedSuccesses)
                self.assertEqual(len(result.expectedFailures), 1)
                self.assertEqual(
                    result.real_expected_types,
                    [(AssertionError, "True is not false")],
                )

    def test_entire_source_contract_avoids_network_and_dns(self):
        with (
            patch.object(socket, "socket", side_effect=AssertionError("network attempted")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS attempted")),
            patch.object(socket, "create_connection", side_effect=AssertionError("connect attempted")),
        ):
            for name in _RED_NAMES:
                result = _AssertionWitnessResult()
                TerminalDotCurrentMainSourceRed(name).run(result)
                self.assertEqual(len(result.expectedFailures), 1, name)
                self.assertEqual(
                    result.real_expected_types,
                    [(AssertionError, "True is not false")],
                )
            self.assertTrue(_decision(_HOST).allowed)
            self.assertFalse(_decision("unlisted.example.test").allowed)

    def test_canonical_port_qualified_urls_preserve_expected_membership(self):
        # URL ports do not create authority, but valid hosts keep their
        # already-established offline membership/authorization semantics.
        for host in (_HOST, _HOST + "."):
            with self.subTest(host=host):
                decision = _decision(f"https://{host}:8443/synthetic-only")
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)
        for host in ("localhost", "127.0.0.1", "localhost.", "127.0.0.1."):
            with self.subTest(host=host):
                decision = ScopePolicy(allow_private_lab=False).decide(
                    Target(f"http://{host}:8080/synthetic-only")
                )
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.LOOPBACK)
        network = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("198.51.100.0/24",),
        )
        decision = network.decide(Target("https://198.51.100.23:443/synthetic-only"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_all_40_malformed_port_qualified_decisions_remain_offline(self):
        # A second sweep covers the same actual installed source with
        # network and process tripwires, without asserting unsafe outcomes.
        cases = (
            (_HOST, frozenset((_HOST,)), (), False, _SYNTHETIC_ONLY),
            ("localhost", frozenset(), (), False, None),
            ("127.0.0.1", frozenset(), (), False, None),
            ("10.42.43.44", frozenset(), (), True, None),
            ("198.51.100.23", frozenset(), ("198.51.100.0/24",), False, _SYNTHETIC_ONLY),
        )
        with (
            patch.object(socket, "socket", side_effect=AssertionError("network attempted")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS attempted")),
            patch.object(socket, "create_connection", side_effect=AssertionError("connect attempted")),
            patch.object(urllib.request, "urlopen", side_effect=AssertionError("HTTP attempted")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process attempted")),
            patch.object(os, "system", side_effect=AssertionError("shell attempted")),
        ):
            count = 0
            for host, hosts, networks, lab, auth in cases:
                policy = ScopePolicy(
                    allow_private_lab=lab,
                    explicit_hosts=hosts,
                    explicit_networks=networks,
                )
                for dots in (2, 3, 7, 17):
                    for port in (80, 8443):
                        value = f"https://{host}{'.' * dots}:{port}/synthetic-only"
                        result = policy.decide(Target(value, authorization=auth))
                        self.assertIs(type(result), ScopeDecision)
                        self.assertIs(type(result.allowed), bool)
                        count += 1
            self.assertEqual(count, 40)

    def test_legacy_strip_mutation_proves_all_244_malformed_alias_groups(self):
        # Model only the known unsafe text operation independently of
        # installed source. This green mutation-sensitivity control survives
        # a future fix of the production normalizer.
        groups = {}
        for value in _reference_bad_root_cases():
            raw = value.strip()
            parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
            self.assertIsNotNone(parsed.hostname)
            unsafe_alias = parsed.hostname.rstrip(".").lower()
            self.assertIsNone(_reference_target_host(value))
            groups[unsafe_alias] = groups.get(unsafe_alias, 0) + 1
        self.assertEqual(
            groups,
            {
                _HOST: 48,
                "localhost": 48,
                "127.0.0.1": 48,
                "10.42.43.44": 48,
                "198.51.100.23": 48,
                "": 4,
            },
        )
        self.assertEqual(sum(groups.values()), 244)

    def test_pure_fail_closed_reference_covers_244_bad_and_30_good_hosts(self):
        # A narrowly scoped REVIEW-ONLY reference for the source owner.
        # It returns a lexical identity or None, never an authorization.
        invalid = _reference_bad_root_cases()
        self.assertEqual(len(invalid), 244)
        self.assertEqual(len(set(invalid)), 244)
        self.assertTrue(all(_reference_target_host(value) is None for value in invalid))

        hosts = (_HOST, "localhost", "127.0.0.1", "10.42.43.44", "198.51.100.23")
        legitimate = tuple(
            (variant, host)
            for host in hosts
            for variant in (
                host,
                host + ".",
                host.upper() + ".",
                "http://" + host + "/synthetic-only",
                "http://" + host + "./synthetic-only",
                "https://" + host + ".:8443/synthetic-only",
            )
        )
        self.assertEqual(len(legitimate), 30)
        for value, canonical in legitimate:
            with self.subTest(value=value):
                self.assertEqual(_reference_target_host(value), canonical)
        # Configuration-side lexical review uses only already isolated
        # hostname text, never target-URL syntax or mutable authorization.
        for dots in range(2, 18):
            self.assertIsNone(_reference_terminal_root_identity(_HOST + "." * dots))
        self.assertEqual(_reference_terminal_root_identity(_HOST + "."), _HOST)
        self.assertIsNone(_reference_terminal_root_identity(""))
        self.assertIsNone(_reference_terminal_root_identity("."))
        self.assertIsNone(_reference_terminal_root_identity(None))

    def test_parser_positive_control_normalizes_exact_and_single_root_dot(self):
        identities = (_HOST, "localhost", "127.0.0.1", "10.42.43.44", "198.51.100.23")
        for expected in identities:
            for value in (expected, expected + ".", "http://" + expected + "./synthetic-only"):
                with self.subTest(value=value):
                    self.assertEqual(ScopePolicy.normalize_host(value), expected)
        self.assertIsNone(ScopePolicy.normalize_host(""))
        self.assertIsNone(ScopePolicy.normalize_host("   "))

    def test_canonical_ipv4_categories_remain_separate_and_auth_gate_stays_required(self):
        self.assertEqual(
            ScopePolicy(allow_private_lab=False).decide(Target("127.0.0.1")).reason,
            ScopeReason.LOOPBACK,
        )
        self.assertEqual(
            ScopePolicy(allow_private_lab=True).decide(Target("10.42.43.44")).reason,
            ScopeReason.PRIVATE_LAB,
        )
        network = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("198.51.100.0/24",),
        )
        self.assertEqual(
            network.decide(Target("198.51.100.23")).reason,
            ScopeReason.AUTHORIZATION_MISSING,
        )
        decision = network.decide(Target("198.51.100.23", authorization=_SYNTHETIC_ONLY))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_NETWORK)
        self.assertEqual(
            ScopePolicy(allow_private_lab=False).decide(Target("10.42.43.44")).reason,
            ScopeReason.OUT_OF_SCOPE,
        )

    def test_all_96_malformed_ipv4_decisions_have_no_external_io(self):
        # All real installed-source scope decisions, zero actual I/O.
        cases = []
        for dots in range(2, 18):
            for ip in ("127.0.0.1", "10.42.43.44", "198.51.100.23"):
                cases.extend(
                    (ip + "." * dots, "http://" + ip + "." * dots + "/synthetic-only")
                )
        self.assertEqual(len(cases), 96)
        with (
            patch.object(socket, "socket", side_effect=AssertionError("network attempted")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS attempted")),
            patch.object(socket, "gethostbyname", side_effect=AssertionError("DNS attempted")),
            patch.object(socket, "create_connection", side_effect=AssertionError("network attempted")),
            patch.object(urllib.request, "urlopen", side_effect=AssertionError("HTTP attempted")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process attempted")),
            patch.object(subprocess, "run", side_effect=AssertionError("process attempted")),
            patch.object(os, "system", side_effect=AssertionError("shell attempted")),
        ):
            results = []
            for value in cases:
                if "127.0.0.1" in value:
                    policy, auth = ScopePolicy(allow_private_lab=False), None
                elif "10.42.43.44" in value:
                    policy, auth = ScopePolicy(allow_private_lab=True), None
                else:
                    policy = ScopePolicy(
                        allow_private_lab=False,
                        explicit_networks=("198.51.100.0/24",),
                    )
                    auth = _SYNTHETIC_ONLY
                result = policy.decide(Target(value, authorization=auth))
                self.assertIs(type(result), ScopeDecision)
                self.assertIs(type(result.allowed), bool)
                results.append(result)
            self.assertEqual(len(results), 96)

    def test_entire_264_case_malformed_matrix_is_process_and_network_free(self):
        # Every W2, W4 and W5 syntactic variant is evaluated as a genuine
        # installed ScopePolicy decision, not a mock source and not a scan.
        # Results may currently be unsafe (tracked as separate REDs), but
        # this green invariant requires that none touches target I/O.
        tests = []
        for dots in range(2, 34):
            suffix = "." * dots
            for value in (_HOST + suffix, "https://" + _HOST + suffix + "/synthetic-only"):
                tests.append((value, _HOST, True))
            for value in (_HOST, _HOST + "."):
                tests.append((value, _HOST + suffix, True))
            for value in ("LOCALHOST" + suffix, "http://localhost" + suffix + "/synthetic-only"):
                tests.append((value, None, False))
        for value in ("..", "...", "https://../synthetic-only", "http://.../synthetic-only"):
            tests.append((value, "", True))
        for dots in range(2, 18):
            suffix = "." * dots
            for value in (_HOST + suffix, "https://" + _HOST + suffix + "/lab-only"):
                tests.append((value, _HOST, False))
            for value in (_HOST, _HOST + "."):
                tests.append((value, _HOST + suffix, False))
        for value in ("..", "...", "http://../lab-only", "https://.../lab-only"):
            tests.append((value, "", False))
        self.assertEqual(len(tests), 264)

        with (
            patch.object(socket, "socket", side_effect=AssertionError("socket prohibited")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS prohibited")),
            patch.object(socket, "gethostbyname", side_effect=AssertionError("DNS prohibited")),
            patch.object(socket, "create_connection", side_effect=AssertionError("connect prohibited")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process prohibited")),
            patch.object(subprocess, "run", side_effect=AssertionError("process prohibited")),
            patch.object(os, "system", side_effect=AssertionError("shell prohibited")),
            patch.object(urllib.request, "urlopen", side_effect=AssertionError("HTTP prohibited")),
        ):
            observed = []
            for value, declared, requires_auth in tests:
                policy = ScopePolicy(
                    allow_private_lab=False,
                    explicit_hosts=frozenset((declared,)) if declared is not None else frozenset(),
                    require_authorization_for_public=requires_auth,
                )
                # No trusted operator data or real targets are supplied.
                marker = _SYNTHETIC_ONLY if requires_auth else None
                decision = policy.decide(Target(value, authorization=marker))
                self.assertIs(type(decision), ScopeDecision)
                self.assertIs(type(decision.allowed), bool)
                observed.append(decision)
            self.assertEqual(len(observed), 264)

    def test_policy_side_url_decorations_cannot_grant_embedded_hostname(self):
        policy_entries = (
            "https://" + _HOST,
            "http://operator@" + _HOST,
            _HOST + ":443",
            _HOST + "/synthetic-path",
            _HOST + "?synthetic-query=1",
            _HOST + "#synthetic-fragment",
            "//" + _HOST,
        )
        for entry in policy_entries:
            with self.subTest(policy_entry=entry):
                decision = _decision(_HOST, entry)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_policy_side_whitespace_decorations_cannot_grant_host(self):
        policy_entries = (
            " " + _HOST,
            _HOST + " ",
            "\t" + _HOST,
            _HOST + "\n",
            "\r" + _HOST,
            _HOST + "\u00a0",
        )
        for entry in policy_entries:
            with self.subTest(repr_entry=repr(entry)):
                decision = _decision(_HOST, entry)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_policy_side_wildcard_leading_dot_and_suffix_never_expand_scope(self):
        entries = (
            "*.example.test",
            ".example.test",
            "example.test",
            _HOST + ".attacker.test",
            "terminal-dot.example",
        )
        for entry in entries:
            with self.subTest(policy_entry=entry):
                decision = _decision(_HOST, entry)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_canonical_target_url_and_whitespace_still_match_exact_policy(self):
        targets = (
            "https://" + _HOST + "/synthetic-only",
            "https://" + _HOST.upper() + ":443/synthetic-only?q=1",
            "\t" + _HOST + " ",
            _HOST + ".",
        )
        for target in targets:
            with self.subTest(target=target):
                decision = _decision(target)
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)
                self.assertEqual(decision.normalized_host, _HOST)

    def test_single_root_dot_policy_entry_remains_canonical(self):
        for policy_entry in (_HOST + ".", _HOST.upper() + "."):
            for target in (_HOST, _HOST.upper() + "."):
                with self.subTest(config=policy_entry, target=target):
                    decision = _decision(target, policy_entry)
                    self.assertTrue(decision.allowed)
                    self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_masked_runtime_error_cannot_masquerade_as_source_red(self):
        # A plain @expectedFailure would swallow this unrelated exception.
        # Our independent witness must *recognize* and reject this outcome.
        with patch(f"{__name__}._decision", side_effect=TypeError("synthetic masking")):
            result = _AssertionWitnessResult()
            TerminalDotCurrentMainSourceRed(
                "test_double_terminal_dot_target_must_not_inherit_explicit_host"
            ).run(result)
        self.assertEqual(len(result.expectedFailures), 1)
        self.assertEqual(result.real_expected_types, [(TypeError, "synthetic masking")])
        self.assertNotEqual(result.real_expected_types, [(AssertionError, "True is not false")])

    def test_untrusted_fixture_is_not_authenticated_customer_approval(self):
        # Genuine customer/operator provenance is intentionally unavailable.
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset((_HOST,)),
        )
        for value in (_HOST, _HOST + ".", _HOST + ".."):
            with self.subTest(value=value):
                decision = policy.decide(Target(value))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_exact_positive_controls_stay_disjoint(self):
        # A malformed other hostname must not gain membership just because
        # the test fixture's own canonical host was explicitly configured.
        for value in ("not-" + _HOST, "x." + _HOST, _HOST + ".evil.test"):
            decision = _decision(value)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_bad_policy_with_default_public_consent_required_does_not_grant_without_auth(self):
        for target, entry in (
            (_HOST + "..", _HOST),
            (_HOST, _HOST + ".."),
            ("...", ""),
        ):
            with self.subTest(value=target, config=entry):
                decision = ScopePolicy(
                    allow_private_lab=False,
                    explicit_hosts=frozenset((entry,)),
                    require_authorization_for_public=True,
                ).decide(Target(target))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_dot_only_targets_cannot_gain_authority_without_empty_policy_entry(self):
        # The original defect requires a corrupt policy declaration too.
        # Unlisted empty host must not be a grant even with fake fixtures.
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset((_HOST,)),
        )
        for value in ("..", "...", "https://../synthetic-only"):
            with self.subTest(value=value):
                decision = policy.decide(Target(value, authorization=_SYNTHETIC_ONLY))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_policy_collections_and_synthetic_authorization_unchanged(self):
        policy = ScopePolicy(explicit_hosts=frozenset((_HOST,)))
        original = policy.explicit_hosts
        auth = _SYNTHETIC_ONLY
        decision = policy.decide(Target(_HOST + ".", authorization=auth))
        self.assertTrue(decision.allowed)
        self.assertEqual(original, policy.explicit_hosts)
        self.assertEqual(auth.reference, "FAKE-NOT-CONSENT")


if __name__ == "__main__":
    unittest.main()
