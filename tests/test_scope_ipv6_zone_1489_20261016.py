"""Actual installed ScopePolicy source REDs and offline #1489 helper controls."""
import builtins
import os
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason
from lightup.ipv6_zone_review_1489 import (
    ZoneReviewStatus,
    review_ipv6_authority_zone,
)


class InstalledScopeZoneAcceptance(unittest.TestCase):
    """These four contracts remain RED until the ORIGINAL scope owner fixes them."""

    @unittest.expectedFailure
    def test_current_source_must_deny_linklocal_percent25_zone(self):
        self.assertFalse(ScopePolicy().decide(Target("http://[fe80::1%25eth0]/")).allowed)

    @unittest.expectedFailure
    def test_current_source_must_deny_linklocal_literal_zone(self):
        self.assertFalse(ScopePolicy().decide(Target("[fe80::1%eth0]")).allowed)

    @unittest.expectedFailure
    def test_current_source_must_deny_ula_zone(self):
        self.assertFalse(ScopePolicy().decide(Target("[fd00::1%eth0]")).allowed)

    @unittest.expectedFailure
    def test_current_source_must_deny_loopback_zone(self):
        self.assertFalse(ScopePolicy().decide(Target("[::1%lo0]")).allowed)

    def test_actual_source_is_exercised_by_red_contracts(self):
        """Evidence that these source contracts touch the real installed policy."""
        for value, reason in (
            ("http://[fe80::1%25eth0]/", ScopeReason.PRIVATE_LAB),
            ("[fd00::1%eth0]", ScopeReason.PRIVATE_LAB),
            ("[::1%lo0]", ScopeReason.LOOPBACK),
        ):
            with self.subTest(value=value):
                decision = ScopePolicy().decide(Target(value))
                self.assertTrue(decision.allowed)  # source gap witness, NOT safe behavior
                self.assertEqual(decision.reason, reason)

    def test_normal_unscoped_loopback_and_ula_still_resolve(self):
        for value, reason in (
            ("[::1]", ScopeReason.LOOPBACK),
            ("[fd00::1]", ScopeReason.PRIVATE_LAB),
        ):
            with self.subTest(value=value):
                decision = ScopePolicy().decide(Target(value))
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.reason, reason)


class OfflineZoneReviewTests(unittest.TestCase):
    def check_hold(self, value):
        result = review_ipv6_authority_zone(value)
        self.assertEqual(result.status, ZoneReviewStatus.HOLD)
        self.assertIs(result.execution_allowed, False)
        self.assertIs(result.permit_allowed, False)
        self.assertIs(result.dispatch_allowed, False)
        self.assertIs(result.release_allowed, False)

    def check_review(self, value):
        result = review_ipv6_authority_zone(value)
        self.assertEqual(result.status, ZoneReviewStatus.REVIEW_ONLY)
        self.assertIs(result.execution_allowed, False)
        self.assertIs(result.permit_allowed, False)
        self.assertIs(result.dispatch_allowed, False)
        self.assertIs(result.release_allowed, False)

    def test_canonical_unscoped_literals_are_review_only_not_authority(self):
        for value in ("[::1]", "[fd00::1]", "[fe80::1]", "[2001:db8::1]"):
            with self.subTest(value=value):
                self.check_review(value)

    def test_canonical_http_https_ipv6_urls_are_review_only(self):
        for value in ("http://[::1]", "https://[fd00::1]/", "http://[fe80::1]/"):
            with self.subTest(value=value):
                self.check_review(value)

    def test_literal_percent_zone_is_hold_for_all_lab_classes(self):
        for value in ("[::1%lo]", "[fd00::1%eth0]", "[fe80::1%eth0]"):
            with self.subTest(value=value):
                self.check_hold(value)

    def test_percent25_escaped_zone_is_hold(self):
        for value in ("https://[fe80::1%25eth0]/", "http://[::1%25lo]/"):
            with self.subTest(value=value):
                self.check_hold(value)

    def test_multiple_percent_and_empty_zone_is_hold(self):
        for value in ("[fe80::1%]", "[fe80::1%eth0%other]", "[::1%%25lo]"):
            with self.subTest(value=value):
                self.check_hold(value)

    def test_zone_contaminated_otherwise_valid_url_is_hold(self):
        self.check_hold("http://[fd00::1%25en0]/")

    def test_malformed_and_non_ipv6_authority_is_hold(self):
        for value in ("::1", "127.0.0.1", "localhost", "[broken]", "", "[]", "[::1", "::1]"):
            with self.subTest(value=value):
                self.check_hold(value)

    def test_ambiguous_ip_versions_and_canonicality_are_hold(self):
        for value in ("[FD00::1]", "[fd00:0:0:0:0:0:0:1]", "[::ffff:192.0.2.1]"):
            with self.subTest(value=value):
                self.check_hold(value)

    def test_userinfo_port_query_fragment_and_path_are_hold(self):
        for value in (
            "http://user@[::1]/",
            "http://[::1]:443/",
            "https://[::1]/search",
            "http://[::1]/?debug=1",
            "http://[::1]/#frag",
            "ftp://[::1]/",
        ):
            with self.subTest(value=value):
                self.check_hold(value)

    def test_reject_subclass_and_nonstring_even_if_stringlike(self):
        class Trick(str):
            pass
        for value in (Trick("[::1]"), b"[::1]", None, True, 1, ["[::1]"]):
            with self.subTest(type=type(value).__name__):
                self.check_hold(value)

    def test_unicode_controls_and_overlarge_authority_hold(self):
        for value in ("[::1]\n", "[::1]\u200b", "[::1]\t", "[::1]" * 80, " [::1]"):
            with self.subTest(length=len(value)):
                self.check_hold(value)

    def test_frozen_result_and_static_false_authority_flags(self):
        from dataclasses import FrozenInstanceError
        out = review_ipv6_authority_zone("[::1]")
        with self.assertRaises(FrozenInstanceError):
            out.release_allowed = True
        self.check_review("[::1]")

    def test_256_input_ceiling_does_not_normalize_untrusted_values(self):
        self.check_hold("[" + "a" * 254 + "]")
        self.check_hold("[" + "a" * 255 + "]")

    def test_no_file_socket_sqlite_or_process_io_in_preview(self):
        with (
            patch.object(builtins, "open", side_effect=AssertionError("file")),
            patch.object(os, "open", side_effect=AssertionError("os.open")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")),
            patch.object(sqlite3, "connect", side_effect=AssertionError("db")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
        ):
            self.check_hold("http://[fe80::1%25eth0]/")
            self.check_review("http://[::1]/")

    def test_zone_variants_are_atomic_and_pure_on_replay(self):
        inputs = ("[::1]", "[::1%lo]", "https://[fe80::1%25eth0]/", "[fd00::1]")
        initial = tuple(review_ipv6_authority_zone(v) for v in inputs)
        for _ in range(128):
            self.assertEqual(tuple(review_ipv6_authority_zone(v) for v in inputs), initial)
        self.assertEqual(inputs, ("[::1]", "[::1%lo]", "https://[fe80::1%25eth0]/", "[fd00::1]"))


if __name__ == "__main__":
    unittest.main()
