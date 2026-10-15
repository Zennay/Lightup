"""Offline lexical hostname shape gate: review-only, never target authorization.

These tests constrain ONLY the new independent snapshot reviewer/JSON CLI.
Other workers retain ownership of real IDNA, scope, consent and execution code.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from unittest.mock import patch

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from lightup.scope_collection_snapshot_review_294 import (
    snapshot_untrusted_scope_collections,
    inspect_existing_scope_policy,
)
from lightup.scope import ScopePolicy
from scope_294_collection_review_cli import review_private_manifest

ALL_PERMITS = (
    "authorization_verified",
    "permit_issued",
    "execution_enabled",
    "scan_approved",
    "merge_approved",
    "release_approved",
)


class OfflineHostShapeTests(unittest.TestCase):
    def assert_not_authority(self, r, expected):
        self.assertEqual(r.status, expected)
        self.assertIs(bool(r), False)
        public = r.to_public_dict()
        self.assertEqual(public["status"], expected)
        self.assertEqual(set(public), {"status", "reason", *ALL_PERMITS})
        for f in ALL_PERMITS:
            self.assertIs(public[f], False)
            self.assertIs(getattr(r, f), False)
        self.assertNotIn("fixture.example.test", str(public))

    def test_explicit_hosts_must_not_be_uris_or_url_authorities(self):
        names = (
            "https://fixture.example.test",
            "http://fixture.example.test/path",
            "fixture.example.test:443",
            "user@fixture.example.test",
            "fixture.example.test/?x=1",
            "fixture.example.test#fragment",
            "fixture.example.test\\evil",
        )
        for value in names:
            with self.subTest(value=value):
                self.assert_not_authority(
                    snapshot_untrusted_scope_collections([value], ()), "HOLD"
                )

    def test_empty_labels_trailing_dot_and_oversized_labels_are_hold(self):
        names = (
            ".fixture.example.test", "fixture..example.test",
            "fixture.example.test.", "a" * 64 + ".example.test",
            "-", "-fixture.example.test", "fixture-.example.test",
            "_fixture.example.test",
        )
        for value in names:
            with self.subTest(value=value[:35]):
                self.assert_not_authority(
                    snapshot_untrusted_scope_collections([value], ()), "HOLD"
                )

    def test_unicode_format_surrogate_space_and_invisible_markers_are_hold(self):
        names = (
            "fixture\u202e.example.test", "fixture\u200b.example.test",
            "fixture\u00a0.example.test", "fixture\ud800.example.test",
            "fixture\n.example.test", "fixture\x7f.example.test",
            " fixture.example.test", "fixture.example.test ",
        )
        for value in names:
            with self.subTest(escaped=ascii(value)):
                self.assert_not_authority(
                    snapshot_untrusted_scope_collections([value], ()), "HOLD"
                )

    def test_exact_lexical_valid_hosts_do_not_grant_permissions(self):
        names = (
            "fixture.example.test", "localhost", "sub-domain.example.test",
            "EXAMPLE.TEST", "xn--bcher-kva.example.test",
            "bücher.example.test", "mañana.example.test",
        )
        for value in names:
            with self.subTest(value=value):
                r = snapshot_untrusted_scope_collections((value,), ())
                self.assert_not_authority(r, "REVIEW_ONLY")
                self.assertEqual(r._hosts, frozenset({value}))

    def test_no_normalization_or_alias_collapsing(self):
        names = ["xn--bcher-kva.example.test", "bücher.example.test"]
        r = snapshot_untrusted_scope_collections(names, ())
        self.assert_not_authority(r, "REVIEW_ONLY")
        self.assertEqual(r._hosts, frozenset(names))
        names.pop()
        self.assertEqual(len(r._hosts), 2)

    def test_one_bad_member_fails_closed_without_exposing_others(self):
        names = ["fixture.example.test", "https://bad.example.test"]
        for entries in (names, list(reversed(names))):
            with self.subTest(entries=entries):
                r = snapshot_untrusted_scope_collections(entries, ["8.8.8.0/24"])
                self.assert_not_authority(r, "HOLD")
                self.assertEqual(r._hosts, frozenset())
                self.assertEqual(r._networks, ())

    def test_cli_reviews_only_lexically_safe_hostname_shape(self):
        for name, state in (
            ("fixture.example.test", "REVIEW_ONLY"),
            ("https://fixture.example.test", "HOLD"),
            ("fixture..example.test", "HOLD"),
            ("fixture.example.test:443", "HOLD"),
            ("bücher.example.test", "REVIEW_ONLY"),
        ):
            with self.subTest(name=name):
                raw = json.dumps(
                    {"hosts": [name], "networks": []}, ensure_ascii=True
                ).encode("utf-8")
                r = review_private_manifest(raw)
                self.assert_not_authority(r, state)

    def test_existing_installed_policy_is_only_diagnosed_never_mutated(self):
        original = frozenset({"https://fixture.example.test"})
        policy = ScopePolicy(
            explicit_hosts=original, explicit_networks=(),
            allow_private_lab=False,
        )
        r = inspect_existing_scope_policy(policy)
        self.assert_not_authority(r, "HOLD")
        self.assertIs(policy.explicit_hosts, original)

    def test_lexical_guard_has_no_dns_http_or_process_side_effects(self):
        with patch("socket.socket", side_effect=AssertionError("socket forbidden")), \
             patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch("subprocess.Popen", side_effect=AssertionError("process forbidden")):
            bad = snapshot_untrusted_scope_collections(
                ["https://fixture.example.test"], ()
            )
            good = snapshot_untrusted_scope_collections(
                ["fixture.example.test"], ()
            )
        self.assert_not_authority(bad, "HOLD")
        self.assert_not_authority(good, "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
