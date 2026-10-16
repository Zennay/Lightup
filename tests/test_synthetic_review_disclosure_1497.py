"""Ordinary tests of #1497 fictional-only review quarantine; no production authority."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lightup.synthetic_review_disclosure_1497 import review_fictional_handoff_notes as review


VALID = "Review asset alpha.example.test; capability header_read; risk 2."


class FictionalDisclosureReviewTests(unittest.TestCase):
    def test_one_fictional_note_stays_review_only(self):
        verdict = review((VALID,))
        self.assertEqual(verdict.status, "REVIEW_ONLY")
        self.assertIn("NOT AUTHORIZED", verdict.notice)
        self.assertEqual(verdict.reviewed_notes, 1)

    def test_two_notes_return_only_count(self):
        x = review((VALID, "Asset beta.example.test; risk 4."))
        self.assertEqual(x.status, "REVIEW_ONLY")
        self.assertEqual(x.reviewed_notes, 2)
        self.assertNotIn("alpha", repr(x))
        self.assertNotIn("beta", repr(x))

    def test_all_authority_flags_always_false(self):
        for notes in ((VALID,), ("Sensitive source example.com",), ()):
            with self.subTest(notes=bool(notes)):
                verdict = review(notes)
                self.assertIs(verdict.authorized, False)
                self.assertIs(verdict.consent_verified, False)
                self.assertIs(verdict.dispatch_allowed, False)
                self.assertIs(verdict.release_allowed, False)

    def test_result_is_frozen(self):
        with self.assertRaises(FrozenInstanceError):
            review((VALID,)).status = "AUTHORIZED"

    def test_permutation_deterministic(self):
        a = VALID
        b = "Asset beta.example.test; risk 4."
        self.assertEqual(review((a, b)), review((b, a)))

    def test_list_not_accepted(self):
        self.assertEqual(review([VALID]).status, "HOLD")

    def test_empty_tuple_denied(self):
        self.assertEqual(review(()).status, "HOLD")

    def test_more_than_sixteen_denied(self):
        self.assertEqual(review((VALID,) * 17).status, "HOLD")

    def test_subclass_tuple_denied(self):
        class InheritedTuple(tuple):
            pass
        self.assertEqual(review(InheritedTuple((VALID,))).status, "HOLD")

    def test_unknown_entry_type_denied(self):
        for sample in (None, True, 123, {"note": VALID}, ["x"], object()):
            with self.subTest(t=type(sample)):
                self.assertEqual(review((sample,)).status, "HOLD")

    def test_str_subclass_denied_without_coercion(self):
        class Deceptive(str):
            def __str__(self):
                raise RuntimeError("do not coerce")
        self.assertEqual(review((Deceptive(VALID),)).status, "HOLD")

    def test_blank_and_space_denied(self):
        for value in ("", "  ", "\n"):
            with self.subTest(value=repr(value)):
                self.assertEqual(review((value,)).status, "HOLD")

    def test_unicode_and_bidi_denied(self):
        for value in ("café alpha.example.test", "\u202ealpha.example.test", "alphа.example.test"):
            with self.subTest(value=repr(value)):
                self.assertEqual(review((value,)).status, "HOLD")

    def test_control_character_denied(self):
        for value in ("alpha.example.test\rtest", "alpha.example.test\x00", "alpha.example.test\t"):
            with self.subTest(value=repr(value)):
                self.assertEqual(review((value,)).status, "HOLD")

    def test_single_note_budget_denied(self):
        self.assertEqual(review(("alpha.example.test " + "a" * 4097,)).status, "HOLD")

    def test_total_budget_atomic(self):
        self.assertEqual(review((VALID + " " + "a" * 2800,) * 16).status, "HOLD")

    def test_unknown_public_and_private_host_denied(self):
        for host in ("company.com", "intranet.local", "alpha.example.test.attacker.com",
                     "bad.example", "partner.co.uk", "example.test"):
            with self.subTest(host=host):
                result = review(("Asset " + host + "; risk 1.",))
                self.assertEqual(result.status, "HOLD")
                self.assertEqual(result.reviewed_notes, 0)
                self.assertNotIn(host, result.notice)

    def test_uppercase_reserved_name_denied(self):
        self.assertEqual(review(("Asset Alpha.example.test",)).status, "HOLD")

    def test_many_nested_fictional_labels_denied(self):
        self.assertEqual(review(("Asset a.b.example.test",)).status, "HOLD")

    def test_embedded_ipv4_public_and_lab_denied(self):
        for ip in ("8.8.8.8", "127.0.0.1", "192.0.2.7", "10.3.1.8"):
            with self.subTest(ip=ip):
                self.assertEqual(review((VALID + " IP " + ip,)).status, "HOLD")

    def test_ipv6_literals_denied(self):
        for ip in ("::1", "2001:db8::3", "fe80::1"):
            with self.subTest(ip=ip):
                self.assertEqual(review((VALID + " IP " + ip,)).status, "HOLD")

    def test_email_url_and_html_denied(self):
        for value in ("user@example.com", "https://alpha.example.test/",
                      "http://real.example.org", "www.company.com",
                      "<script>alert(1)</script>"):
            with self.subTest(value=value):
                self.assertEqual(review((VALID + " " + value,)).status, "HOLD")

    def test_credential_markers_denied(self):
        for value in ("API_KEY", "password", "Bearer", "access_token",
                      "private_key", "secret", "sk-secretvalue"):
            with self.subTest(value=value):
                self.assertEqual(review((VALID + " " + value,)).status, "HOLD")

    def test_atomic_quarantine_of_mixed_batch(self):
        verdict = review((VALID, "customer.example.com", VALID))
        self.assertEqual(verdict.reviewed_notes, 0)
        self.assertEqual(verdict.status, "HOLD")
        self.assertEqual(verdict.notice, review((None,)).notice)

    def test_no_file_sqlite_socket_or_subprocess_side_effects(self):
        with patch("builtins.open", side_effect=AssertionError("file")), \
             patch("os.open", side_effect=AssertionError("os")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("db")), \
             patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            self.assertEqual(review((VALID,)).status, "REVIEW_ONLY")
            self.assertEqual(review((VALID, "client.com")).status, "HOLD")


class FictionalDisclosureCliTests(unittest.TestCase):
    def invoke(self, content: bytes, *args: str):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "lightup.synthetic_review_disclosure_cli_1497", *args],
            input=content, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, timeout=8, check=False,
        )

    def test_real_subprocess_review_only_exit_two(self):
        x = self.invoke(json.dumps([VALID]).encode(), "--synthetic-only")
        self.assertEqual(x.returncode, 2, x.stderr)
        data = json.loads(x.stdout)
        self.assertEqual(data["status"], "REVIEW_ONLY")
        self.assertFalse(data["authorized"])
        self.assertFalse(data["release_allowed"])

    def test_real_subprocess_bad_domain_generic_hold_exit_three(self):
        x = self.invoke(b'["private.customer.com"]', "--synthetic-only")
        self.assertEqual(x.returncode, 3)
        self.assertEqual(json.loads(x.stdout)["status"], "HOLD")
        self.assertNotIn(b"private.customer.com", x.stdout)

    def test_real_subprocess_invalid_json_holds(self):
        x = self.invoke(b'not json', "--synthetic-only")
        self.assertEqual(x.returncode, 3)
        self.assertEqual(json.loads(x.stdout)["reviewed_notes"], 0)

    def test_real_subprocess_no_flag_holds(self):
        x = self.invoke(json.dumps([VALID]).encode())
        self.assertEqual(x.returncode, 3)

    def test_real_subprocess_no_positive_exit_code_even_on_good_json(self):
        for raw in (b'[]', b'{}', b'null', b'123', b'["x"]', json.dumps([VALID]).encode()):
            with self.subTest(raw=raw[:30]):
                self.assertIn(self.invoke(raw, "--synthetic-only").returncode, (2, 3))

    def test_real_subprocess_rejects_large_stdin(self):
        x = self.invoke(b'["' + b'a' * 32770 + b'"]', "--synthetic-only")
        self.assertEqual(x.returncode, 3)

    def test_real_subprocess_rejects_nested_dict(self):
        x = self.invoke(b'[{"text":"alpha.example.test"}]', "--synthetic-only")
        self.assertEqual(x.returncode, 3)


if __name__ == "__main__":
    unittest.main()
