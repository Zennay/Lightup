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


VALID = "Asset alpha.example.test; capability header_read; proposed risk 2."


class FictionalDisclosureReviewTests(unittest.TestCase):
    def test_one_fictional_note_stays_review_only(self):
        verdict = review((VALID,))
        self.assertEqual(verdict.status, "REVIEW_ONLY")
        self.assertIn("NOT AUTHORIZED", verdict.notice)
        self.assertEqual(verdict.reviewed_notes, 1)

    def test_two_notes_return_only_count(self):
        x = review((VALID, "Asset beta.example.test; capability tls_review; proposed risk 4."))
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
        b = "Asset beta.example.test; capability tls_review; proposed risk 4."
        self.assertEqual(review((a, b)), review((b, a)))

    def test_list_not_accepted(self):
        self.assertEqual(review([VALID]).status, "HOLD")

    def test_empty_tuple_denied(self):
        self.assertEqual(review(()).status, "HOLD")

    def test_exact_sixteen_fictional_notes_allowed_but_not_authorized(self):
        verdict = review(tuple(f"Asset lab{i}.example.test; capability header_read; proposed risk 2." for i in range(16)))
        self.assertEqual(verdict.status, "REVIEW_ONLY")
        self.assertEqual(verdict.reviewed_notes, 16)
        self.assertIs(verdict.authorized, False)

    def test_1600_control_and_separator_insertions_are_quarantined(self):
        # Every insertion must fail for arbitrary positions, including inside
        # the otherwise valid reserved hostname; no parser substring rescue.
        positions = range(len(VALID) + 1)
        bad_chars = ("\x00", "\x01", "\x09", "\x0a", "\x0d",
                     "\x1f", "\x7f", "/", "\\", "\"",
                     "'", "<", ">", "@", "#", "~", "|", "\u202e")
        tested = 0
        for index in positions:
            for char in bad_chars:
                verdict = review((VALID[:index] + char + VALID[index:],))
                self.assertEqual(verdict.status, "HOLD", (index, ord(char)))
                self.assertEqual(verdict.reviewed_notes, 0)
                tested += 1
        self.assertGreater(tested, 1000)

    def test_16_distinct_proposals_atomic_late_duplicate_hold(self):
        valid = tuple(
            f"Asset node{i}.example.test; capability header_read; proposed risk 2."
            for i in range(15)
        )
        self.assertEqual(review(valid + (
            "Asset node15.example.test; capability header_read; proposed risk 5.",
        )).status, "REVIEW_ONLY")
        self.assertEqual(review(valid + (valid[0],)).status, "HOLD")

    def test_input_tuple_and_strings_not_mutated(self):
        records = (VALID, "Asset beta.example.test; capability header_read; proposed risk 3.")
        before = records[:]
        self.assertEqual(review(records).status, "REVIEW_ONLY")
        self.assertEqual(records, before)

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

    def test_dotted_suffix_partial_match_never_promotes_review(self):
        for ending in (".x", ".3", ".999", ".", "..", "-other", "_other"):
            with self.subTest(ending=ending):
                self.assertEqual(review(("Asset alpha.example.test" + ending,)).status, "HOLD")

    def test_dotted_numeric_and_internal_aliased_values_denied(self):
        for value in ("version 3.14", "host internal.net", "mixed 8.8.8.8a",
                      "asset a.b.example.test", "asset alpha.example.test.alpha"):
            with self.subTest(value=value):
                self.assertEqual(review((VALID + " " + value,)).status, "HOLD")

    def test_common_secret_shapes_denied_without_echo(self):
        for value in ("token=xyz", "cookie=xyz", "client_secret=xyz",
                      "ghp_example123", "github_pat_abc123",
                      "AKIA1234567890ABCDEF"):
            with self.subTest(value=value):
                verdict = review((VALID + " " + value,))
                self.assertEqual(verdict.status, "HOLD")
                self.assertNotIn(value, repr(verdict))

    def test_fake_operator_approval_claim_quarantined(self):
        for value in ("APPROVED", "authorized", "consent granted",
                      "approval granted", "GO LIVE", "signed off"):
            with self.subTest(value=value):
                self.assertEqual(review((VALID + " " + value,)).status, "HOLD")

    def test_any_extra_text_never_passes_as_a_scope_record(self):
        for extra in (" unrelated notes", " scan was approved", " access to customer",
                      " private payload", "\nasset beta.example.test",
                      " user john at internal", "; additional field enabled",
                      " ; more", " #tracked", "\n", "\t"):
            with self.subTest(extra=repr(extra)):
                self.assertEqual(review((VALID + extra,)).status, "HOLD")

    def test_missing_required_fields_fail_atomically(self):
        for note in ("Asset alpha.example.test",
                     "Asset alpha.example.test; capability header_read.",
                     "Asset alpha.example.test; proposed risk 2.",
                     "Asset alpha.example.test; capability header_read; proposed risk.",
                     "Asset alpha.example.test; capability header_read; proposed risk 2"):
            with self.subTest(note=note):
                self.assertEqual(review((note,)).status, "HOLD")

    def test_unknown_capabilities_can_never_be_self_declared(self):
        for capability in ("scan", "exploit", "ssh", "header-write", "HEADER_READ",
                           "capability", "tls_review_more", "header_read_",
                           "a" * 60):
            with self.subTest(capability=capability):
                note = f"Asset alpha.example.test; capability {capability}; proposed risk 2."
                self.assertEqual(review((note,)).status, "HOLD")

    def test_all_documented_fictional_capability_examples_are_review_only(self):
        for capability in ("header_read", "tls_review", "service_inventory", "passive_discovery"):
            with self.subTest(capability=capability):
                note = f"Asset alpha.example.test; capability {capability}; proposed risk 3."
                self.assertEqual(review((note,)).status, "REVIEW_ONLY")

    def test_risk_is_exact_canonical_one_to_five(self):
        for risk in range(1, 6):
            with self.subTest(risk=risk):
                self.assertEqual(review((f"Asset alpha.example.test; capability header_read; proposed risk {risk}.",)).status, "REVIEW_ONLY")
        for bad in ("0", "6", "10", "02", "2.0", "+2", "-2", "true", "4 "):
            with self.subTest(risk=bad):
                self.assertEqual(review((f"Asset alpha.example.test; capability header_read; proposed risk {bad}.",)).status, "HOLD")

    def test_duplicate_identical_claim_is_atomic_hold(self):
        self.assertEqual(review((VALID, VALID)).status, "HOLD")

    def test_same_asset_and_capability_cannot_have_conflicting_risks(self):
        conflicting = "Asset alpha.example.test; capability header_read; proposed risk 5."
        self.assertEqual(review((VALID, conflicting)).status, "HOLD")

    def test_same_asset_can_have_independent_capabilities_without_approval(self):
        second = "Asset alpha.example.test; capability tls_review; proposed risk 5."
        verdict = review((VALID, second))
        self.assertEqual(verdict.status, "REVIEW_ONLY")
        self.assertEqual(verdict.reviewed_notes, 2)
        self.assertFalse(verdict.authorized)

    def test_strict_spacing_case_and_punctuation(self):
        for bad in (VALID.lower(), VALID.upper(), VALID.replace("; ", ";"),
                    VALID.replace("Asset ", "Asset  "), VALID.replace("risk 2.", "risk 2. "),
                    VALID.replace("example.test", "example.test."),
                    VALID.replace("Asset ", " ASSET ")):
            with self.subTest(value=repr(bad[:45])):
                self.assertEqual(review((bad,)).status, "HOLD")

    def test_canonical_host_label_upper_bound_and_shape(self):
        longest = "a" + "b" * 61 + "c"
        self.assertEqual(len(longest), 63)
        note = f"Asset {longest}.example.test; capability tls_review; proposed risk 5."
        self.assertEqual(review((note,)).status, "REVIEW_ONLY")
        for label in (longest + "d", "a-", "-a", "a_b", "a.b"):
            with self.subTest(label=label[:20]):
                bad = f"Asset {label}.example.test; capability tls_review; proposed risk 5."
                self.assertEqual(review((bad,)).status, "HOLD")

    def test_direct_verdict_cannot_spoof_authorization_state(self):
        from lightup.synthetic_review_disclosure_1497 import DisclosureVerdict
        for state, notice, count in (
            ("AUTHORIZED", "APPROVED", 1),
            ("APPROVED", "HOLD", 1),
            ("REVIEW_ONLY", "APPROVED", 1),
            ("HOLD", "APPROVED", 0),
            ("HOLD", "HOLD — offline handoff quarantined; no input echoed. NOT AUTHORIZED.", 1),
            ("REVIEW_ONLY", "REVIEW_ONLY — fictional notes still require independent human privacy and scope review. NOT AUTHORIZED.", 0),
            ("REVIEW_ONLY", "REVIEW_ONLY — fictional notes still require independent human privacy and scope review. NOT AUTHORIZED.", 17),
        ):
            with self.subTest(state=state, count=count):
                with self.assertRaisesRegex(ValueError, "invalid fictional review verdict"):
                    DisclosureVerdict(state, notice, count)

    def test_direct_verdict_rejects_type_confused_status_and_count(self):
        from lightup.synthetic_review_disclosure_1497 import DisclosureVerdict
        class Spoof(str):
            pass
        for status, count in ((Spoof("HOLD"), 0), ("HOLD", False), ("HOLD", "0"), ("HOLD", 0.0)):
            with self.subTest(status=type(status), count=type(count)):
                with self.assertRaises(ValueError):
                    DisclosureVerdict(status, "HOLD — offline handoff quarantined; no input echoed. NOT AUTHORIZED.", count)

    def test_punycode_fictional_hostname_still_holds(self):
        for label in ("xn--", "xn--admin", "xn--paypa1"):
            with self.subTest(label=label):
                note = f"Asset {label}.example.test; capability header_read; proposed risk 2."
                self.assertEqual(review((note,)).status, "HOLD")

    def test_direct_verdict_cannot_inject_noncanonical_hold_detail(self):
        from lightup.synthetic_review_disclosure_1497 import DisclosureVerdict
        canonical = review((None,))
        self.assertEqual(DisclosureVerdict("HOLD", canonical.notice, 0), canonical)
        with self.assertRaises(ValueError):
            DisclosureVerdict("HOLD", canonical.notice + " Alpha.example.test", 0)

    def test_forged_flags_cannot_be_injected_via_constructor(self):
        from lightup.synthetic_review_disclosure_1497 import DisclosureVerdict
        with self.assertRaises(TypeError):
            DisclosureVerdict("REVIEW_ONLY", "APPROVED", 1, authorized=True)
        with self.assertRaises(TypeError):
            DisclosureVerdict("REVIEW_ONLY", "APPROVED", 1, dispatch_allowed=True)

    def test_invalid_mid_batch_returns_exact_same_generic_hold(self):
        valid_1 = VALID
        valid_2 = "Asset beta.example.test; capability tls_review; proposed risk 4."
        wrong = "Asset gamma.example.test; capability root_shell; proposed risk 4."
        for notes in ((wrong, valid_1, valid_2),
                      (valid_1, wrong, valid_2),
                      (valid_1, valid_2, wrong)):
            with self.subTest(pos=notes.index(wrong)):
                self.assertEqual(review(notes), review((None,)))

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

    def test_real_subprocess_deep_json_nesting_generic_hold(self):
        deeply_nested = b"[" * 1500 + b"0" + b"]" * 1500
        x = self.invoke(deeply_nested, "--synthetic-only")
        self.assertEqual(x.returncode, 3, x.stderr)
        self.assertEqual(json.loads(x.stdout)["status"], "HOLD")
        self.assertNotIn(b"Traceback", x.stderr)

    def test_cli_rejects_duplicate_records_without_input_echo(self):
        payload = json.dumps([VALID, VALID]).encode("utf-8")
        result = self.invoke(payload, "--synthetic-only")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)["status"], "HOLD")
        self.assertNotIn(b"alpha.example.test", result.stdout)

    def test_cli_rejects_ambiguous_extra_content(self):
        payload = json.dumps([VALID + " consent granted"]).encode("utf-8")
        result = self.invoke(payload, "--synthetic-only")
        self.assertEqual(result.returncode, 3)
        self.assertNotIn(b"consent granted", result.stdout)

    def test_cli_rejects_partial_scope_on_json_keyed_dict(self):
        result = self.invoke(json.dumps({"notes": [VALID]}).encode(), "--synthetic-only")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)["reviewed_notes"], 0)

    def test_cli_rejects_surrogate_escape_without_traceback_or_echo(self):
        x = self.invoke(b'["Asset alpha.example.test; capability header_read; proposed risk 2.\\ud800"]', "--synthetic-only")
        self.assertEqual(x.returncode, 3)
        self.assertEqual(json.loads(x.stdout)["status"], "HOLD")
        self.assertNotIn(b"Traceback", x.stderr)
        self.assertNotIn(b"alpha.example.test", x.stdout)

    def test_cli_rejects_nonfinite_number_and_bad_scalar_types(self):
        for payload in (b'["Asset alpha.example.test", NaN]',
                        b'[true]', b'[false]', b'[null]', b'[0]',
                        b'["Asset alpha.example.test", Infinity]'):
            with self.subTest(payload=payload[:32]):
                x = self.invoke(payload, "--synthetic-only")
                self.assertEqual(x.returncode, 3)
                self.assertEqual(json.loads(x.stdout)["reviewed_notes"], 0)

    def test_real_subprocess_rejects_nested_dict(self):
        x = self.invoke(b'[{"text":"alpha.example.test"}]', "--synthetic-only")
        self.assertEqual(x.returncode, 3)


if __name__ == "__main__":
    unittest.main()
