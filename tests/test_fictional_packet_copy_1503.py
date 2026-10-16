"""Ordinary offline tests for independent, non-authorizing #1503 copy checker."""
from __future__ import annotations

import dataclasses
import hashlib
import itertools
import pathlib
import random
import json
import unittest
from unittest.mock import patch

from lightup.fictional_packet_copy_1503 import (
    CopyReview,
    compare_fictional_packet_copies,
)

FIELDS = (
    ("schema", "lightup-fictional-copy-v1"),
    ("asset", "alpha.example.test"),
    ("message", "REVIEW_REQUIRED"),
    ("capabilities", ["metadata_read", "report_preview"]),
    ("authorized", False),
    ("consent_verified", False),
    ("dispatch_allowed", False),
    ("release_allowed", False),
)


def packet(fields=FIELDS):
    return json.dumps(
        dict(fields), ensure_ascii=True, separators=(",", ":"), sort_keys=False
    ).encode("ascii")


CANONICAL = packet()


class FictionalPacketCopyTests(unittest.TestCase):
    def assert_hold(self, other):
        result = compare_fictional_packet_copies(CANONICAL, other)
        self.assertEqual(result.status, "HOLD")
        self.assertIsNone(result.sha256)
        self.assertIs(result.authorized, False)
        self.assertIs(result.consent_verified, False)
        self.assertIs(result.dispatch_allowed, False)
        self.assertIs(result.release_allowed, False)

    def test_identical_copy_is_only_review_only(self):
        result = compare_fictional_packet_copies(CANONICAL, CANONICAL)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.sha256, hashlib.sha256(CANONICAL).hexdigest())
        self.assertIs(result.authorized, False)
        self.assertIs(result.consent_verified, False)
        self.assertIs(result.dispatch_allowed, False)
        self.assertIs(result.release_allowed, False)
        self.assertTrue(dataclasses.is_dataclass(result))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.status = "APPROVED"

    def test_changed_message_held(self):
        self.assert_hold(CANONICAL.replace(b"REVIEW_REQUIRED", b"REVIEW_ON_HOLD"))

    def test_changed_asset_held_with_no_fingerprint(self):
        self.assert_hold(CANONICAL.replace(b"alpha.example.test", b"beta.example.test"))

    def test_changed_capability_held(self):
        self.assert_hold(CANONICAL.replace(b"report_preview", b"scope_review"))

    def test_narrowed_copy_still_held_even_when_not_semantic_expansion(self):
        self.assert_hold(CANONICAL.replace(b',"report_preview"', b""))

    def test_noncanonical_json_whitespace_held(self):
        self.assert_hold(b" " + CANONICAL)
        self.assert_hold(CANONICAL + b"\n")

    def test_reordered_fields_held(self):
        ordered = list(FIELDS)
        ordered[0], ordered[1] = ordered[1], ordered[0]
        self.assert_hold(packet(ordered))

    def test_unknown_missing_duplicate_fields_held(self):
        self.assert_hold(CANONICAL[:-1] + b',"hidden":"example"}')
        self.assert_hold(packet(FIELDS[:-1]))
        self.assert_hold(CANONICAL[:-1] + b',"asset":"beta.example.test"}')

    def test_unicode_escape_alias_and_nonascii_held(self):
        self.assert_hold(CANONICAL.replace(b"alpha", b"\\u0061lpha"))
        self.assert_hold(CANONICAL.replace(b"alpha", "álpha".encode("utf-8")))
        self.assert_hold(CANONICAL.replace(b"alpha", b"\\ud800"))
        self.assert_hold(b"\xef\xbb\xbf" + CANONICAL)

    def test_real_assets_urls_and_confusables_held(self):
        for value in ("example.com", "alpha.example.test.evil", "192.168.0.1",
                      "http://alpha.example.test", "xn--test.example.test",
                      "a--b.example.test", "ends-.example.test"):
            with self.subTest(value=value):
                candidate = packet([(k, value if k == "asset" else v) for k, v in FIELDS])
                self.assert_hold(candidate)

    def test_invalid_message_or_schema_held(self):
        for key, value in (("message", "APPROVED"), ("schema", "v2"),
                           ("message", ""), ("message", 0)):
            self.assert_hold(packet([(k, value if k == key else v) for k, v in FIELDS]))

    def test_capabilities_must_be_canonical_sorted_unique_allowlisted(self):
        for capabilities in ([], ["metadata_read", "metadata_read"],
                             ["scope_review", "metadata_read"], ["exec"],
                             ["metadata_read", True], ["metadata_read"] * 4):
            with self.subTest(capabilities=capabilities):
                self.assert_hold(packet([(k, capabilities if k == "capabilities" else v)
                                         for k, v in FIELDS]))

    def test_true_or_polymorphic_authority_flags_held(self):
        for flag in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            for value in (True, 0, "", [], None, "false"):
                with self.subTest(flag=flag, value=value):
                    self.assert_hold(packet([(k, value if k == flag else v) for k, v in FIELDS]))

    def test_bad_types_and_bounds_atomic(self):
        class ByteSubclass(bytes):
            pass

        for value in (None, "", b"", bytearray(CANONICAL),
                      ByteSubclass(CANONICAL), CANONICAL * 40,
                      b"[]" * 1025):
            self.assert_hold(value)
            result = compare_fictional_packet_copies(value, CANONICAL)
            self.assertEqual((result.status, result.sha256), ("HOLD", None))

    def test_invalid_first_copy_never_yields_partial_sha(self):
        altered = CANONICAL.replace(b"REVIEW_REQUIRED", b"APPROVED")
        self.assertEqual(
            (compare_fictional_packet_copies(altered, CANONICAL).status,
             compare_fictional_packet_copies(altered, CANONICAL).sha256),
            ("HOLD", None),
        )

    def test_duplicate_and_ambiguous_nested_json(self):
        self.assert_hold(CANONICAL.replace(b'["metadata_read","report_preview"]', b'[["metadata_read"],"report_preview"]'))
        self.assert_hold(b'{"schema":"lightup-fictional-copy-v1"}')
        self.assert_hold(b'{"schema":NaN}')
        self.assert_hold(b"[" * 300 + b"]" * 300)

    def test_valid_fictional_asset_and_message_combinations(self):
        for asset, message, caps in itertools.product(
            ("a.example.test", "fictional-7.example.test"),
            ("REVIEW_REQUIRED", "REVIEW_ON_HOLD"),
            (["metadata_read"], ["report_preview", "scope_review"]),
        ):
            payload = packet(
                [(k, {"asset": asset, "message": message, "capabilities": caps}.get(k, v))
                 for k, v in FIELDS]
            )
            verdict = compare_fictional_packet_copies(payload, payload)
            self.assertEqual(verdict.status, "REVIEW_ONLY")

    def test_canonical_input_not_mutated(self):
        first = bytes(CANONICAL)
        second = bytes(CANONICAL)
        compare_fictional_packet_copies(first, second)
        self.assertEqual((first, second), (CANONICAL, CANONICAL))

    def test_no_files_network_process_database_during_comparison(self):
        with patch("builtins.open", side_effect=AssertionError("file IO")), \
             patch("socket.socket", side_effect=AssertionError("network IO")), \
             patch("sqlite3.connect", side_effect=AssertionError("DB IO")), \
             patch("subprocess.Popen", side_effect=AssertionError("process IO")):
            self.assertEqual(compare_fictional_packet_copies(CANONICAL, CANONICAL).status,
                             "REVIEW_ONLY")
            self.assertEqual(compare_fictional_packet_copies(CANONICAL, b"secret").status,
                             "HOLD")

    def test_review_result_constructor_cannot_claim_permission(self):
        with self.assertRaises(TypeError):
            CopyReview(status="REVIEW_ONLY", sha256="0" * 64, authorized=True)
        for status, digest in (("APPROVED", None), ("REVIEW_ONLY", None),
                               ("HOLD", "a" * 64), ("REVIEW_ONLY", "Z" * 64)):
            with self.assertRaises(ValueError):
                CopyReview(status=status, sha256=digest)


    def test_each_byte_substitution_is_atomic_hold_against_original(self):
        for index in range(len(CANONICAL)):
            for replacement in (0, 31, 34, 44, 92, 127, 255):
                if CANONICAL[index] == replacement:
                    continue
                altered = CANONICAL[:index] + bytes((replacement,)) + CANONICAL[index + 1:]
                result = compare_fictional_packet_copies(CANONICAL, altered)
                self.assertEqual((result.status, result.sha256), ("HOLD", None))

    def test_fixed_seed_mutation_fuzz_never_promotes_changed_copy(self):
        rng = random.Random(1503)
        for _ in range(1024):
            index = rng.randrange(len(CANONICAL))
            new_byte = (CANONICAL[index] + rng.randrange(1, 256)) % 256
            altered = CANONICAL[:index] + bytes((new_byte,)) + CANONICAL[index + 1:]
            result = compare_fictional_packet_copies(CANONICAL, altered)
            self.assertEqual((result.status, result.sha256), ("HOLD", None))
            self.assertIs(result.release_allowed, False)

    def test_standalone_module_not_imported_by_production_modules(self):
        root = pathlib.Path(__file__).resolve().parents[1] / "src" / "lightup"
        for path in root.rglob("*.py"):
            if path.name == "fictional_packet_copy_1503.py":
                continue
            with self.subTest(file=path.relative_to(root)):
                self.assertNotIn("fictional_packet_copy_1503", path.read_text(encoding="utf-8"))

if __name__ == "__main__":
    unittest.main()
