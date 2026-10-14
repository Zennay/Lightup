"""Defense-in-depth deterministic adversarial tests of review-only lab literal shape."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import random
import shlex
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.check_scope_lab_literal_offline import review_literal  # noqa: E402

SCRIPT = ROOT / "scripts" / "check_scope_lab_literal_offline.py"
_ALLOWED = tuple(ipaddress.ip_network(cidr) for cidr in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
    "192.168.0.0/16", "::1/128", "fd00::/8",
))
_FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
          "merge_approved", "release_approved")


class AdversarialLabLiteralReviewTests(unittest.TestCase):
    def assertNotAuthorized(self, receipt):
        self.assertIn(receipt["status"], ("HOLD", "REVIEW_ONLY"))
        self.assertTrue(all(receipt[flag] is False for flag in _FLAGS))

    def test_no_network_or_dns_even_on_valid_shape(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket called")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS called")):
                for value in ("127.0.0.1", "::1", "fd12::1", "10.1.2.3",
                              "169.254.1.1", "2001:db8::1", "8.8.8.8"):
                    self.assertNotAuthorized(review_literal(value))

    def test_review_outcome_does_not_cache_or_retain_prior_authority(self):
        values = ("10.1.1.1", "8.8.8.8", "10.1.1.1", "0.0.0.0", "8.8.8.8")
        statuses = [review_literal(value)["status"] for value in values]
        self.assertEqual(statuses, ["REVIEW_ONLY", "HOLD", "REVIEW_ONLY",
                                    "HOLD", "HOLD"])

    def test_random_ipv4_review_shapes_are_only_exact_allowlisted_ranges(self):
        rng = random.Random(0xCAFE)
        for _ in range(1600):
            address = ipaddress.IPv4Address(rng.getrandbits(32))
            result = review_literal(str(address))
            self.assertNotAuthorized(result)
            if result["status"] == "REVIEW_ONLY":
                self.assertTrue(any(address in net for net in _ALLOWED),
                                "a non-lab literal shape was reviewed")

    def test_random_ipv6_review_shapes_are_only_exact_allowlisted_ranges(self):
        rng = random.Random(0xBEEF)
        for _ in range(1600):
            address = ipaddress.IPv6Address(rng.getrandbits(128))
            result = review_literal(str(address))
            self.assertNotAuthorized(result)
            if result["status"] == "REVIEW_ONLY":
                self.assertTrue(any(address in net for net in _ALLOWED),
                                "a non-lab IPv6 literal shape was reviewed")

    def test_mapped_ipv4_is_never_promoted_by_both_families(self):
        for ipv4 in ("127.0.0.1", "10.10.10.10", "8.8.8.8", "192.168.10.10"):
            address = ipaddress.IPv6Address("::ffff:" + ipv4)
            result = review_literal(str(address))
            self.assertEqual(result["status"], "HOLD")
            self.assertNotAuthorized(result)

    def test_controls_unicode_and_invisible_delimiters_fail_closed(self):
        for special in ("\r", "\n", "\t", "\x00", "\x1b", "\u200b",
                        "\ufeff", "\u2060", "\u202e", "\u00a0"):
            result = review_literal("127.0.0.1" + special)
            self.assertEqual(result["status"], "HOLD")
            self.assertNotAuthorized(result)

    def test_shell_and_cannot_execute_downstream_canary(self):
        # Executes only a harmless echo sentinel if a future bug reintroduces
        # success exit status; never invokes a LightUp target-capable action.
        command = (
            shlex.quote(sys.executable) + " " + shlex.quote(str(SCRIPT))
            + " && echo AUTHORITY_SHOULD_NOT_RUN"
        )
        for input_data, expected_rc in ((b"10.1.2.3\n", 3), (b"8.8.8.8\n", 2)):
            with self.subTest(input_data=input_data):
                result = subprocess.run(
                    ["sh", "-c", command], input=input_data,
                    capture_output=True, check=False, timeout=5,
                )
                self.assertEqual(result.returncode, expected_rc, result.stderr)
                self.assertNotIn(b"AUTHORITY_SHOULD_NOT_RUN", result.stdout)
                self.assertNotAuthorized(json.loads(result.stdout))

    def test_cli_receipts_do_not_echo_private_input_even_if_invalid(self):
        for marker in (b"SECRET-CLIENT-ASSET", b"127.0.0.1\x1b[8mSECRET\x1b[0m",
                       b"private.example.invalid", b"fd00::1%PRIVATE-DEVICE"):
            process = subprocess.run(
                [sys.executable, str(SCRIPT)], input=marker,
                capture_output=True, check=False, timeout=5,
            )
            self.assertEqual(process.returncode, 2)
            self.assertNotIn(marker, process.stdout + process.stderr)
            self.assertNotAuthorized(json.loads(process.stdout))


if __name__ == "__main__":
    unittest.main()
