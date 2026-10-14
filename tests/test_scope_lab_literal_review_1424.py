"""Issue #1424: exact built-in IP-literal review, with no target I/O."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from pathlib import Path
import json
import subprocess
from unittest import TestCase, main, mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.scope_lab_literal_review_1424 import LabLiteralReview, review_lab_literal


class LiteralReviewOfflineTests(TestCase):
    flags = (
        "authorization_verified", "permit_issued", "execution_enabled",
        "merge_approved", "release_approved",
    )

    def assert_receipt(self, value, expected_status, expected_class):
        receipt = review_lab_literal(value)
        self.assertIs(type(receipt), LabLiteralReview)
        self.assertEqual(receipt.status, expected_status)
        self.assertEqual(receipt.classification, expected_class)
        self.assertEqual(set(item.name for item in fields(receipt)),
                         {"status", "classification", *self.flags})
        for key in self.flags:
            self.assertIs(getattr(receipt, key), False, key)
        self.assertNotIn("target", repr(receipt).lower())
        self.assertNotIn("grant", repr(receipt).lower())
        return receipt

    def test_ipv4_private_use_membership_is_explicit(self):
        for value in (
            "10.0.0.1", "10.255.255.254", "172.16.0.1",
            "172.31.255.254", "192.168.0.1", "192.168.255.254",
        ):
            with self.subTest(value=value):
                self.assert_receipt(value, "REVIEW_ONLY", "PRIVATE_USE")

    def test_loopback_both_families(self):
        for value in ("127.0.0.1", "127.255.255.254", "::1"):
            with self.subTest(value=value):
                self.assert_receipt(value, "REVIEW_ONLY", "LOOPBACK")

    def test_ipv6_ula_only(self):
        for value in ("fc00::1", "fd00::1", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"):
            with self.subTest(value=value):
                self.assert_receipt(value, "REVIEW_ONLY", "PRIVATE_USE")

    def test_reserved_non_global_documentation_and_link_local_hold(self):
        values = (
            "0.0.0.0", "255.255.255.255", "192.0.2.1", "198.51.100.1",
            "203.0.113.1", "198.18.0.1", "198.19.255.254", "169.254.1.1",
            "100.64.0.1", "224.0.0.1", "240.0.0.1", "192.88.99.1",
            "::", "2001:db8::1", "fe80::1", "ff02::1", "2001::1",
            "::ffff:c0a8:101", "::c0a8:101", "2001:4860:4860::8888",
            "8.8.8.8", "1.1.1.1",
        )
        for value in values:
            with self.subTest(value=value):
                self.assert_receipt(value, "HOLD", "UNTRUSTED")

    def test_noncanonical_or_embedded_authority_is_hold(self):
        values = (
            "", " ", "\n10.0.0.1", "10.0.0.1 ", "010.0.0.1",
            "10.0.0.1:443", "http://10.0.0.1", "10.0.0.1/8",
            "10.0.0.1\x00", "127.1", "localhost", "[fd00::1]",
            "FD00::1", "fd00:0:0:0:0:0:0:1",
            "fe80::1%eth0", "fe80::1%1", "::ffff:192.168.1.1",
            "a" * 1024,
        )
        for value in values:
            with self.subTest(value=value):
                self.assert_receipt(value, "HOLD", "UNTRUSTED")

    def test_type_confusion_and_untrusted_getters_do_not_run(self):
        class StringSubclass(str):
            pass

        class Spoof:
            def __str__(self):
                raise AssertionError("untrusted __str__ must not be invoked")

            def __bool__(self):
                raise AssertionError("untrusted __bool__ must not be invoked")

        for value in (False, True, 0, 12, None, b"10.0.0.1",
                      ["10.0.0.1"], {"addr": "10.0.0.1"},
                      StringSubclass("10.0.0.1"), Spoof()):
            with self.subTest(type=type(value).__name__):
                self.assert_receipt(value, "HOLD", "UNTRUSTED")

    def test_review_receipts_are_immutable_and_authority_false(self):
        for value in ("10.1.1.1", "::1", "192.0.2.1"):
            receipt = review_lab_literal(value)
            for name in ("status", "classification", *self.flags):
                with self.subTest(value=value, name=name):
                    with self.assertRaises((FrozenInstanceError, AttributeError)):
                        setattr(receipt, name, True)
            with self.assertRaises((AttributeError, TypeError)):
                receipt.__dict__["permit_issued"] = True

    def test_external_constructor_cannot_forge_review_or_permission(self):
        # Frozen dataclass still exposes a public constructor: enforce exact
        # False and coherent status/classification on all external instances.
        for name in self.flags:
            for falsy_or_truthy in (True, 0, 1, "", None, "false"):
                with self.subTest(flag=name, value=repr(falsy_or_truthy)):
                    with self.assertRaises(ValueError):
                        LabLiteralReview(**{name: falsy_or_truthy})
        invalid_shapes = (
            ("YES", "PRIVATE_USE"),
            ("REVIEW_ONLY", "UNTRUSTED"),
            ("HOLD", "PRIVATE_USE"),
            ("REVIEW_ONLY", "HOLD"),
            (True, "LOOPBACK"),
            ("HOLD", False),
        )
        for status, classification in invalid_shapes:
            with self.subTest(status=repr(status), cls=repr(classification)):
                with self.assertRaises(ValueError):
                    LabLiteralReview(status=status, classification=classification)
        self.assert_receipt("127.0.0.1", "REVIEW_ONLY", "LOOPBACK")
        self.assert_receipt("192.0.2.1", "HOLD", "UNTRUSTED")

    def test_hold_receipts_do_not_share_mutable_identity_between_calls(self):
        first = review_lab_literal("192.0.2.1")
        second = review_lab_literal("8.8.8.8")
        self.assertIsNot(first, second)
        self.assertIs(first.permit_issued, False)
        # Any caller with arbitrary Python object mutation powers can bypass
        # dataclass frozen, but it must not poison any later returned HOLD.
        object.__setattr__(first, "permit_issued", True)
        try:
            new = self.assert_receipt("203.0.113.1", "HOLD", "UNTRUSTED")
            self.assertIsNot(new, first)
            self.assertIsNot(new, second)
        finally:
            object.__setattr__(first, "permit_issued", False)

    def test_no_dns_socket_disk_or_process_even_for_positive_literal(self):
        # The module is already imported; exercise only the reviewer runtime.
        with (
            mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS invoked")) as dns,
            mock.patch("socket.socket", side_effect=AssertionError("socket invoked")) as sock,
            mock.patch("builtins.open", side_effect=AssertionError("disk invoked")) as op,
            mock.patch("subprocess.run", side_effect=AssertionError("process invoked")) as proc,
            mock.patch("os.system", side_effect=AssertionError("command invoked")) as command,
        ):
            for value in ("10.0.0.1", "fd00::1", "192.0.2.1", "8.8.8.8"):
                receipt = review_lab_literal(value)
                self.assertIs(receipt.permit_issued, False)
            dns.assert_not_called()
            sock.assert_not_called()
            op.assert_not_called()
            proc.assert_not_called()
            command.assert_not_called()


    def test_real_optin_cli_never_exits_zero_or_repeats_literals(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_lab_literal_1424_offline.py"
        self.assertTrue(script.is_file())
        cases = (
            (("--literal", "10.23.45.67"), 3, "REVIEW_ONLY", "PRIVATE_USE"),
            (("--literal", "fd00::2"), 3, "REVIEW_ONLY", "PRIVATE_USE"),
            (("--literal", "127.0.0.1"), 3, "REVIEW_ONLY", "LOOPBACK"),
            (("--literal", "192.0.2.1"), 2, "HOLD", "UNTRUSTED"),
            (("--literal", "8.8.8.8"), 2, "HOLD", "UNTRUSTED"),
            (("--literal", "http://10.23.45.67"), 2, "HOLD", "UNTRUSTED"),
            (("--literal", "10.23.45.67", "--literal", "127.0.0.1"), 2, "HOLD", "UNTRUSTED"),
            (("--literal",), 2, "HOLD", "UNTRUSTED"),
            ((), 2, "HOLD", "UNTRUSTED"),
            (("--bad-argument", "synthetic-private-secret-value"), 2, "HOLD", "UNTRUSTED"),
        )
        for args, code, status, classification in cases:
            with self.subTest(args=args):
                result = subprocess.run(
                    [sys.executable, "-B", str(script), *args],
                    input=b"synthetic-stdin-secret-never-read",
                    capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(result.stderr, b"")
                receipt = json.loads(result.stdout)
                self.assertEqual(receipt["status"], status)
                self.assertEqual(receipt["classification"], classification)
                self.assertEqual(set(receipt), {"status", "classification", *self.flags})
                for key in self.flags:
                    self.assertIs(receipt[key], False, key)
                self.assertNotIn(b"synthetic", result.stdout)
                self.assertNotIn(b"10.23.45.67", result.stdout)
                self.assertNotIn(b"8.8.8.8", result.stdout)
                self.assertNotIn(b"192.0.2.1", result.stdout)
                self.assertNotIn(b"127.0.0.1", result.stdout)


if __name__ == "__main__":
    main()
