"""Issue #1424: exact built-in IP-literal review, with no target I/O."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from pathlib import Path
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


if __name__ == "__main__":
    main()
