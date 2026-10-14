"""Deterministic, offline, independent integer-oracle admission review #1424.

A review receipt is never an authorization grant. No DNS, scan or target I/O.
The expected membership oracle deliberately does NOT use is_private/is_global.
"""
from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
import random
import sys
from unittest import TestCase, main

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lightup.scope_lab_literal_review_1424 import review_lab_literal


_FALSE_FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)


def _expect_ipv4(number: int) -> tuple[str, str]:
    pools = (
        (0x7F000000, 0x7FFFFFFF, "LOOPBACK"),
        (0x0A000000, 0x0AFFFFFF, "PRIVATE_USE"),
        (0xAC100000, 0xAC1FFFFF, "PRIVATE_USE"),
        (0xC0A80000, 0xC0A8FFFF, "PRIVATE_USE"),
    )
    for start, end, label in pools:
        if start < number < end:
            return "REVIEW_ONLY", label
    return "HOLD", "UNTRUSTED"


def _expect_ipv6(number: int) -> tuple[str, str]:
    if number == 1:
        return "REVIEW_ONLY", "LOOPBACK"
    # ULA fc00::/7: exact 7 leading bits 1111110. Independently
    # reject all-zero /64 interface identifiers (potential subnet-router
    # anycast) rather than treating them as ordinary reviewed hosts.
    if number >> 121 == 0b1111110 and (number & ((1 << 64) - 1)) != 0:
        return "REVIEW_ONLY", "PRIVATE_USE"
    return "HOLD", "UNTRUSTED"


class IntegerOracleLabReviewTests(TestCase):
    def assert_oracle(self, value: str, expectation):
        receipt = review_lab_literal(value)
        self.assertEqual((receipt.status, receipt.classification), expectation, value)
        for flag in _FALSE_FLAGS:
            self.assertIs(getattr(receipt, flag), False, (value, flag))

    def test_deterministic_ipv4_boundary_and_weighted_samples(self):
        rng = random.Random(1424)
        pools = (
            (0, 0xFFFFFFFF),
            (0x7F000000, 0x7FFFFFFF),
            (0x0A000000, 0x0AFFFFFF),
            (0xAC100000, 0xAC1FFFFF),
            (0xC0A80000, 0xC0A8FFFF),
            (0xA9FE0000, 0xA9FEFFFF),  # link-local is not trusted private use
            (0xC0000200, 0xC00002FF),  # TEST-NET-1 never lab
            (0xC6120000, 0xC613FFFF),  # benchmark network never lab
        )
        for start, end in pools:
            edge_candidates = {
                max(0, start - 1), start, min(0xFFFFFFFF, start + 1),
                max(0, end - 1), end, min(0xFFFFFFFF, end + 1),
            }
            edge_candidates.update(rng.randint(start, end) for _ in range(96))
            for value in sorted(edge_candidates):
                literal = str(IPv4Address(value))
                with self.subTest(ip=literal):
                    self.assert_oracle(literal, _expect_ipv4(value))

    def test_deterministic_ipv6_ula_and_special_space_samples(self):
        rng = random.Random(1425)
        ula_start = 0xFC << 120
        ula_end = (0xFE << 120) - 1
        pools = (
            (0, (1 << 128) - 1),
            (ula_start, ula_end),
            (0xFE80 << 112, (0xFEBF << 112) | ((1 << 112) - 1)),
            (0x20010DB8 << 96, (0x20010DB8 << 96) | ((1 << 96) - 1)),
            (0xFF << 120, (1 << 128) - 1),
        )
        for start, end in pools:
            candidates = {
                max(0, start - 1), start, min((1 << 128) - 1, start + 1),
                max(0, end - 1), end, min((1 << 128) - 1, end + 1),
            }
            candidates.update(rng.randint(start, end) for _ in range(96))
            for value in sorted(candidates):
                literal = str(IPv6Address(value))
                with self.subTest(ip=literal):
                    self.assert_oracle(literal, _expect_ipv6(value))


if __name__ == "__main__":
    main()
