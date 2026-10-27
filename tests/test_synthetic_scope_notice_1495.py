"""Offline, original-path-only regression suite for synthetic notice issue #1495."""
from __future__ import annotations

import builtins
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import os
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.synthetic_scope_notice_1495 import (
    ScopeNotice, ScopeProposal, render_scope_notice,
)

AT = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)


def proposal(
    asset: str = "desk.example.test",
    capability: str = "inventory_read",
    risk: int = 2,
    valid_from: datetime = AT - timedelta(hours=1),
    valid_until: datetime = AT + timedelta(hours=1),
) -> ScopeProposal:
    return ScopeProposal(asset, capability, risk, valid_from, valid_until)


def review(*items: ScopeProposal, at: datetime = AT) -> ScopeNotice:
    return render_scope_notice(tuple(items), review_at=at)


class SyntheticScopeNotice1495(unittest.TestCase):
    def assert_held(self, result: ScopeNotice) -> None:
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.reviewed, 0)
        self.assertFalse(result.elevated_risk)
        self.assertIn("NOT AUTHORIZED", result.text)
        self.assertLessEqual(len(result.text), 8192)
        self.assert_no_authority(result)

    def assert_no_authority(self, result: ScopeNotice) -> None:
        self.assertIs(result.authorized, False)
        self.assertIs(result.consent_verified, False)
        self.assertIs(result.dispatch_allowed, False)
        self.assertIs(result.release_allowed, False)

    def test_canonical_preview_human_readable_and_never_permission(self):
        result = review(proposal())
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.reviewed, 1)
        self.assertFalse(result.elevated_risk)
        self.assertIn("desk.example.test | inventory_read | 2/5", result.text)
        self.assertIn("No client consent", result.text)
        self.assertIn("No real assets, scans", result.text)
        self.assert_no_authority(result)

    def test_same_asset_different_capabilities_are_different_proposals(self):
        r = review(proposal(), proposal(capability="meta_read"))
        self.assertEqual(r.reviewed, 2)
        self.assertEqual(r.status, "REVIEW_ONLY")
        self.assert_no_authority(r)

    def test_permutation_invariance_and_immutable_input(self):
        values = (
            proposal("zeta.example.test", "watch_only", 1),
            proposal("alpha.example.test", "inventory_read", 4),
        )
        snapshot = repr(values)
        a, b = review(*values), review(*reversed(values))
        self.assertEqual(a, b)
        self.assertEqual(repr(values), snapshot)
        self.assertTrue(a.elevated_risk)
        self.assertLess(a.text.index("alpha.example.test"), a.text.index("zeta.example.test"))
        self.assertIn("step-up", a.text)
        self.assert_no_authority(a)

    def test_risk_four_and_five_require_stepup_not_permission(self):
        for score in (4, 5):
            with self.subTest(score=score):
                out = review(proposal(risk=score))
                self.assertEqual(out.status, "REVIEW_ONLY")
                self.assertTrue(out.elevated_risk)
                self.assertIn("independent step-up", out.text)
                self.assert_no_authority(out)

    def test_unacceptable_risk_types_and_range_hold(self):
        for risk in (True, False, 0, 6, 2.0, "3", None, -1):
            with self.subTest(risk=risk):
                self.assert_held(review(proposal(risk=risk)))

    def test_empty_wrong_container_and_oversized_cohort_hold(self):
        self.assert_held(render_scope_notice((), review_at=AT))
        self.assert_held(render_scope_notice([proposal()], review_at=AT))
        self.assert_held(render_scope_notice((proposal() for _ in range(1)), review_at=AT))
        many = tuple(proposal(f"host{i}.example.test") for i in range(33))
        self.assert_held(render_scope_notice(many, review_at=AT))

    def test_full_cohort_of_32_distinct_entries(self):
        samples = tuple(proposal(f"host{i:02d}.example.test") for i in range(32))
        out = render_scope_notice(samples, review_at=AT)
        self.assertEqual(out.status, "REVIEW_ONLY")
        self.assertEqual(out.reviewed, 32)
        self.assert_no_authority(out)

    def test_exact_dataclass_not_subclass_or_dynamic_objects(self):
        class Subclass(ScopeProposal):
            pass

        self.assert_held(review(Subclass(*tuple(vars_for(proposal())))))
        self.assert_held(render_scope_notice(({"asset": "desk.example.test"},), review_at=AT))
        self.assert_held(render_scope_notice((object(),), review_at=AT))

    def test_synthetic_only_no_customer_domain_or_numeric_ip(self):
        for value in ("company.com", "desk.company.com", "127.0.0.1", "localhost",
                      "example.test", "desk.example.test.evil.com", "DESK.example.test",
                      "desk.example.test.", "http://desk.example.test"):
            with self.subTest(asset=value):
                self.assert_held(review(proposal(asset=value)))

    def test_invalid_dns_identity_is_hold_without_echo(self):
        invalid = ("a-.example.test", "-a.example.test", "a..example.test",
                   "xn--fake.example.test", "café.example.test",
                   "a" * 64 + ".example.test", "a" * 239 + ".example.test",
                   "name\nSHOULD NOT LEAK.example.test", "a_b.example.test")
        for value in invalid:
            with self.subTest(value=value):
                out = review(proposal(asset=value))
                self.assert_held(out)
                self.assertNotIn(value, out.text)

    def test_normalized_aliases_never_silently_resolve(self):
        for value in ("A.example.test", "a..example.test", "a.example.test ",
                      "a.example.test\u200b", " a.example.test",
                      "a%2eexample.test", "a.example.test:443"):
            self.assert_held(review(proposal(asset=value)))

    def test_invalid_capability_or_type_fails_atomically(self):
        values = ("", "A", "UPPER", "tool/action", "json\nattack", "tool.edit",
                  "a" * 33, "x", "x\u00e9", 17, None)
        for value in values:
            with self.subTest(value=value):
                self.assert_held(review(proposal(capability=value)))

    def test_duplicate_pair_even_distinct_records_or_window_hold(self):
        p = proposal()
        later = replace(p, valid_from=AT-timedelta(minutes=2))
        self.assert_held(review(p, p))
        self.assert_held(review(p, later))
        self.assert_held(review(later, p))

    def test_duplicate_inside_otherwise_good_batch_is_atomic_hold(self):
        p = proposal()
        out = review(proposal("other.example.test"), p, p)
        self.assert_held(out)
        self.assertNotIn("other.example.test", out.text)

    def test_invalid_item_inside_batch_does_not_echo_other_entry(self):
        secret = "real-customer-secret.example.com"
        out = review(proposal("fine.example.test"), proposal(secret))
        self.assert_held(out)
        self.assertNotIn("fine.example.test", out.text)
        self.assertNotIn(secret, out.text)

    def test_naive_datetime_timezone_subclass_and_fractional_second_hold(self):
        for value in (AT.replace(tzinfo=None), AT.replace(microsecond=1),
                      AT.replace(tzinfo=timezone(timedelta(hours=1))),
                      AT.replace(fold=1), datetime(2101, 1, 1, tzinfo=timezone.utc)):
            with self.subTest(value=value):
                self.assert_held(render_scope_notice((proposal(),), review_at=value))
                self.assert_held(review(proposal(valid_from=value)))

    def test_expired_future_start_zero_or_oversized_duration_hold(self):
        cases = [
            proposal(valid_until=AT),
            proposal(valid_from=AT+timedelta(seconds=1)),
            proposal(valid_from=AT, valid_until=AT),
            proposal(valid_from=AT-timedelta(days=91)),
        ]
        for item in cases:
            with self.subTest(item=item):
                self.assert_held(review(item))

    def test_datetime_requires_explicit_utc(self):
        self.assert_held(render_scope_notice((proposal(),), review_at=None))
        self.assert_held(render_scope_notice((proposal(),), review_at="2026-10-16T12:00:00Z"))

    def test_type_confused_string_subclass_rejected(self):
        class MyStr(str):
            pass

        for item in (proposal(asset=MyStr("desk.example.test")),
                     proposal(capability=MyStr("inventory_read"))):
            self.assert_held(review(item))

    def test_subclassed_boolean_like_int_rejected(self):
        self.assert_held(review(proposal(risk=True)))

    def test_long_32_item_report_fails_closed_without_truncation(self):
        many = tuple(proposal(
            asset=f"{'a'*52}{i:02d}.{'b'*52}.{'c'*52}.example.test",
            capability=f"operation_{i:02d}_{'x'*15}",
        ) for i in range(32))
        self.assert_held(render_scope_notice(many, review_at=AT))

    def test_no_io_or_dispatch_even_when_valid(self):
        with patch.object(builtins, "open", side_effect=AssertionError("file I/O")), \
             patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("db")), \
             patch.object(subprocess, "run", side_effect=AssertionError("process")):
            success = review(proposal())
            denied = review(proposal(asset="real.example.com"))
        self.assertEqual(success.status, "REVIEW_ONLY")
        self.assert_held(denied)
        self.assert_no_authority(success)

    def test_result_and_proposal_are_frozen(self):
        r = review(proposal())
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            r.authorized = True
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            proposal().asset = "real.example.com"


def vars_for(item: ScopeProposal):
    return (item.asset, item.capability, item.risk, item.valid_from, item.valid_until)


if __name__ == "__main__":
    unittest.main()
