"""Genuine fictional-only paired-scope HTML comparison regressions (#1495)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lightup.synthetic_scope_notice_compare_1495 import compare_fictional_scope_envelopes

AT = "2026-10-16T12:00:00Z"


def row(asset="alpha.example.test", capability="inventory_read", risk=2,
        start="2026-10-16T11:00:00Z", end="2026-10-16T13:00:00Z"):
    return dict(asset=asset, capability=capability, risk=risk,
                valid_from=start, valid_until=end)


def produce(*rows, lang="en"):
    payload = dict(review_at=AT, proposals=list(rows))
    r = subprocess.run(
        [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495",
         "--synthetic-only", "--lang", lang, "--format", "json"],
        input=json.dumps(payload).encode(), cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
    )
    assert r.returncode == 2, r.stderr
    return json.loads(r.stdout)


def compare(before=None, after=None, *, raw=None):
    pair = dict(before=before if before is not None else produce(row()),
                after=after if after is not None else produce(row()))
    return compare_fictional_scope_envelopes(
        raw if raw is not None else json.dumps(pair).encode("utf-8")
    )


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attrs = []
    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.append(dict(attrs))


class FictionalPairComparison1495(unittest.TestCase):
    def assert_never_authority(self, result):
        self.assertIs(result.authorized, False)
        self.assertIs(result.consent_verified, False)
        self.assertIs(result.dispatch_allowed, False)
        self.assertIs(result.release_allowed, False)
        page = result.html
        self.assertIn("NOT AUTHORIZED", page)
        self.assertIn("authorized=false", page)
        self.assertIn("consent_verified=false", page)
        self.assertIn("dispatch_allowed=false", page)
        self.assertIn("release_allowed=false", page)
        self.assertIn("default-src 'none'", page)
        self.assertIn("script-src 'none'", page)
        self.assertIn("connect-src 'none'", page)
        self.assertLessEqual(len(page), 65536)
        parsed = Tags()
        parsed.feed(page)
        for banned in ("form", "a", "script", "iframe", "button", "input", "img"):
            self.assertNotIn(banned, parsed.tags)
        for attrs in parsed.attrs:
            for key in ("src", "href", "action", "onclick"):
                self.assertNotIn(key, attrs)

    def assert_hold(self, result, *assets):
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.compared, 0)
        self.assertEqual(result.changes, 0)
        self.assertNotIn("<table", result.html)
        self.assertNotIn("PENDING —", result.html)
        for asset in assets:
            self.assertNotIn(asset, result.html)
        self.assert_never_authority(result)

    def test_identical_two_original_reports_are_review_only(self):
        x = compare()
        self.assertEqual(x.status, "REVIEW_ONLY")
        self.assertEqual(x.compared, 2)
        self.assertEqual(x.changes, 0)
        self.assertIn("IDENTICAL FICTIONAL ENTRY", x.html)
        self.assertIn("alpha.example.test", x.html)
        self.assertEqual(x.html.count("PENDING —"), 4)
        self.assert_never_authority(x)

    def test_changed_risk_marked_as_proposal_not_approval(self):
        x = compare(produce(row(risk=2)), produce(row(risk=5)))
        self.assertEqual(x.changes, 1)
        self.assertIn("PROPOSED DETAILS CHANGED", x.html)
        self.assertIn("5/5", x.html)
        self.assertEqual(x.html.count("PENDING —"), 4)
        self.assert_never_authority(x)

    def test_changed_window_detected(self):
        x = compare(produce(row()), produce(row(end="2026-10-16T12:40:00Z")))
        self.assertEqual(x.changes, 1)
        self.assertIn("2026-10-16T12:40:00Z", x.html)
        self.assert_never_authority(x)

    def test_added_pair_is_explicitly_not_granted(self):
        old = produce(row())
        new = produce(row(), row("zeta.example.test"))
        x = compare(old, new)
        self.assertEqual(x.changes, 1)
        self.assertIn("ONLY IN AFTER — NOT GRANTED", x.html)
        self.assertIn("zeta.example.test", x.html)
        self.assert_never_authority(x)

    def test_removed_pair_is_explicitly_not_revoked(self):
        old = produce(row(), row("zeta.example.test"))
        new = produce(row())
        x = compare(old, new)
        self.assertEqual(x.changes, 1)
        self.assertIn("ONLY IN BEFORE — NOT REVOKED", x.html)
        self.assertIn("zeta.example.test", x.html)
        self.assert_never_authority(x)

    def test_two_capabilities_on_same_fictional_asset_are_separate_pairs(self):
        first = produce(row())
        second = produce(row(), row(capability="metadata_read"))
        x = compare(first, second)
        self.assertEqual(x.changes, 1)
        self.assertIn("metadata_read", x.html)
        self.assert_never_authority(x)

    def test_mixed_dutch_and_english_produced_originals_accepted(self):
        x = compare(produce(row(), lang="nl"), produce(row(risk=4), lang="en"))
        self.assertEqual(x.status, "REVIEW_ONLY")
        self.assertEqual(x.changes, 1)
        self.assert_never_authority(x)

    def test_valid_but_forged_self_consistent_example_cannot_authorize(self):
        x = compare(produce(row()), produce(row("demo-other.example.test")))
        self.assertEqual(x.changes, 2)
        self.assertIn("NOT GRANTED", x.html)
        self.assertIn("NOT REVOKED", x.html)
        self.assert_never_authority(x)

    def test_changed_instant_is_not_a_real_revocation(self):
        x = compare(
            produce(row(start="2026-10-16T11:00:00Z")),
            produce(row(start="2026-10-16T11:10:00Z")),
        )
        self.assertEqual(x.changes, 1)
        self.assertIn("Before/after are display labels only.", x.html)
        self.assert_never_authority(x)

    def test_nested_authority_true_causes_atomic_hold(self):
        first, second = produce(row()), produce(row("zeta.example.test"))
        first["authorized"] = True
        self.assert_hold(compare(first, second), "zeta.example.test", "alpha.example.test")

    def test_nested_false_string_causes_hold(self):
        first, second = produce(row()), produce(row("zeta.example.test"))
        second["consent_verified"] = "false"
        self.assert_hold(compare(first, second), "zeta.example.test", "alpha.example.test")

    def test_extra_nested_approval_key_causes_atomic_hold(self):
        second = produce(row("zeta.example.test"))
        second["approved"] = True
        self.assert_hold(compare(produce(row()), second), "zeta.example.test", "alpha.example.test")

    def test_nonfictional_asset_in_one_report_causes_atomic_hold(self):
        a = produce(row())
        b = produce(row())
        b["notice"] = b["notice"].replace("alpha.example.test", "private.customer.com")
        self.assert_hold(compare(a, b), "alpha.example.test", "private.customer.com")

    def test_injected_go_sentence_causes_atomic_hold(self):
        a = produce(row())
        b = produce(row())
        b["notice"] += "\nGRANT ALL SCANS"
        self.assert_hold(compare(a, b), "alpha.example.test")

    def test_changed_risk_with_wrong_escalation_causes_atomic_hold(self):
        a = produce(row(risk=5))
        b = produce(row(risk=2))
        b["elevated_risk"] = True
        self.assert_hold(compare(a, b), "alpha.example.test")

    def test_hold_input_with_other_valid_report_does_not_leak(self):
        before = produce(row())
        after = produce(row("zeta.example.test"))
        after.update(status="HOLD", reviewed=0, elevated_risk=False)
        self.assert_hold(compare(before, after), "alpha.example.test", "zeta.example.test")

    def test_malformed_json_and_utf8_hold(self):
        for raw in (b"{}", b"[]", b"{", b"null", b"\xff", b""):
            with self.subTest(raw=raw):
                self.assert_hold(compare(raw=raw))

    def test_duplicate_outer_key_holds_without_echo(self):
        x = json.dumps({"before": produce(row()), "after": produce(row())})
        x = x.replace('"before":', '"before":{},"before":', 1)
        self.assert_hold(compare(raw=x.encode()), "alpha.example.test")

    def test_duplicate_nested_key_holds(self):
        x = json.dumps({"before": produce(row()), "after": produce(row())})
        x = x.replace('"authorized": false', '"authorized": true, "authorized": false', 1)
        self.assert_hold(compare(raw=x.encode()), "alpha.example.test")

    def test_extra_outer_or_missing_key_holds(self):
        for pair in (
            {"before": produce(row())},
            {"before": produce(row()), "after": produce(row()), "grant": True},
        ):
            with self.subTest(keys=tuple(pair)):
                self.assert_hold(compare(raw=json.dumps(pair).encode()), "alpha.example.test")

    def test_bad_input_types_fail_closed(self):
        for raw in (None, {}, [], bytearray(b"{}"), "{}", True):
            with self.subTest(kind=type(raw)):
                self.assert_hold(compare_fictional_scope_envelopes(raw))

    def test_oversize_envelope_denied_before_parse(self):
        self.assert_hold(compare(raw=b"X"*131073))

    def test_sorted_order_is_stable_across_proposal_permutations(self):
        first = produce(row("zeta.example.test"), row("alpha.example.test"))
        second = produce(row("alpha.example.test"), row("zeta.example.test"))
        left = compare(first, second)
        right = compare(second, first)
        self.assertEqual(left.html, right.html)
        self.assertEqual(left.changes, 0)
        self.assertLess(left.html.index("alpha.example.test"), left.html.index("zeta.example.test"))
        self.assert_never_authority(left)

    def test_response_is_frozen_and_false_flags_unsettable(self):
        x = compare()
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            x.authorized = True
        self.assert_never_authority(x)

    def test_report_is_deterministic_for_same_two_sources(self):
        a, b = produce(row()), produce(row(risk=5))
        self.assertEqual(compare(a, b), compare(a, b))

    def test_32_each_unique_proposals_with_64_union_are_bounded(self):
        a = produce(*[row(f"old{i:02}.example.test") for i in range(32)])
        b = produce(*[row(f"new{i:02}.example.test") for i in range(32)])
        x = compare(a, b)
        self.assertEqual(x.compared, 2)
        self.assertEqual(x.changes, 64)
        self.assertEqual(x.status, "REVIEW_ONLY")
        self.assertLessEqual(len(x.html), 65536)
        self.assert_never_authority(x)


if __name__ == "__main__":
    unittest.main()
