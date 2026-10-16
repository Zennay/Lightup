"""Adversarial caller-owned data mutation evidence for fictional HTML #1495."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.synthetic_scope_notice_1495 import ScopeProposal, render_scope_notice
from lightup.synthetic_scope_notice_html_1495 import render_synthetic_scope_html

AT = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)


def proposal(asset="desk.example.test", capability="inventory_read", risk=2):
    return ScopeProposal(asset, capability, risk, AT-timedelta(hours=1), AT+timedelta(hours=1))


class FrozenCallerSnapshot1495(unittest.TestCase):
    def test_real_frozen_input_is_copied_before_review(self):
        original = proposal()
        observed = []

        def inspect(snapshot, **kw):
            self.assertIsNot(snapshot[0], original)
            self.assertEqual(snapshot[0], original)
            observed.append(snapshot)
            return render_scope_notice(snapshot, **kw)

        with patch("lightup.synthetic_scope_notice_html_1495.render_scope_notice",
                   side_effect=inspect):
            page = render_synthetic_scope_html((original,), review_at=AT)
        self.assertEqual(len(observed), 1)
        self.assertIn("desk.example.test", page)
        self.assertIn("NOT AUTHORIZED", page)

    def test_mutating_original_asset_during_review_cannot_change_display(self):
        original = proposal()
        def adversarial_review(snapshot, **kw):
            object.__setattr__(original, "asset", "sensitive-customer.example.com")
            return render_scope_notice(snapshot, **kw)

        with patch("lightup.synthetic_scope_notice_html_1495.render_scope_notice",
                   side_effect=adversarial_review):
            page = render_synthetic_scope_html((original,), review_at=AT)
        self.assertIn("desk.example.test", page)
        self.assertNotIn("sensitive-customer.example.com", page)
        self.assertIn("REVIEW_ONLY", page)

    def test_mutating_original_risk_cannot_turn_review_into_misleading_high_risk(self):
        original = proposal(risk=2)
        def adversarial_review(snapshot, **kw):
            object.__setattr__(original, "risk", 5)
            return render_scope_notice(snapshot, **kw)

        with patch("lightup.synthetic_scope_notice_html_1495.render_scope_notice",
                   side_effect=adversarial_review):
            page = render_synthetic_scope_html((original,), review_at=AT)
        self.assertIn("2/5", page)
        self.assertNotIn("5/5", page)
        self.assertIn("Elevated risks</span><strong>0</strong>", page)

    def test_mutating_original_expiry_cannot_postdate_reviewed_window(self):
        original = proposal()
        def adversarial_review(snapshot, **kw):
            object.__setattr__(original, "valid_until", AT+timedelta(days=800))
            return render_scope_notice(snapshot, **kw)

        with patch("lightup.synthetic_scope_notice_html_1495.render_scope_notice",
                   side_effect=adversarial_review):
            page = render_synthetic_scope_html((original,), review_at=AT)
        self.assertIn("2026-10-16T13:00:00Z", page)
        self.assertNotIn("2028", page)
        self.assertIn("NOT AUTHORIZED", page)

    def test_deleting_original_slot_before_snapshot_holds_atomically(self):
        original = proposal()
        object.__delattr__(original, "asset")
        page = render_synthetic_scope_html((original,), review_at=AT)
        self.assertIn("HOLD", page)
        self.assertNotIn("desk.example.test", page)
        self.assertNotIn("<table>", page)

    def test_invalid_exact_type_rejects_before_copy_without_field_access(self):
        class Malicious:
            def __getattribute__(self, key):
                raise AssertionError("must not read noncanonical object")

        page = render_synthetic_scope_html((Malicious(),), review_at=AT)
        self.assertIn("HOLD", page)
        self.assertNotIn("<table>", page)

    def test_mutable_list_is_rejected_not_converted(self):
        original = [proposal()]
        page = render_synthetic_scope_html(original, review_at=AT)
        self.assertIn("HOLD", page)
        self.assertNotIn("desk.example.test", page)

    def test_malformed_second_record_does_not_echo_valid_first(self):
        page = render_synthetic_scope_html(
            (proposal(), proposal("a-client.example.com")), review_at=AT,
        )
        self.assertIn("HOLD", page)
        self.assertNotIn("desk.example.test", page)
        self.assertNotIn("a-client.example.com", page)

    def test_snapshot_stability_for_two_fictional_scopes_and_permutations(self):
        records = (proposal("zeta.example.test"), proposal("alpha.example.test", risk=4))
        a = render_synthetic_scope_html(records, review_at=AT)
        b = render_synthetic_scope_html(tuple(reversed(records)), review_at=AT)
        self.assertEqual(a, b)
        self.assertIn("Elevated risks</span><strong>1</strong>", a)

    def test_invalid_language_cannot_inherit_prior_valid_preview(self):
        item = proposal()
        valid = render_synthetic_scope_html((item,), review_at=AT, language="nl")
        hold = render_synthetic_scope_html((item,), review_at=AT, language="NL")
        self.assertIn("desk.example.test", valid)
        self.assertIn("HOLD", hold)
        self.assertNotIn("desk.example.test", hold)


if __name__ == "__main__":
    unittest.main()
