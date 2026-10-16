"""Original-producer coherence regression for untrusted fake scope display (1495).

These are real decoder and subprocess tests, never a real authorization check.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lightup.synthetic_scope_notice_consumer_1495 import decode_fictional_notice_for_display

DATA = {
    "review_at": "2026-10-16T12:00:00Z",
    "proposals": [
        {"asset": "alpha.example.test", "capability": "inventory_read", "risk": 4,
         "valid_from": "2026-10-16T11:00:00Z", "valid_until": "2026-10-16T13:00:00Z"},
        {"asset": "zeta.example.test", "capability": "metadata_read", "risk": 2,
         "valid_from": "2026-10-16T11:10:00Z", "valid_until": "2026-10-16T12:40:00Z"},
    ],
}


def origin(lang="en", data=None):
    command = [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495",
               "--synthetic-only", "--lang", lang, "--format", "json"]
    completed = subprocess.run(command, cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        input=json.dumps(DATA if data is None else data).encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False)
    assert completed.returncode == 2, completed.stderr
    return json.loads(completed.stdout)


def encoded(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True).encode()


class ExactOriginalScopeNotice1495(unittest.TestCase):
    def accept(self, obj):
        view = decode_fictional_notice_for_display(encoded(obj))
        self.assertIsNotNone(view)
        self.assertEqual(view.status, "REVIEW_ONLY")
        self.assertIs(view.authorized, False)
        self.assertIs(view.consent_verified, False)
        self.assertIs(view.dispatch_allowed, False)
        self.assertIs(view.release_allowed, False)

    def denied(self, obj):
        self.assertIsNone(decode_fictional_notice_for_display(encoded(obj)))

    def test_real_two_rows_english_exactly_accepted(self):
        self.accept(origin())

    def test_real_two_rows_dutch_exactly_accepted(self):
        self.accept(origin("nl"))

    def test_low_risk_report_still_valid_when_produced_normally(self):
        data = copy.deepcopy(DATA)
        for p in data["proposals"]:
            p["risk"] = 1
        self.accept(origin(data=data))

    def test_one_valid_fictional_record_from_original_is_accepted(self):
        data = copy.deepcopy(DATA)
        data["proposals"].pop()
        self.accept(origin(data=data))

    def test_unrelated_customer_domain_in_text_is_rejected(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "alpha.example.test", "alpha.customer.com"
        )
        self.denied(obj)

    def test_nonfictional_url_disguised_as_asset_is_rejected(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "alpha.example.test", "https://alpha.example.test"
        )
        self.denied(obj)

    def test_asset_with_punycode_prefix_is_rejected(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "alpha.example.test", "xn--fake.example.test"
        )
        self.denied(obj)

    def test_capability_invalid_unicode_is_rejected(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "inventory_read", "inventóry_read"
        )
        self.denied(obj)

    def test_capability_name_swap_is_consistent_but_not_authenticated(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "inventory_read", "inventory_write"
        )
        # Internally self-consistent fictional text is still never trusted:
        # the decoder may show it, but has absolutely no authority flags.
        self.accept(obj)

    def test_risk_number_mismatch_to_elevated_flag_is_rejected(self):
        obj = origin()
        obj["elevated_risk"] = False
        self.denied(obj)

    def test_risk_score_changed_but_stepup_text_missing_is_rejected(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "4/5", "2/5"
        )
        self.denied(obj)

    def test_invalid_severity_six_is_rejected(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "4/5", "6/5"
        )
        self.denied(obj)

    def test_injected_row_is_rejected(self):
        obj = origin()
        obj["notice"] += "\n- extra.example.test | scan | 1/5 | 2026-10-16T11:00:00Z | 2026-10-16T13:00:00Z"
        self.denied(obj)

    def test_duplicate_row_is_rejected(self):
        obj = origin()
        rows = obj["notice"].splitlines()
        rows.insert(7, rows[6])
        obj["notice"] = "\n".join(rows)
        obj["reviewed"] = 3
        self.denied(obj)

    def test_reversed_row_order_is_rejected(self):
        obj = origin()
        rows = obj["notice"].splitlines()
        rows[6], rows[7] = rows[7], rows[6]
        obj["notice"] = "\n".join(rows)
        self.denied(obj)

    def test_expired_window_is_rejected(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "2026-10-16T13:00:00Z", "2026-10-16T11:20:00Z"
        )
        self.denied(obj)

    def test_review_instant_outside_validity_is_rejected(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "Review timestamp (UTC): 2026-10-16T12:00:00Z",
            "Review timestamp (UTC): 2026-10-16T17:00:00Z",
        )
        self.denied(obj)

    def test_timestamp_offset_and_subseconds_are_rejected(self):
        obj = origin()
        for stamp in ("2026-10-16T12:00:00+00:00",
                      "2026-10-16T12:00:00.000Z",
                      "2026-10-16T12:00Z"):
            with self.subTest(stamp=stamp):
                candidate = dict(obj)
                candidate["notice"] = obj["notice"].replace(
                    "2026-10-16T12:00:00Z", stamp,
                )
                self.denied(candidate)

    def test_max_ninety_day_window_enforced(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "2026-10-16T11:00:00Z", "2026-06-01T11:00:00Z",
        )
        self.denied(obj)

    def test_malformed_section_title_is_rejected(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "Proposed asset | capability | risk", "Authorized asset | capability | risk"
        )
        self.denied(obj)

    def test_fake_consent_sentence_is_rejected(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "No client consent, operator identity, approval or execution authority verified.",
            "Client consent, operator identity and authority verified.",
        )
        self.denied(obj)

    def test_removed_final_no_scan_warning_is_rejected(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(
            "No real assets, scans, tools, data collection or production changes permitted.",
            "Live scanners can be started.",
        )
        self.denied(obj)

    def test_wrong_language_tail_is_rejected(self):
        obj = origin("nl")
        obj["notice"] = obj["notice"].replace(
            "Dit is GEEN toestemming, grant, uitvoeropdracht of productie-goedkeuring.",
            "This is NOT a grant, consent record, dispatch ticket or release approval.",
        )
        self.denied(obj)

    def test_missing_separator_is_rejected(self):
        obj = origin()
        obj["notice"] = obj["notice"].replace(" | inventory_read |", " inventory_read |")
        self.denied(obj)

    def test_escaped_markup_is_rejected_not_rendered_as_trusted_preview(self):
        obj = origin()
        obj["notice"] += "\n<script>alert('go')</script>"
        self.denied(obj)


if __name__ == "__main__":
    unittest.main()
