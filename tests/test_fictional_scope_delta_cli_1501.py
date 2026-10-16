"""Actual offline subprocess contract for the fictional, NEVER-authorizing CLI."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from unittest import TestCase
from unittest.mock import patch
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "FICTIONAL-SCOPE-HISTORY-1501-V1"
MODULE = "lightup.fictional_scope_delta_cli_1501"


def snapshot(**changes):
    item = {
        "assets": ["alpha.example.test", "beta.example.test"],
        "capabilities": ["headers_view", "metadata_view"],
        "exclusions": [],
        "risk": 3,
        "valid_from": "2026-11-01T10:00:00Z",
        "valid_until": "2026-11-03T10:00:00Z",
    }
    item.update(changes)
    return item


def wire(history, **extras):
    data = {"contract": CONTRACT, "history": history}
    data.update(extras)
    return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def launch(raw: bytes, *args: str):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        (sys.executable, "-m", MODULE, *args),
        input=raw, capture_output=True, timeout=15, env=env, cwd=ROOT, check=False
    )


class SyntheticScopeDeltaCLITests(TestCase):
    def assert_wire(self, result, *, status, code):
        self.assertEqual(result.returncode, code, result.stderr[:300])
        self.assertEqual(result.stderr, b"")
        self.assertTrue(result.stdout.endswith(b"\n"))
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], status)
        self.assertEqual(report["contract"], CONTRACT)
        self.assertEqual(
            result.stdout,
            json.dumps(report, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        )
        self.assertEqual(set(report), {
            "contract", "status", "transition_count", "first_held_step",
            "held_steps", "held_step_dimensions",
            "expanded_dimensions", "narrowed_dimensions",
            "authorized", "consent_verified", "dispatch_allowed", "release_allowed",
        })
        for flag in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(report[flag], False)
        return report

    def test_equal_fictional_snapshots_report_review_only_exit_two(self):
        item = snapshot()
        result = launch(wire([item, item]), "--offline-review-only")
        report = self.assert_wire(result, status="REVIEW_ONLY", code=2)
        self.assertEqual(report["transition_count"], 1)
        self.assertEqual(report["expanded_dimensions"], [])

    def test_narrowed_fictional_snapshot_remains_unapproved(self):
        result = launch(wire([snapshot(), snapshot(risk=2)]), "--offline-review-only")
        report = self.assert_wire(result, status="REVIEW_ONLY", code=2)
        self.assertEqual(report["narrowed_dimensions"], ["risk"])

    def test_intermediate_widening_rolls_back_but_holds(self):
        first = snapshot()
        wide = snapshot(risk=5)
        report = self.assert_wire(
            launch(wire([first, wide, first]), "--offline-review-only"),
            status="HOLD", code=3,
        )
        self.assertEqual(report["first_held_step"], 1)
        self.assertEqual(report["held_steps"], [1])
        self.assertEqual(report["held_step_dimensions"], [["risk"]])
        self.assertEqual(report["expanded_dimensions"], ["risk"])
        self.assertEqual(report["narrowed_dimensions"], [])

    def test_cli_lists_every_widening_transition_without_asset_values(self):
        original = snapshot()
        risk = snapshot(risk=5)
        asset = snapshot(assets=[
            "alpha.example.test", "beta.example.test", "gamma.example.test",
        ])
        records = [original, risk, original, asset, snapshot(
            assets=asset["assets"], risk=4,
        )]
        report = self.assert_wire(
            launch(wire(records), "--offline-review-only"), status="HOLD", code=3,
        )
        self.assertEqual(report["held_steps"], [1, 3, 4])
        self.assertEqual(report["held_step_dimensions"], [["risk"], ["assets"], ["risk"]])
        self.assertEqual(report["first_held_step"], 1)
        self.assertEqual(report["expanded_dimensions"], ["assets", "risk"])
        self.assertNotIn("gamma.example.test", json.dumps(report))

    def test_cli_invalid_late_record_discards_earlier_transition_metadata(self):
        records = [
            snapshot(), snapshot(risk=5),
            snapshot(assets=["private.real.invalid"]),
        ]
        result = launch(wire(records), "--offline-review-only")
        report = self.assert_wire(result, status="HOLD", code=3)
        self.assertEqual(report["held_steps"], [])
        self.assertEqual(report["held_step_dimensions"], [])
        self.assertEqual(report["expanded_dimensions"], [])
        self.assertIsNone(report["first_held_step"])
        self.assertEqual(report["transition_count"], 0)
        self.assertNotIn(b"private.real.invalid", result.stdout)

    def test_cli_all_15_boundaries_report_exact_bounded_held_steps(self):
        records = [snapshot(risk=3 if i % 2 == 0 else 5) for i in range(16)]
        report = self.assert_wire(
            launch(wire(records), "--offline-review-only"), status="HOLD", code=3,
        )
        self.assertEqual(report["transition_count"], 15)
        self.assertEqual(report["held_steps"], list(range(1, 16, 2)))
        self.assertEqual(report["held_step_dimensions"], [["risk"]] * 8)

    def test_cli_categories_map_to_each_widening_step_without_values(self):
        start = snapshot()
        added = snapshot(assets=[
            "alpha.example.test", "beta.example.test", "gamma.example.test",
        ])
        higher = snapshot(assets=added["assets"], risk=4)
        earlier = snapshot(assets=added["assets"], risk=4,
                           valid_from="2026-11-01T09:59:59Z")
        result = launch(wire([start, added, higher, earlier]),
                        "--offline-review-only")
        report = self.assert_wire(result, status="HOLD", code=3)
        self.assertEqual(report["held_steps"], [1, 2, 3])
        self.assertEqual(
            report["held_step_dimensions"],
            [["assets"], ["risk"], ["valid_from"]],
        )
        self.assertNotIn(b"gamma.example.test", result.stdout)

    def test_real_host_and_sensitive_fields_are_zero_echo_hold(self):
        bad = snapshot(assets=["real.corp.example", "beta.example.test"])
        for content in (
            wire([snapshot(), bad]),
            wire([snapshot(), snapshot()], credential="do-not-echo-SECRET"),
            wire([snapshot(), snapshot()], authorized=True),
            wire([snapshot(), snapshot()], consent_verified=True),
        ):
            with self.subTest(payload=content[:50]):
                result = launch(content, "--offline-review-only")
                report = self.assert_wire(result, status="HOLD", code=3)
                self.assertEqual(report["expanded_dimensions"], [])
                self.assertEqual(report["transition_count"], 0)
                self.assertNotIn(b"real.corp.example", result.stdout)
                self.assertNotIn(b"do-not-echo-SECRET", result.stdout)

    def test_noncanonical_json_duplicate_keys_and_nan_fail_closed(self):
        valid = wire([snapshot(), snapshot()])
        variations = (
            b'{"contract":"' + CONTRACT.encode() + b'","contract":"FAKE","history":[]}',
            valid.replace(b'":', b'" :', 1),
            valid.replace(b'"risk":3', b'"risk":3.0', 1),
            valid.replace(b'"risk":3', b'"risk":NaN', 1),
            valid.replace(b'"risk":3', b'"risk":true', 1),
            valid.replace(b'"alpha.example.test"', b'"\\u0061lpha.example.test"', 1),
            valid + b"\n\n",
            b"", b"[", b"null", b"{}",
        )
        for data in variations:
            with self.subTest(data=data[:60]):
                self.assert_wire(launch(data, "--offline-review-only"), status="HOLD", code=3)

    def test_allow_only_one_final_lf(self):
        valid = wire([snapshot(), snapshot()])
        self.assert_wire(launch(valid + b"\n", "--offline-review-only"), status="REVIEW_ONLY", code=2)
        self.assert_wire(launch(b"\n" + valid, "--offline-review-only"), status="HOLD", code=3)

    def test_invalid_utc_strings_never_normalize_into_permission(self):
        for date in (
            "2026-11-01T10:00:00+00:00", "2026-11-01T10:00:00.000Z",
            "2026-11-01T11:00:00+01:00", "2026-2-01T10:00:00Z",
            "2026-11-01T10:00:60Z", "2026-02-30T10:00:00Z",
        ):
            with self.subTest(date=date):
                raw = wire([snapshot(), snapshot(valid_from=date)])
                self.assert_wire(launch(raw, "--offline-review-only"), status="HOLD", code=3)

    def test_excessive_input_is_bounded_without_echo(self):
        data = b"SECRET" * 10000
        result = launch(data, "--offline-review-only")
        self.assert_wire(result, status="HOLD", code=3)
        self.assertNotIn(b"SECRET", result.stdout)

    def test_missing_opt_in_and_unsupported_args_never_exit_zero(self):
        data = wire([snapshot(), snapshot()])
        for args in ((), ("--help",), ("--offline-review-only", "--extra")):
            with self.subTest(args=args):
                self.assert_wire(launch(data, *args), status="HOLD", code=3)

    def test_repeated_inert_wire_output_is_identical(self):
        raw = wire([snapshot(), snapshot()])
        a = launch(raw, "--offline-review-only")
        b = launch(raw, "--offline-review-only")
        self.assertEqual(a.stdout, b.stdout)
        self.assert_wire(a, status="REVIEW_ONLY", code=2)
        self.assert_wire(b, status="REVIEW_ONLY", code=2)

    def test_utc_parser_never_uses_locale_or_strptime_cache(self):
        from lightup.fictional_scope_delta_cli_1501 import _utc
        import locale

        with patch.object(locale, "getlocale", side_effect=AssertionError("locale lookup")):
            parsed = _utc("2028-02-29T23:59:59Z")
        self.assertEqual(parsed, datetime(2028, 2, 29, 23, 59, 59, tzinfo=timezone.utc))
        self.assertIs(parsed.tzinfo, timezone.utc)

    def test_utc_parser_rejects_invalid_calendar_and_clock_values(self):
        from lightup.fictional_scope_delta_cli_1501 import _utc

        invalid = (
            "2027-02-29T10:00:00Z", "2100-02-29T10:00:00Z",
            "2026-00-01T10:00:00Z", "2026-13-01T10:00:00Z",
            "2026-11-00T10:00:00Z", "2026-11-31T10:00:00Z",
            "2026-11-01T24:00:00Z", "2026-11-01T10:60:00Z",
            "2026-11-01T10:00:60Z", "2026-11-01T10:00:00z",
            "2026-11-01t10:00:00Z", "2026-11-01T10:00:00+00:00",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                _utc(value)
