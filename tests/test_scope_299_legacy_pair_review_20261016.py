"""Contract for the #299 isolated, non-authorizing synthetic provenance pair mode.

All packet contents are fictional and the subprocess can only emit HOLD.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest


_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "scope_299_legacy_provenance_review.py"
_FLAGS = {
    "can_authorize", "can_dispatch", "can_deploy", "can_merge",
    "can_release", "can_scan",
}


def _packet(before=None, after=None):
    baseline = {"owner": "fictional-owner", "reference": "NOT-A-GRANT"}
    return json.dumps({
        "before": baseline if before is None else before,
        "after": baseline if after is None else after,
    }, separators=(",", ":")).encode("utf-8")


def _invoke(raw: bytes, *options: str):
    p = subprocess.run(
        [sys.executable, "-B", str(_SCRIPT), *options],
        cwd=_ROOT, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=10,
    )
    stdout = p.stdout.decode("utf-8")
    if len(stdout.splitlines()) != 1:
        raise AssertionError("must produce exactly one receipt line")
    data = json.loads(stdout)
    if type(data) is not dict:
        raise AssertionError("must produce a JSON object")
    return p.returncode, data, p.stderr.decode("utf-8")


class Scope299PairedOfflineAcceptance(unittest.TestCase):
    def assert_hold(self, result, reason, code=2):
        actual, receipt, stderr = result
        self.assertEqual(actual, code)
        self.assertEqual(stderr, "")
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["reason"], reason)
        self.assertEqual(set(receipt), {"status", "reason", *_FLAGS})
        for field in _FLAGS:
            self.assertIs(receipt[field], False)
        self.assertLess(len(json.dumps(receipt)), 240)

    def review(self, raw: bytes):
        return _invoke(raw, "--offline-synthetic-pair-only")

    def test_canonical_synthetic_pair_never_issues_permission(self):
        self.assert_hold(self.review(_packet()), "unchanged_shape_only")

    def test_changed_owner_is_diagnostic_not_reauthorization(self):
        self.assert_hold(self.review(_packet(
            after={"owner": "other-fictional-owner", "reference": "NOT-A-GRANT"}
        )), "provenance_changed")

    def test_changed_reference_is_diagnostic_not_reauthorization(self):
        self.assert_hold(self.review(_packet(
            after={"owner": "fictional-owner", "reference": "CHANGED-NOT-A-GRANT"}
        )), "provenance_changed")

    def test_changed_both_provenance_fields_cannot_be_promoted(self):
        self.assert_hold(self.review(_packet(
            after={"owner": "other", "reference": "OTHER-NOT-A-GRANT"}
        )), "provenance_changed")

    def test_reordered_member_keys_do_not_fake_change(self):
        raw = (b'{"after":{"reference":"NOT-A-GRANT","owner":"fictional-owner"},'
               b'"before":{"owner":"fictional-owner","reference":"NOT-A-GRANT"}}')
        self.assert_hold(self.review(raw), "unchanged_shape_only")

    def test_whitespace_and_polymorphic_fields_fail_closed(self):
        for value in ("", " ", "\t", None, True, 0, 1.2, [], {}, ["x"]):
            for side in ("before", "after"):
                for field in ("owner", "reference"):
                    with self.subTest(value=repr(value), side=side, field=field):
                        packet = json.loads(_packet())
                        packet[side][field] = value
                        raw = json.dumps(packet).encode("utf-8")
                        self.assert_hold(self.review(raw), "noncanonical_shape")

    def test_padded_source_data_cannot_be_normalized_to_match(self):
        for field in ("owner", "reference"):
            with self.subTest(field=field):
                packet = json.loads(_packet())
                packet["after"][field] = " " + packet["after"][field]
                self.assert_hold(self.review(json.dumps(packet).encode("utf-8")),
                                 "noncanonical_shape")

    def test_one_missing_snapshot_denies_whole_packet(self):
        for packet in (
            b'{"before":{"owner":"fictional","reference":"NOT-GRANT"}}',
            b'{"after":{"owner":"fictional","reference":"NOT-GRANT"}}',
            b'{}', b'[]', b'null',
            b'{"before":null,"after":null}',
        ):
            with self.subTest(packet=packet):
                self.assert_hold(self.review(packet), "invalid_packet", 3)

    def test_snapshot_extra_or_missing_or_changed_schema_denies(self):
        base = json.loads(_packet())
        mutants = [
            {**base, "asserted_approval": True},
            {"Before": base["before"], "after": base["after"]},
            {"before": base["before"], "after": {"owner": "fictional-owner"}},
            {"before": {**base["before"], "scope": "public"}, "after": base["after"]},
            {"before": base["before"], "after": "fictional-owner"},
            {"before": {}, "after": base["after"]},
        ]
        for mutant in mutants:
            with self.subTest(mutant=mutant):
                self.assert_hold(self.review(json.dumps(mutant).encode("utf-8")),
                                 "invalid_packet", 3)

    def test_duplicate_root_and_nested_keys_are_always_invalid(self):
        packets = (
            b'{"before":{},"before":{},"after":{}}',
            b'{"before":{"owner":"x","owner":"y","reference":"n"},'
            b'"after":{"owner":"x","reference":"n"}}',
            b'{"before":{"owner":"x","reference":"n"},'
            b'"after":{"owner":"x","reference":"n","reference":"n"}}',
            b'{"before":{"owner":"x","reference":"n","unused":{"x":1,"x":2}},'
            b'"after":{"owner":"x","reference":"n"}}',
        )
        for packet in packets:
            with self.subTest(packet=packet):
                self.assert_hold(self.review(packet), "invalid_packet", 3)

    def test_parser_prohibits_nan_infinity_and_partial_json(self):
        packets = (
            b'{"before":NaN,"after":{}}',
            b'{"before":Infinity,"after":{}}',
            b'{"before":{},"after":{}} trailing',
            b'{"before":{},"after":',
            b'\xff',
            b'',
        )
        for packet in packets:
            with self.subTest(packet=packet):
                self.assert_hold(self.review(packet), "invalid_packet", 3)

    def test_overlong_and_deep_packets_fail_without_echo(self):
        huge = _packet() + (b"X" * 6000) + b"SECRET-SYNTHETIC-OPAQUE"
        self.assert_hold(self.review(huge), "invalid_packet", 3)
        deep = b'{"before":' + b"[" * 32 + b"0" + b"]" * 32 + b',"after":{}}'
        self.assert_hold(self.review(deep), "invalid_packet", 3)

    def test_brackets_inside_quoted_values_are_not_json_nesting(self):
        before = {"owner": "[" * 100 + "\\\"" + "}" * 80, "reference": "NOT-GRANT"}
        self.assert_hold(self.review(_packet(before=before, after=dict(before))),
                         "unchanged_shape_only")

    def test_single_mode_never_treats_a_pair_as_one_provenance(self):
        self.assert_hold(_invoke(_packet(), "--offline-synthetic-only"),
                         "invalid_packet", 3)

    def test_paired_mode_never_treats_single_record_as_a_pair(self):
        single = b'{"owner":"fictional","reference":"NOT-GRANT"}'
        self.assert_hold(self.review(single), "invalid_packet", 3)

    def test_explicit_optin_is_required_with_no_file_or_target_args(self):
        packet = _packet()
        for opts in ((), ("--offline-synthetic-pair-only", "--scan"),
                     ("--offline-synthetic-pair-only", "--target", "x"),
                     ("--offline-synthetic-pair-only", "--path", "x"),
                     ("--offline-synthetic-pair-only", "--authorize")):
            with self.subTest(opts=opts):
                self.assert_hold(_invoke(packet, *opts), "invalid_packet", 3)

    def test_private_snapshots_never_echo_to_receipt_or_stderr(self):
        secret = "FICTIONAL-PROVENANCE-SECRET-NEVER-PRINT-12345"
        packet = _packet(
            before={"owner": secret, "reference": "NOT-GRANT"},
            after={"owner": secret + "-changed", "reference": "NOT-GRANT"},
        )
        output = self.review(packet)
        self.assert_hold(output, "provenance_changed")
        self.assertNotIn(secret, json.dumps(output))

    def test_failed_batch_has_no_partial_positive_report(self):
        packet = json.loads(_packet())
        packet["before"]["reference"] = "NOT-GRANT"
        packet["after"]["reference"] = None
        result = self.review(json.dumps(packet).encode("utf-8"))
        self.assert_hold(result, "noncanonical_shape")
        self.assertNotIn("unchanged_shape_only", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
