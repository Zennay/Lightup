"""No-authority offline fictional chronology regressions for issue #1505."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta
import builtins
import importlib
import pathlib
import re
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

from lightup.fictional_review_sequence_1505 import (
    FictionalHandoff, ReviewOutcome, review_fictional_handoff_sequence,
)


def sample(count=3):
    return tuple(
        FictionalHandoff(
            "review-demo.example.test", n, format(n, "064x"),
            (datetime(2026, 1, 1, 12) + timedelta(minutes=n)).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        for n in range(1, count + 1)
    )


class TestFictionalSequence(unittest.TestCase):
    def assert_hold(self, records):
        outcome = review_fictional_handoff_sequence(records)
        self.assertEqual((outcome.status, outcome.checked_records), ("HOLD", 0))
        self.assertIs(type(outcome), ReviewOutcome)
        for flag in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(outcome, flag), False)
        self.assertNotIn("example.test", str(outcome))

    def test_valid_review_is_never_approval(self):
        for count in (2, 3, 16):
            outcome = review_fictional_handoff_sequence(sample(count))
            self.assertEqual(outcome.status, "REVIEW_ONLY")
            self.assertEqual(outcome.checked_records, count)
            for flag in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
                self.assertIs(getattr(outcome, flag), False)

    def test_empty_one_oversize_and_wrong_container(self):
        for data in ((), sample(1), sample(17), list(sample()), None, "irrelevant", b"irrelevant"):
            with self.subTest(data=type(data)):
                self.assert_hold(data)

    def test_sequence_gap_duplicate_and_reordering(self):
        records = sample()
        for seq in (0, 1, 3, 4, -1, True, 2.0, "2"):
            modified = list(records)
            modified[1] = FictionalHandoff(records[1].case_id, seq,
                                             records[1].packet_sha256, records[1].observed_at)
            self.assert_hold(tuple(modified))
        self.assert_hold(tuple(reversed(records)))
        self.assert_hold((records[0], records[2]))

    def test_digest_replay_aliases_type_and_length(self):
        records = sample()
        for digest in (records[0].packet_sha256, "a"*63, "a"*65, "A"*64, "g"*64,
                       "a"*63+"é", b"a"*64, None, "a"*63+"\n"):
            changed = list(records)
            changed[1] = FictionalHandoff(changed[1].case_id, 2, digest, changed[1].observed_at)
            self.assert_hold(tuple(changed))

    def test_case_mismatch_unicode_alias_and_field_subtypes(self):
        original = sample()
        for case in ("review-other.example.test", "REVIEW-demo.example.test",
                     "review-demo.example.test.", "review-demo.example.test\n",
                     "review-démо.example.test", "review-demo.example.com",
                     "review-.example.test", "x"*200, b"review-demo.example.test", None):
            changed = list(original)
            changed[1] = FictionalHandoff(case, 2, changed[1].packet_sha256, changed[1].observed_at)
            self.assert_hold(tuple(changed))

    def test_time_order_equal_invalid_and_day_window(self):
        originals = sample()
        for when in ("2026-01-01T12:01:00Z", "2026-01-01T12:00:00Z",
                     "2026-01-01T12:02:00+00:00", "2026-01-01t12:02:00z",
                     "2026-02-30T12:02:00Z", "2026-01-01T12:02:60Z",
                     "2026-01-01T12:02:00.000Z", "٢٠٢٦-01-01T12:02:00Z", None):
            changed = list(originals)
            changed[1] = FictionalHandoff(changed[1].case_id, 2, changed[1].packet_sha256, when)
            self.assert_hold(tuple(changed))
        records = list(originals)
        records[-1] = FictionalHandoff(records[-1].case_id, 3,
            records[-1].packet_sha256, "2026-01-02T12:02:01Z")
        self.assert_hold(tuple(records))

    def test_record_subclass_is_rejected_without_dynamic_callback(self):
        class Alien(FictionalHandoff):
            def __eq__(self, _other):
                raise AssertionError("should not compare alien")
        record = sample()
        self.assert_hold((Alien(*tuple(getattr(record[0], f) for f in
                                     ("case_id", "sequence", "packet_sha256", "observed_at"))), record[1]))
        class AlienStr(str):
            def __eq__(self, _other):
                raise AssertionError("should not compare alien string")
        self.assert_hold((FictionalHandoff(AlienStr(record[0].case_id), 1,
                                         record[0].packet_sha256, record[0].observed_at), record[1]))

    def test_mutation_attempt_and_outcome_forgery(self):
        record = sample()[0]
        outcome = review_fictional_handoff_sequence(sample())
        with self.assertRaises(FrozenInstanceError):
            record.sequence = 5
        with self.assertRaises(FrozenInstanceError):
            outcome.authorized = True
        for args in (("APPROVED", 2), ("REVIEW_ONLY", 0), ("HOLD", 3),
                     ("REVIEW_ONLY", True), ("HOLD", "0")):
            with self.assertRaises(ValueError):
                ReviewOutcome(*args)

    def test_pure_review_has_no_io_or_runtime_import(self):
        records = sample()
        def forbidden(*_a, **_kw):
            raise AssertionError("I/O not allowed")
        with patch.object(builtins, "open", forbidden), \
             patch.object(socket.socket, "connect", forbidden), \
             patch.object(subprocess, "Popen", forbidden), \
             patch.object(sqlite3, "connect", forbidden):
            result = review_fictional_handoff_sequence(records)
        self.assertEqual(result.status, "REVIEW_ONLY")
        module_path = pathlib.Path(sys.modules[review_fictional_handoff_sequence.__module__].__file__)
        source = module_path.read_text(encoding="utf-8")
        for forbidden_text in ("lightup.scope", "lightup.activation", "lightup.execution_policy",
                               "os.system", "subprocess.", "socket.", "sqlite3.", "open("):
            self.assertNotIn(forbidden_text, source)

    def test_no_partial_result_if_later_record_invalid(self):
        records = list(sample(16))
        records[-1] = FictionalHandoff("review-unexpected.example.test", 16,
                                       records[-1].packet_sha256, records[-1].observed_at)
        self.assert_hold(tuple(records))

    def test_two_snapshot_read_detects_observed_mutation(self):
        class ChangedOnAccess(FictionalHandoff):
            pass
        self.assert_hold((ChangedOnAccess(*tuple(getattr(sample()[0], f) for f in
                       ("case_id", "sequence", "packet_sha256", "observed_at"))), sample()[1]))


    def test_second_snapshot_catches_observed_exact_record_change(self):
        records = sample()
        target = records[1]
        original_get = FictionalHandoff.__getattribute__
        calls = [0]

        def changed_on_second_copy(record, attribute):
            if record is target and attribute == "packet_sha256":
                calls[0] += 1
                if calls[0] == 2:
                    object.__setattr__(record, "packet_sha256", "f" * 64)
            return original_get(record, attribute)

        with patch.object(FictionalHandoff, "__getattribute__", changed_on_second_copy):
            self.assert_hold(records)
        self.assertEqual(calls[0], 2)

    def test_exact_24h_boundary_is_review_only_without_authority(self):
        records = list(sample(2))
        records[1] = FictionalHandoff(records[1].case_id, 2,
                                     records[1].packet_sha256, "2026-01-02T12:01:00Z")
        result = review_fictional_handoff_sequence(tuple(records))
        self.assertEqual((result.status, result.checked_records), ("REVIEW_ONLY", 2))
        self.assertIs(result.authorized, False)

if __name__ == "__main__":
    unittest.main()
