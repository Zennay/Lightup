"""Fiction-only predecessor-chain regression contracts (#1505)."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta
import builtins
import socket
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

from lightup.fictional_review_sequence_linked_1505 import (
    FictionalLinkedHandoff, review_fictional_parent_links,
)


def sample(n=3):
    start = datetime(2026, 1, 1, 12)
    return tuple(
        FictionalLinkedHandoff(
            "review-demo.example.test", step, f"{step:064x}",
            (start + timedelta(minutes=step)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            f"{step-1:064x}",
        ) for step in range(1, n + 1)
    )


def replace(row, **changes):
    fields = {key: getattr(row, key) for key in
              ("case_id", "sequence", "packet_sha256",
               "observed_at", "previous_packet_sha256")}
    fields.update(changes)
    return FictionalLinkedHandoff(**fields)


class TestSyntheticLinkedHistory(unittest.TestCase):
    def validate(self, records, status):
        actual = review_fictional_parent_links(records)
        self.assertEqual((actual.status, actual.checked_records),
                         (status, len(records) if status == "REVIEW_ONLY" else 0))
        for field in ("authorized", "consent_verified", "dispatch_allowed",
                      "release_allowed"):
            self.assertIs(getattr(actual, field), False)
        self.assertNotIn("review-demo", repr(actual))

    def test_exact_two_three_and_sixteen_events_never_authorize(self):
        for count in (2, 3, 16):
            self.validate(sample(count), "REVIEW_ONLY")

    def test_genesis_and_wrong_parent_are_hold(self):
        rows = list(sample())
        for bad in ("f"*64, "1"*64, "A"*64, "0"*63, "0"*65, None, b"0"*64,
                    "0"*63+"\n", "０"*64, True):
            changed = rows.copy()
            changed[0] = replace(rows[0], previous_packet_sha256=bad)
            self.validate(tuple(changed), "HOLD")
        rows[1] = replace(rows[1], previous_packet_sha256="f"*64)
        self.validate(tuple(rows), "HOLD")

    def test_valid_looking_changed_digest_breaks_following_link(self):
        original = sample()
        rows = list(original)
        rows[1] = replace(original[1], packet_sha256="f"*64)
        self.validate(tuple(rows), "HOLD")
        # Coordinated edits are detectable only when they FAIL locally:
        # changing both untrusted hints consistently is NOT provenance.
        rows[2] = replace(rows[2], previous_packet_sha256="f"*64)
        self.validate(tuple(rows), "REVIEW_ONLY")

    def test_invalid_sequence_time_and_mixed_case_hold(self):
        rows = list(sample())
        for change in (
            {"sequence": 3}, {"sequence": True},
            {"observed_at": "2026-01-01T12:01:00Z"},
            {"observed_at": "2026-02-30T12:02:00Z"},
            {"case_id": "review-other.example.test"},
        ):
            candidate = list(sample())
            candidate[1] = replace(candidate[1], **change)
            self.validate(tuple(candidate), "HOLD")

    def test_duplicates_gaps_reverse_and_non_tuple_hold(self):
        original = sample()
        for data in ((), sample(1), sample(17), list(original),
                     tuple(reversed(original)), (original[0], original[0]),
                     (original[0], original[2]), None):
            self.validate(data, "HOLD")

    def test_exact_builtin_records_and_fields_precede_comparison(self):
        original = sample()
        class PoisonStr(str):
            def __eq__(self, _other):
                raise AssertionError("foreign equality")
        class PoisonInt(int):
            def __eq__(self, _other):
                raise AssertionError("foreign integer equality")
        class PoisonRecord(FictionalLinkedHandoff):
            def __eq__(self, _other):
                raise AssertionError("foreign record equality")
        for row in (
            replace(original[0], previous_packet_sha256=PoisonStr("0"*64)),
            replace(original[0], sequence=PoisonInt(1)),
            PoisonRecord(**{name: getattr(original[0], name) for name in
                ("case_id","sequence","packet_sha256","observed_at","previous_packet_sha256")}),
        ):
            self.validate((row, original[1]), "HOLD")

    def test_immutable_record_cannot_be_changed_normally(self):
        with self.assertRaises(FrozenInstanceError):
            sample()[0].sequence = 5

    def test_mutation_on_third_snapshot_is_hold(self):
        records = sample()
        target = records[1]
        original = FictionalLinkedHandoff.__getattribute__
        hits = [0]
        def changing(record, name):
            if record is target and name == "previous_packet_sha256":
                hits[0] += 1
                if hits[0] == 3:
                    object.__setattr__(record, name, "f"*64)
            return original(record, name)
        with patch.object(FictionalLinkedHandoff, "__getattribute__", changing):
            self.validate(records, "HOLD")
        self.assertEqual(hits[0], 3)

    def test_no_files_network_database_or_process(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("review must have no I/O")
        with patch.object(builtins, "open", forbidden), \
             patch.object(socket.socket, "connect", forbidden), \
             patch.object(sqlite3, "connect", forbidden), \
             patch.object(subprocess, "Popen", forbidden):
            self.validate(sample(), "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
