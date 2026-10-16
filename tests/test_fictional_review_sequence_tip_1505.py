"""Offline fictional last-copy digest pin tests, always nonauthorizing."""
from __future__ import annotations

import builtins
import socket
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

from lightup.fictional_review_sequence_linked_1505 import (
    FictionalLinkedHandoff,
)
from lightup.fictional_review_sequence_tip_1505 import review_fictional_tip_pin


def sample(count=3, altered_tip=False):
    return tuple(FictionalLinkedHandoff(
        "review-demo.example.test", n,
        f"{n:064x}", f"2026-01-01T12:{n:02d}:00Z", f"{n-1:064x}",
    ) for n in range(1, count+1))


def replacement(row, **kw):
    names = ("case_id", "sequence", "packet_sha256",
             "observed_at", "previous_packet_sha256")
    d = {name:getattr(row,name) for name in names}
    d.update(kw)
    return FictionalLinkedHandoff(**d)


class TestFictionalTip(unittest.TestCase):
    def check(self, rows, tip, status):
        result = review_fictional_tip_pin(rows, tip)
        self.assertEqual((result.status, result.checked_records),
                         (status, len(rows) if status == "REVIEW_ONLY" else 0))
        for name in ("authorized", "consent_verified",
                     "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(result, name), False)
        self.assertNotIn("review-demo", repr(result))

    def test_unchanged_tip_is_review_only_never_authority(self):
        for n in (2, 3, 16):
            self.check(sample(n), f"{n:064x}", "REVIEW_ONLY")

    def test_terminal_digest_change_requires_stored_original_tip(self):
        rows = list(sample())
        rows[-1] = replacement(rows[-1], packet_sha256="f"*64)
        self.check(tuple(rows), f"{3:064x}", "HOLD")
        self.check(tuple(rows), "f"*64, "REVIEW_ONLY")

    def test_wrong_missing_alias_or_untrusted_tip_subtype_is_hold(self):
        rows = sample()
        class PoisonStr(str):
            def __eq__(self, _other):
                raise AssertionError("alien tip comparison")
        for bad in (None, "", "A"*64, "g"*64, "3"*64,
                    "0"*63, "0"*65, b"0"*64, True,
                    PoisonStr(f"{3:064x}"), f"{3:064x}\n"):
            self.check(rows, bad, "HOLD")

    def test_breaking_middle_link_cannot_be_ignored_by_valid_tip(self):
        rows = list(sample())
        rows[1] = replacement(rows[1], previous_packet_sha256="f"*64)
        self.check(tuple(rows), f"{3:064x}", "HOLD")

    def test_incorrect_container_or_number_and_mutated_cases_hold(self):
        rows = sample()
        for changed in ((), (rows[0],), sample(17), list(rows),
                        tuple(reversed(rows)), None):
            self.check(changed, f"{3:064x}", "HOLD")

    def test_observed_changed_tip_during_second_capture_is_hold(self):
        rows = sample()
        target = rows[-1]
        original = FictionalLinkedHandoff.__getattribute__
        calls = [0]
        def changed(row, name):
            if row is target and name == "packet_sha256":
                calls[0] += 1
                if calls[0] == 2:
                    object.__setattr__(row, name, "f"*64)
            return original(row, name)
        with patch.object(FictionalLinkedHandoff, "__getattribute__", changed):
            self.check(rows, f"{3:064x}", "HOLD")
        self.assertGreaterEqual(calls[0], 2)

    def test_tip_check_never_uses_network_db_process_or_file(self):
        def forbidden(*_a, **_k):
            raise AssertionError("IO in reviewer")
        with patch.object(builtins, "open", forbidden), \
             patch.object(socket.socket, "connect", forbidden), \
             patch.object(sqlite3, "connect", forbidden), \
             patch.object(subprocess, "Popen", forbidden):
            self.check(sample(), f"{3:064x}", "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
