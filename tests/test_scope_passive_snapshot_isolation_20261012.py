"""Independent opt-in snapshot isolation proof, no targets or network (#936)."""
from __future__ import annotations

import socket
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from lightup.discovery import ProspectProfile, ProspectSignal, SignalCategory
from lightup.passive_snapshot import PassiveProspectSnapshot


def signal(i: int = 0, *, public: bool = True,
           interactive: bool = False) -> ProspectSignal:
    return ProspectSignal(
        SignalCategory.CONFIGURATION,
        f"Synthetic public observation {i}",
        "invented offline fixture",
        0.75,
        public,
        interactive,
    )


class RaisingTuple(tuple):
    def __iter__(self):
        raise AssertionError("subclass iteration must not occur")


class ImmutablePassiveSnapshotIsolationTests(unittest.TestCase):
    def test_no_dns_or_socket_for_valid_and_invalid_admission(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket called")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS called")):
                origin = PassiveProspectSnapshot("prospect-1", "Example")
                new = origin.with_signal(signal())
                with self.assertRaises(PermissionError):
                    new.with_signal(signal(1, interactive=True))
                with self.assertRaises(PermissionError):
                    PassiveProspectSnapshot.from_signals(
                        "prospect-2", "Example", (signal(), signal(2, public=False))
                    )
                self.assertEqual(origin.signals, ())
                self.assertEqual(len(new.signals), 1)

    def test_parallel_copy_on_write_never_changes_shared_origin(self):
        initial = PassiveProspectSnapshot.from_signals(
            "prospect-1", "Example", (signal(),)
        )
        before = initial.signals
        with ThreadPoolExecutor(max_workers=8) as pool:
            children = list(pool.map(
                lambda n: initial.with_signal(signal(n)), range(1, 33)
            ))
        self.assertEqual(initial.signals, before)
        self.assertEqual(len(initial.signals), 1)
        for n, child in enumerate(children, start=1):
            self.assertIsNot(child, initial)
            self.assertEqual(child.signals[0], initial.signals[0])
            self.assertEqual(child.signals[1].summary, f"Synthetic public observation {n}")
            self.assertEqual(child.prospect_id, initial.prospect_id)
            self.assertEqual(child.organization_name, initial.organization_name)

    def test_changes_to_legacy_mutable_profile_do_not_alias_snapshot(self):
        legacy = ProspectProfile("prospect-1", "Example")
        original = signal()
        legacy.add_signal(original)
        reference = PassiveProspectSnapshot.from_signals(
            legacy.prospect_id,
            legacy.organization_name,
            tuple(legacy.signals),
        )
        # Legacy mutability is intentionally *not fixed* here; the opt-in
        # canonical records must not retain any mutable caller-owned aliases.
        legacy.signals.clear()
        legacy.prospect_id = "rewritten legacy identity"
        object.__setattr__(original, "source", "later overwritten origin")
        self.assertEqual(reference.prospect_id, "prospect-1")
        self.assertEqual(reference.organization_name, "Example")
        self.assertEqual(len(reference.signals), 1)
        self.assertEqual(reference.signals[0].source, "invented offline fixture")

    def test_polymorphic_tuple_is_denied_before_custom_iteration(self):
        source = RaisingTuple((signal(),))
        with self.assertRaisesRegex(ValueError, "exact tuple"):
            PassiveProspectSnapshot.from_signals("p-1", "Example", source)

    def test_fresh_late_denial_preserves_two_prior_versions(self):
        initial = PassiveProspectSnapshot("p-1", "Example")
        first = initial.with_signal(signal(1))
        second = first.with_signal(signal(2))
        with self.assertRaises(PermissionError):
            second.with_signal(signal(3, public=False))
        third = second.with_signal(signal(4))
        self.assertEqual(len(initial.signals), 0)
        self.assertEqual(len(first.signals), 1)
        self.assertEqual(len(second.signals), 2)
        self.assertEqual(len(third.signals), 3)
        self.assertEqual(
            tuple(record.summary for record in second.signals),
            ("Synthetic public observation 1", "Synthetic public observation 2"),
        )


if __name__ == "__main__":
    unittest.main()
