"""Offline acceptance for the separate opt-in passive-snapshot reference (#936)."""
from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from lightup.discovery import ProspectSignal, SignalCategory
from lightup.passive_snapshot import (
    AdmittedPublicSignal,
    MAX_SNAPSHOT_SIGNALS,
    PassiveProspectSnapshot,
)


class TrapText(str):
    def strip(self, *args, **kwargs):
        raise AssertionError("untrusted str subclass method must not be called")


class TrapSignal(ProspectSignal):
    def __getattribute__(self, key):
        raise AssertionError("polymorphic signal must be rejected before access")


class PassiveSnapshotTest(unittest.TestCase):
    @staticmethod
    def signal(**kwargs):
        values = dict(
            category=SignalCategory.CONFIGURATION,
            summary="Invented public configuration",
            source="offline-fixture",
            confidence=0.8,
            public_source=True,
            requires_target_interaction=False,
        )
        values.update(kwargs)
        return ProspectSignal(**values)

    def test_empty_snapshot_has_no_signal_or_confidence(self):
        snapshot = PassiveProspectSnapshot("test-prospect", "Example")
        self.assertIs(type(snapshot.signals), tuple)
        self.assertEqual(snapshot.signals, ())
        self.assertEqual(snapshot.confidence, 0.0)

    def test_batch_creation_copies_public_values(self):
        source = self.signal()
        snap = PassiveProspectSnapshot.from_signals("test-prospect", "Example", (source,))
        self.assertIs(type(snap.signals[0]), AdmittedPublicSignal)
        self.assertEqual(snap.signals[0].source, "offline-fixture")
        object.__setattr__(source, "source", "later caller mutation")
        object.__setattr__(source, "public_source", False)
        self.assertEqual(snap.signals[0].source, "offline-fixture")
        self.assertTrue(snap.signals[0].public_source)

    def test_admission_returns_distinct_snapshot_not_mutation(self):
        start = PassiveProspectSnapshot("p-1", "Example")
        one = start.with_signal(self.signal())
        two = one.with_signal(self.signal(confidence=0.6, summary="Second"))
        self.assertEqual(start.signals, ())
        self.assertEqual(one.confidence, 0.8)
        self.assertEqual(len(one.signals), 1)
        self.assertEqual(len(two.signals), 2)
        self.assertAlmostEqual(two.confidence, 0.7)
        self.assertEqual(two.signals[0], one.signals[0])

    def test_identity_and_collection_refuse_reassignment_and_deletion(self):
        snap = PassiveProspectSnapshot.from_signals(
            "p-1", "Example", (self.signal(),)
        )
        for attr, value in (
            ("prospect_id", "p-2"),
            ("organization_name", "Wrong"),
            ("signals", ()),
        ):
            with self.subTest(attribute=attr):
                with self.assertRaises((AttributeError, TypeError, FrozenInstanceError)):
                    setattr(snap, attr, value)
                with self.assertRaises((AttributeError, TypeError, FrozenInstanceError)):
                    delattr(snap, attr)
        self.assertEqual(snap.prospect_id, "p-1")
        self.assertEqual(len(snap.signals), 1)

    def test_no_inplace_collection_or_record_mutation(self):
        snap = PassiveProspectSnapshot.from_signals("p-1", "Example", (self.signal(),))
        with self.assertRaises(AttributeError):
            snap.signals.append(self.signal())
        with self.assertRaises(TypeError):
            snap.signals[0] = self.signal()
        with self.assertRaises((AttributeError, TypeError)):
            snap.signals[0].source = "other"
        self.assertEqual(snap.signals[0].source, "offline-fixture")

    def test_bad_signal_type_rejected_before_attribute_access(self):
        snap = PassiveProspectSnapshot("p-1", "Example")
        hostile = TrapSignal(
            SignalCategory.CONFIGURATION, "Public", "Fixture", 0.8, True, False
        )
        with self.assertRaisesRegex(ValueError, "exact ProspectSignal"):
            snap.with_signal(hostile)
        self.assertEqual(snap.signals, ())

    def test_reject_malformed_categories_without_state_change(self):
        snap = PassiveProspectSnapshot.from_signals("p-1", "Example", (self.signal(),))
        for bad in ("configuration", None, 1, object()):
            with self.subTest(category=type(bad).__name__):
                with self.assertRaises(ValueError):
                    snap.with_signal(self.signal(category=bad))
                self.assertEqual(len(snap.signals), 1)

    def test_reject_malformed_text_without_custom_coercion(self):
        snap = PassiveProspectSnapshot("p-1", "Example")
        for key in ("summary", "source"):
            for value in ("", " \t ", TrapText("looks valid"), None, 3, object()):
                with self.subTest(field=key, value=type(value).__name__):
                    with self.assertRaises(ValueError):
                        snap.with_signal(self.signal(**{key: value}))
                    self.assertEqual(snap.signals, ())

    def test_reject_invalid_confidence_without_numerical_coercion(self):
        snap = PassiveProspectSnapshot("p-1", "Example")
        for bad in (0, 1, True, float("nan"), float("inf"), -float("inf"),
                    -0.01, 1.01, "0.5", object()):
            with self.subTest(confidence=str(type(bad))):
                with self.assertRaises(ValueError):
                    snap.with_signal(self.signal(confidence=bad))
                self.assertEqual(snap.signals, ())

    def test_reject_false_or_polymorphic_public_flags(self):
        snap = PassiveProspectSnapshot("p-1", "Example")
        for bad in (False, 1, 0, "true", None):
            with self.subTest(public_source=bad):
                with self.assertRaises((ValueError, PermissionError)):
                    snap.with_signal(self.signal(public_source=bad))
                self.assertEqual(snap.signals, ())

    def test_reject_interactive_or_polymorphic_interaction_flags(self):
        snap = PassiveProspectSnapshot("p-1", "Example")
        for bad in (True, 1, "false", None):
            with self.subTest(interactive=bad):
                with self.assertRaises((ValueError, PermissionError)):
                    snap.with_signal(self.signal(requires_target_interaction=bad))
                self.assertEqual(snap.signals, ())

    def test_atomic_late_batch_failure_leaves_previous_snapshot_unchanged(self):
        current = PassiveProspectSnapshot.from_signals("p-1", "Example", (self.signal(),))
        source_batch = (self.signal(), self.signal(confidence=0.6),
                        self.signal(requires_target_interaction=True))
        with self.assertRaises(PermissionError):
            PassiveProspectSnapshot.from_signals("p-2", "Other", source_batch)
        self.assertEqual(current.prospect_id, "p-1")
        self.assertEqual(len(current.signals), 1)
        self.assertEqual(source_batch[1].confidence, 0.6)

    def test_direct_constructor_rejects_preseed_noncanonical_records(self):
        for bad in ([], [self.signal()], (self.signal(),),
                    (("wrong",),)):
            with self.subTest(value=type(bad).__name__):
                with self.assertRaises(ValueError):
                    PassiveProspectSnapshot("p-1", "Example", bad)

    def test_direct_constructor_rejects_nonpublic_record(self):
        bad = AdmittedPublicSignal(
            SignalCategory.CONFIGURATION, "Invented", "fixture", 0.8, False, False
        )
        with self.assertRaises(PermissionError):
            PassiveProspectSnapshot("p-1", "Example", (bad,))

    def test_direct_constructor_rejects_noncanonical_nested_data(self):
        for confidence in (1, float("nan")):
            record = AdmittedPublicSignal(
                SignalCategory.CONFIGURATION, "Invented", "fixture",
                confidence, True, False
            )
            with self.assertRaises(ValueError):
                PassiveProspectSnapshot("p-1", "Example", (record,))

    def test_identity_must_be_exact_nonempty_text(self):
        for bad in ("", "\t ", TrapText("p-1"), None, 1):
            with self.subTest(value=type(bad).__name__):
                with self.assertRaises(ValueError):
                    PassiveProspectSnapshot(bad, "Example")
                with self.assertRaises(ValueError):
                    PassiveProspectSnapshot("p-1", bad)

    def test_exact_tuple_required_before_traversal(self):
        snap = PassiveProspectSnapshot("p-1", "Example")
        with self.assertRaises(ValueError):
            PassiveProspectSnapshot.from_signals("p-2", "Other", [self.signal()])
        self.assertEqual(snap.signals, ())

    def test_capacity_limits_are_atomic(self):
        ordinary = self.signal()
        source_batch = (ordinary,) * MAX_SNAPSHOT_SIGNALS
        full = PassiveProspectSnapshot.from_signals("p-1", "Example", source_batch)
        self.assertEqual(len(full.signals), MAX_SNAPSHOT_SIGNALS)
        self.assertAlmostEqual(full.confidence, 0.8)
        with self.assertRaises(ValueError):
            full.with_signal(ordinary)
        with self.assertRaises(ValueError):
            PassiveProspectSnapshot.from_signals(
                "p-2", "Other", source_batch + (ordinary,)
            )
        self.assertEqual(len(full.signals), MAX_SNAPSHOT_SIGNALS)

    def test_reject_too_long_identity_and_source_without_truncation(self):
        too_long = "x" * 4097
        with self.assertRaises(ValueError):
            PassiveProspectSnapshot(too_long, "Example")
        with self.assertRaises(ValueError):
            PassiveProspectSnapshot("p-1", too_long)
        with self.assertRaises(ValueError):
            PassiveProspectSnapshot("p-1", "Example").with_signal(
                self.signal(source=too_long)
            )

    def test_positive_boundary_float_values(self):
        source = (
            self.signal(confidence=0.0),
            self.signal(confidence=1.0),
            self.signal(confidence=-0.0),
        )
        snap = PassiveProspectSnapshot.from_signals("p-1", "Example", source)
        self.assertEqual(len(snap.signals), 3)
        self.assertAlmostEqual(snap.confidence, 1 / 3)


if __name__ == "__main__":
    unittest.main()
