import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationMode
from lightup.state import StateStore


class RunAuthorizationProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db")
        self.store = StateStore(self.tmp.name)

    def tearDown(self):
        self.tmp.close()

    def _runs(self):
        with self.store.connect() as con:
            return con.execute(
                "SELECT target, authorization_ref, activation_mode, status FROM runs ORDER BY rowid"
            ).fetchall()

    def test_default_plan_only_run_stores_no_authorization(self):
        self.store.create_run("plan-target")

        rows = self._runs()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["activation_mode"], "plan_only")
        self.assertIsNone(rows[0]["authorization_ref"])

    def test_lab_only_enum_stores_canonical_mode_without_authorization(self):
        self.store.create_run("lab-target", activation_mode=ActivationMode.LAB_ONLY)

        rows = self._runs()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["activation_mode"], "lab_only")
        self.assertIsNone(rows[0]["authorization_ref"])

    def test_existing_exact_canonical_string_mode_remains_supported(self):
        self.store.create_run("legacy-plan", activation_mode="plan_only")

        rows = self._runs()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["activation_mode"], "plan_only")

    def test_authorized_run_requires_canonical_reference(self):
        run_id = self.store.create_run(
            "authorized-target",
            activation_mode=ActivationMode.AUTHORIZED,
            authorization_ref="approval-123",
        )

        self.assertTrue(run_id)
        rows = self._runs()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["activation_mode"], "authorized")
        self.assertEqual(rows[0]["authorization_ref"], "approval-123")

    def test_unknown_mode_fails_before_persistence(self):
        with self.assertRaises(ValueError):
            self.store.create_run("target", activation_mode="authorized_assessment")

        self.assertEqual(self._runs(), [])

    def test_string_subclass_mode_fails_before_persistence(self):
        class ConfusedMode(str):
            pass

        with self.assertRaises(ValueError):
            self.store.create_run("target", activation_mode=ConfusedMode("plan_only"))

        self.assertEqual(self._runs(), [])

    def test_non_authorized_modes_reject_authorization_reference(self):
        for mode in (ActivationMode.PLAN_ONLY, ActivationMode.LAB_ONLY, "plan_only", "lab_only"):
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    self.store.create_run(
                        "target",
                        activation_mode=mode,
                        authorization_ref="approval-should-not-bind",
                    )

        self.assertEqual(self._runs(), [])

    def test_authorized_mode_rejects_missing_blank_or_noncanonical_reference(self):
        class ReferenceSubclass(str):
            pass

        bad_references = (
            None,
            "",
            "   ",
            " approval-123",
            "approval-123 ",
            ReferenceSubclass("approval-123"),
        )
        for reference in bad_references:
            with self.subTest(reference=repr(reference)):
                with self.assertRaises(ValueError):
                    self.store.create_run(
                        "target",
                        activation_mode=ActivationMode.AUTHORIZED,
                        authorization_ref=reference,
                    )

        self.assertEqual(self._runs(), [])


if __name__ == "__main__":
    unittest.main()
