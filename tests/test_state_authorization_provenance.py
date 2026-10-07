import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.engagements import AssessmentMode
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

    def test_non_authorized_assessment_modes_persist_without_authorization(self):
        for mode in (
            AssessmentMode.ANALYSIS_ONLY,
            AssessmentMode.PASSIVE_DISCOVERY,
            AssessmentMode.LAB_AUTONOMOUS,
        ):
            with self.subTest(mode=mode):
                self.store.create_run(f"target-{mode.value}", activation_mode=mode)

        rows = self._runs()
        self.assertEqual(
            [row["activation_mode"] for row in rows],
            ["analysis_only", "passive_discovery", "lab_autonomous"],
        )
        self.assertTrue(all(row["authorization_ref"] is None for row in rows))

    def test_existing_exact_canonical_string_modes_remain_supported(self):
        for mode in (
            "plan_only",
            "analysis_only",
            "passive_discovery",
            "lab_autonomous",
        ):
            with self.subTest(mode=mode):
                self.store.create_run(f"target-{mode}", activation_mode=mode)

        self.assertEqual(
            [row["activation_mode"] for row in self._runs()],
            ["plan_only", "analysis_only", "passive_discovery", "lab_autonomous"],
        )

    def test_authorized_assessment_requires_canonical_reference(self):
        run_id = self.store.create_run(
            "authorized-target",
            activation_mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            authorization_ref="approval-123",
        )

        self.assertTrue(run_id)
        rows = self._runs()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["activation_mode"], "authorized_assessment")
        self.assertEqual(rows[0]["authorization_ref"], "approval-123")

    def test_authorized_assessment_exact_string_mode_is_supported(self):
        self.store.create_run(
            "authorized-target",
            activation_mode="authorized_assessment",
            authorization_ref="approval-456",
        )

        rows = self._runs()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["activation_mode"], "authorized_assessment")
        self.assertEqual(rows[0]["authorization_ref"], "approval-456")

    def test_unknown_or_legacy_activation_mode_fails_before_persistence(self):
        for mode in ("authorized", "lab_only", "unexpected"):
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    self.store.create_run("target", activation_mode=mode)

        self.assertEqual(self._runs(), [])

    def test_string_subclass_mode_fails_before_persistence(self):
        class ConfusedMode(str):
            pass

        with self.assertRaises(ValueError):
            self.store.create_run("target", activation_mode=ConfusedMode("lab_autonomous"))

        self.assertEqual(self._runs(), [])

    def test_non_authorized_modes_reject_authorization_reference(self):
        modes = (
            "plan_only",
            AssessmentMode.ANALYSIS_ONLY,
            AssessmentMode.PASSIVE_DISCOVERY,
            AssessmentMode.LAB_AUTONOMOUS,
        )
        for mode in modes:
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    self.store.create_run(
                        "target",
                        activation_mode=mode,
                        authorization_ref="approval-should-not-bind",
                    )

        self.assertEqual(self._runs(), [])

    def test_authorized_assessment_rejects_missing_blank_or_noncanonical_reference(self):
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
                        activation_mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
                        authorization_ref=reference,
                    )

        self.assertEqual(self._runs(), [])


if __name__ == "__main__":
    unittest.main()
