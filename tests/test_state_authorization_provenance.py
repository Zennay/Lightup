import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.state import StateStore


class RunAuthorizationProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db")
        self.store = StateStore(self.tmp.name)

    def tearDown(self):
        self.tmp.close()

    def _run_row(self, run_id: str):
        with self.store.connect() as con:
            return con.execute(
                "SELECT target, authorization_ref, activation_mode FROM runs WHERE run_id=?",
                (run_id,),
            ).fetchone()

    def test_authorized_assessment_requires_explicit_authorization_reference(self):
        with self.assertRaisesRegex(ValueError, "require authorization_ref"):
            self.store.create_run(
                "app.example.test",
                activation_mode="authorized_assessment",
            )

    def test_authorized_assessment_persists_exact_reference(self):
        run_id = self.store.create_run(
            "app.example.test",
            activation_mode="authorized_assessment",
            authorization_ref="AUTH-2026-007",
        )

        row = self._run_row(run_id)
        self.assertEqual(row["target"], "app.example.test")
        self.assertEqual(row["activation_mode"], "authorized_assessment")
        self.assertEqual(row["authorization_ref"], "AUTH-2026-007")

    def test_non_authorized_modes_cannot_carry_authorization_reference(self):
        for mode in (
            "plan_only",
            "analysis_only",
            "passive_discovery",
            "lab_autonomous",
        ):
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(
                    ValueError,
                    "only valid for authorized_assessment",
                ):
                    self.store.create_run(
                        "127.0.0.1",
                        activation_mode=mode,
                        authorization_ref="AUTH-SHOULD-NOT-BE-TRUSTED",
                    )

    def test_unknown_or_type_confused_activation_modes_fail_closed(self):
        for mode in (
            "",
            "AUTHORIZED_ASSESSMENT",
            " authorized_assessment",
            "authorized_assessment ",
            True,
            1,
        ):
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(ValueError, "activation_mode is invalid"):
                    self.store.create_run("127.0.0.1", activation_mode=mode)

    def test_authorization_reference_must_be_canonical_non_empty_text(self):
        for reference in ("", "   ", " AUTH-1", "AUTH-1 ", 7, True):
            with self.subTest(reference=reference):
                with self.assertRaises(ValueError):
                    self.store.create_run(
                        "app.example.test",
                        activation_mode="authorized_assessment",
                        authorization_ref=reference,
                    )


if __name__ == "__main__":
    unittest.main()
