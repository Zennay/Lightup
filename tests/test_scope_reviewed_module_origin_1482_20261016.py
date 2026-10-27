"""#1482 module-origin evidence is only an offline test-runner sanity check.

No module-origin string proves signed source, safe imports, customer scope or
a release. All unexpected identity conflicts remain HOLD.
"""
import importlib
import importlib.util
import io
from pathlib import Path
import sys
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_scope_1482_all_owned_acceptance_20261016.py"
spec = importlib.util.spec_from_file_location("scope_1482_module_origins", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ModuleOriginAdmissionTests(unittest.TestCase):
    def test_original_modules_resolve_to_reviewed_source_after_import(self):
        sys.path.insert(0, str(ROOT / "src"))
        for name in verifier.MODULE_FILE_PINS:
            importlib.import_module(name)
        self.assertTrue(verifier.module_origins_valid(require_all=True))

    def test_exact_module_map_has_seven_source_pins(self):
        self.assertEqual(len(verifier.MODULE_FILE_PINS), 7)
        self.assertEqual(
            set(verifier.MODULE_FILE_PINS.values()),
            {name for name in verifier.PINNED_GIT_BLOBS if name.startswith("src/")},
        )

    def test_wrong_module_file_location_is_rejected(self):
        fake = types.ModuleType("lightup.scope")
        fake.__file__ = "/no-such-external-plugin/scope.py"
        fake.__spec__ = types.SimpleNamespace(origin=fake.__file__)
        with patch.dict(sys.modules, {"lightup.scope": fake}):
            self.assertFalse(verifier.module_origins_valid())

    def test_right_file_label_wrong_import_spec_is_rejected(self):
        filename = str(ROOT / "src/lightup/scope.py")
        fake = types.ModuleType("lightup.scope")
        fake.__file__ = filename
        fake.__spec__ = types.SimpleNamespace(origin="/external-shadow/scope.py")
        with patch.dict(sys.modules, {"lightup.scope": fake}):
            self.assertFalse(verifier.module_origins_valid())

    def test_missing_spec_is_rejected(self):
        fake = types.ModuleType("lightup.scope")
        fake.__file__ = str(ROOT / "src/lightup/scope.py")
        with patch.dict(sys.modules, {"lightup.scope": fake}):
            self.assertFalse(verifier.module_origins_valid())

    def test_unimported_source_is_acceptable_only_during_preflight(self):
        with patch.dict(sys.modules, {"lightup.scope": None}):
            self.assertTrue(verifier.module_origins_valid(require_all=False))
            self.assertFalse(verifier.module_origins_valid(require_all=True))

    def test_legitimate_parent_dot_path_resolves_to_same_source(self):
        import lightup.scope as real
        original_file = real.__file__
        original_spec_origin = real.__spec__.origin
        alias = str(ROOT / "tests" / ".." / "src" / "lightup" / "scope.py")
        try:
            real.__file__ = alias
            real.__spec__.origin = alias
            self.assertTrue(verifier.module_origins_valid())
        finally:
            real.__file__ = original_file
            real.__spec__.origin = original_spec_origin

    def test_bogus_origin_before_test_discovery_returns_hold(self):
        with patch.object(verifier, "module_origins_valid", return_value=False), \
             patch.object(unittest.defaultTestLoader, "discover",
                          side_effect=AssertionError("must not discover")):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = verifier.run()
        self.assertEqual(rc, 2)
        self.assertEqual(out.getvalue().strip(), "HOLD: module_origin")

    def test_origin_changes_during_tests_returns_hold_after_full_run(self):
        with patch.object(verifier, "module_origins_valid",
                          side_effect=[True, False]) as spy:
            out = io.StringIO()
            with redirect_stdout(out):
                rc = verifier.run()
        self.assertEqual(rc, 2)
        self.assertEqual(spy.call_count, 2)
        self.assertEqual(out.getvalue().strip(), "HOLD: module_origin")

    def test_normal_owned_126_case_returns_review_only(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = verifier.run()
        self.assertEqual(rc, 0)
        self.assertIn("REVIEW_ONLY", out.getvalue())
        self.assertIn("NO RELEASE", out.getvalue())


if __name__ == "__main__":
    unittest.main()
