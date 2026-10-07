"""Unit checks for the offline documentation integrity checker.

These tests do not exercise ToolExecutor or establish authorization security.
"""
import importlib.util
from pathlib import Path
import unittest


CHECKER_PATH = Path(__file__).resolve().parents[1] / "scripts/check_scope_authorization_gate_matrix.py"
spec = importlib.util.spec_from_file_location("scope_gate_matrix_checker", CHECKER_PATH)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ScopeGateMatrixSpecificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = module.MATRIX.read_text(encoding="utf-8")

    def test_current_specification_has_expected_cases(self):
        self.assertEqual(module.check(self.reference), [])

    def test_duplicate_case_fails(self):
        row = next(line for line in self.reference.splitlines() if line.startswith("| L1 |"))
        self.assertTrue(any("Duplicate" in error for error in module.check(self.reference + "\n" + row)))

    def test_missing_case_fails(self):
        document = "\n".join(
            line for line in self.reference.splitlines() if not line.startswith("| T4 |")
        )
        self.assertTrue(any("missing=" in error for error in module.check(document)))

    def test_required_safety_language_fails_when_removed(self):
        altered = self.reference.replace("No DNS/network I/O", "No external access")
        self.assertTrue(any("No DNS/network I/O" in error for error in module.check(altered)))

    def test_malformed_row_fails(self):
        altered = self.reference.replace("| L1 | Construct executor", "| L1 | unexpected | Construct executor", 1)
        self.assertTrue(any("Malformed" in error for error in module.check(altered)))


if __name__ == "__main__":
    unittest.main()
