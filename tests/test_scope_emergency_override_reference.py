"""Offline no-network emergency authority non-escalation checks."""
import unittest
from pathlib import Path
import importlib.util

module_path = Path(__file__).with_name("scope_emergency_override_reference.py")
spec = importlib.util.spec_from_file_location("emergency_ref", module_path)
module = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class EmergencyReferenceTests(unittest.TestCase):
    def test_no_override_can_bypass_denial(self):
        for override in (True, False):
            for stopped in (True, False):
                with self.subTest(override=override, stopped=stopped):
                    self.assertFalse(module.emergency_boundary(
                        stop_active=stopped, override_requested=override,
                        normal_gate_allowed=False).allow_dispatch)

    def test_stop_dominates_positive_grant(self):
        decision = module.emergency_boundary(
            stop_active=True, override_requested=True, normal_gate_allowed=True)
        self.assertFalse(decision.allow_dispatch)
        self.assertEqual(decision.reason, "emergency_stop")

    def test_normal_grant_is_only_positive_path(self):
        result = module.emergency_boundary(
            stop_active=False, override_requested=False, normal_gate_allowed=True)
        self.assertTrue(result.allow_dispatch)
        self.assertTrue(result.require_normal_gate)

    def test_no_coercion_of_untrusted_flags(self):
        for invalid in (1, 0, None, "false", [], object()):
            with self.subTest(invalid=repr(invalid)):
                result = module.emergency_boundary(
                    stop_active=False, override_requested=invalid,
                    normal_gate_allowed=True)
                self.assertFalse(result.allow_dispatch)
                self.assertEqual(result.reason, "invalid_emergency_input")


if __name__ == "__main__":
    unittest.main()
