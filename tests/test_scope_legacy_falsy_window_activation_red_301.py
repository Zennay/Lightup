"""#301 real in-process ActivationGate synthetic permit acceptance (expected RED).

No live target interaction, adapter, DNS, socket, actual consent or persist.
The .test hostname is never resolved. Source owner #100/#104 retains files.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy

FIXTURE = "fixture.example.test"


def _gate(mode):
    return ActivationGate(
        ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset((FIXTURE,)),
            require_authorization_for_public=True,
        ),
        ActivationPolicy(mode=mode, activation_reference="SYNTHETIC_NOT_CONSENT"),
    )


def _target(start=None, end=None):
    return Target(
        FIXTURE,
        authorization=Authorization(
            owner="fictional-owner",
            reference="NOT_REAL_CONSENT",
            valid_from=start,
            valid_until=end,
        ),
    )


class FalsyLegacyActivationGateRedTests(unittest.TestCase):
    def test_plan_only_denies_even_falsey_expiry(self):
        with self.assertRaises(PermissionError):
            _gate(ActivationMode.PLAN_ONLY).issue(_target(end=False),
                                                   "web-baseline")

    def test_lab_only_denies_explicit_public_fixture(self):
        with self.assertRaises(PermissionError):
            _gate(ActivationMode.LAB_ONLY).issue(_target(), "web-baseline")

    def test_expired_builtin_authorization_denied(self):
        past = datetime.now(timezone.utc) - timedelta(days=2)
        with self.assertRaises(PermissionError):
            _gate(ActivationMode.AUTHORIZED).issue(
                _target(start=past - timedelta(days=1), end=past),
                "web-baseline",
            )

    def test_future_builtin_authorization_denied(self):
        future = datetime.now(timezone.utc) + timedelta(days=2)
        with self.assertRaises(PermissionError):
            _gate(ActivationMode.AUTHORIZED).issue(
                _target(start=future, end=future + timedelta(days=1)),
                "web-baseline",
            )

    @unittest.expectedFailure
    def test_red_invalid_falsey_expiry_false_must_deny_authorized_permit(self):
        with self.assertRaises(PermissionError):
            _gate(ActivationMode.AUTHORIZED).issue(
                _target(end=False), "web-baseline"
            )

    @unittest.expectedFailure
    def test_red_invalid_falsey_expiry_zero_must_deny_authorized_permit(self):
        with self.assertRaises(PermissionError):
            _gate(ActivationMode.AUTHORIZED).issue(
                _target(end=0), "web-baseline"
            )

    @unittest.expectedFailure
    def test_red_invalid_falsey_start_false_must_deny_authorized_permit(self):
        with self.assertRaises(PermissionError):
            _gate(ActivationMode.AUTHORIZED).issue(
                _target(start=False), "web-baseline"
            )

    @unittest.expectedFailure
    def test_red_invalid_falsey_start_zero_must_deny_authorized_permit(self):
        with self.assertRaises(PermissionError):
            _gate(ActivationMode.AUTHORIZED).issue(
                _target(start=0), "web-baseline"
            )

    def test_synthetic_gate_is_in_process_without_network(self):
        with patch("socket.create_connection", side_effect=AssertionError("network")), \
             patch("socket.socket", side_effect=AssertionError("network")), \
             patch("sqlite3.connect", side_effect=AssertionError("database")):
            with self.assertRaises(PermissionError):
                _gate(ActivationMode.PLAN_ONLY).issue(_target(end=False),
                                                       "web-baseline")

    def test_assertion_witnesses_do_not_hide_runtime_exceptions(self):
        methods = (
            "test_red_invalid_falsey_expiry_false_must_deny_authorized_permit",
            "test_red_invalid_falsey_expiry_zero_must_deny_authorized_permit",
            "test_red_invalid_falsey_start_false_must_deny_authorized_permit",
            "test_red_invalid_falsey_start_zero_must_deny_authorized_permit",
        )
        for name in methods:
            self.assertTrue(getattr(
                self.__class__.__dict__[name],
                "__unittest_expecting_failure__", False
            ))
        result = unittest.TestResult()
        unittest.TestSuite([self.__class__(name) for name in methods]).run(result)
        self.assertEqual(result.testsRun, 4)
        self.assertFalse(result.errors)
        self.assertFalse(result.failures)
        self.assertFalse(result.unexpectedSuccesses)
        self.assertEqual(len(result.expectedFailures), 4)
        for _, traceback in result.expectedFailures:
            self.assertIn("AssertionError:", traceback)
            self.assertNotIn("TypeError:", traceback)


if __name__ == "__main__":
    unittest.main()
