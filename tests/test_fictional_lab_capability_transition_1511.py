"""#1511 synthetic installed-ActivationGate transition proof, no product code changes.

A *test-instance-only* wrapper demonstrates one proposed capability-ID
narrowing; it never alters ActivationGate.issue on the class, writes grants,
imports active workers, or connects to a target. Runtime fix remains OPEN.
"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.fictional_lab_capability_review_1511 import (
    review_fictional_lab_capability_1511,
)
from lightup.models import Target
from lightup.scope import ScopePolicy


class _EqSpoofer:
    def __eq__(self, other):
        return True


class _Subclass(str):
    pass


class _CandidateLabGate:
    """Test-only temporary wrapper; NOT installed, not a permission system."""

    def __init__(self, gate: ActivationGate):
        self._gate = gate

    def issue(self, target: Target, capability_id: object):
        # Fake allowlist is merely a local test fixture, not trusted registry
        # or actual client/operator consent. The result is NEVER a grant.
        scope = ("web-baseline", "tls-baseline")
        decision = review_fictional_lab_capability_1511(capability_id, scope)
        if decision.status != "REVIEW_ONLY":
            raise PermissionError("synthetic LAB capability admission HOLD")
        return self._gate.issue(target, capability_id)


class FictionalLabInstalledTransition1511Tests(unittest.TestCase):
    def new_gate(self, mode=ActivationMode.LAB_ONLY, scope=None):
        return ActivationGate(
            scope if scope is not None else ScopePolicy(),
            ActivationPolicy(mode=mode, activation_reference="LAB-SYNTHETIC"),
        )

    def test_test_only_wrapper_denies_invalid_capabilities_before_permit(self):
        wrapper = _CandidateLabGate(self.new_gate())
        fake = Target("127.0.0.1")
        for value in ("", " ", "web baseline", "Web-baseline",
                      "web--baseline", "web_baseline", "a" * 65,
                      None, False, 7, _EqSpoofer(), _Subclass("web-baseline")):
            with self.subTest(kind=type(value).__name__), self.assertRaises(PermissionError):
                wrapper.issue(fake, value)

    def test_wrapper_still_allows_canonical_local_fixture_without_dispatch(self):
        wrapper = _CandidateLabGate(self.new_gate())
        permit = wrapper.issue(Target("127.0.0.1"), "web-baseline")
        self.assertEqual(permit.mode, ActivationMode.LAB_ONLY)
        self.assertEqual(permit.capability_id, "web-baseline")
        self.assertEqual(permit.target, "127.0.0.1")

    def test_wrapper_does_not_widen_original_plan_only_gate(self):
        wrapper = _CandidateLabGate(self.new_gate(ActivationMode.PLAN_ONLY))
        with self.assertRaises(PermissionError):
            wrapper.issue(Target("127.0.0.1"), "web-baseline")

    def test_wrapper_does_not_enable_public_target_under_lab_only(self):
        scope = ScopePolicy(
            explicit_hosts=frozenset({"review.example.test"}),
            require_authorization_for_public=False,
        )
        wrapper = _CandidateLabGate(self.new_gate(scope=scope))
        with self.assertRaises(PermissionError):
            wrapper.issue(Target("review.example.test"), "web-baseline")

    def test_unknown_canonical_string_stays_on_hold_without_trusted_registry(self):
        wrapper = _CandidateLabGate(self.new_gate())
        with self.assertRaises(PermissionError):
            wrapper.issue(Target("127.0.0.1"), "unknown-tool")

    def test_wrapper_does_not_change_original_activation_gate_class(self):
        original = ActivationGate.issue
        wrapped = _CandidateLabGate(self.new_gate())
        with self.assertRaises(PermissionError):
            wrapped.issue(Target("127.0.0.1"), " ")
        self.assertIs(ActivationGate.issue, original)
        # Demonstrates that the underlying original product bug remains OPEN:
        unwrapped = self.new_gate().issue(Target("127.0.0.1"), " ")
        self.assertEqual(unwrapped.capability_id, " ")
        self.assertIs(ActivationGate.issue, original)

    def test_fictitious_review_only_is_not_authenticated_client_consent(self):
        review = review_fictional_lab_capability_1511("web-baseline", ("web-baseline",))
        self.assertEqual(review.status, "REVIEW_ONLY")
        self.assertFalse(review.authorized)
        self.assertFalse(review.consent_verified)
        self.assertFalse(review.dispatch_allowed)
        self.assertFalse(review.release_allowed)


if __name__ == "__main__":
    unittest.main()
