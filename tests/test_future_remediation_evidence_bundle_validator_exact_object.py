from __future__ import annotations

import dataclasses
import unittest

import test_future_remediation_evidence_bundle as bundle_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_evidence_bundle import (
    FutureRemediationEvidenceBundle,
    validate_future_remediation_evidence_bundle,
)


class _EqualitySpoofBundle(FutureRemediationEvidenceBundle):
    """Producer-impossible subtype that can lie about value equality."""

    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False


class FutureRemediationEvidenceBundleValidatorExactObjectAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.b = bundle_tests.FutureRemediationEvidenceBundleTest(
            "test_bundle_is_deterministic_and_json_serializable"
        )
        self.b.setUp()
        self.addCleanup(self.b.tearDown)
        self.state = self.b.state
        (
            _,
            self.proposal,
            self.context,
            self.resolution,
            self.preview,
            self.report,
            self.plan,
            self.bundle,
        ) = self.b._bundle(
            AttackPathTransitionClassification.WORSENED,
            suffix="validator-exact-object",
        )

    def _state_counts(self) -> tuple[int, int, int]:
        with self.state.connect() as con:
            return tuple(
                int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("runs", "capability_leases", "evidence")
            )

    def _spoof(self, **mutations) -> _EqualitySpoofBundle:
        values = {
            field.name: getattr(self.bundle, field.name)
            for field in dataclasses.fields(FutureRemediationEvidenceBundle)
        }
        values.update(mutations)
        return _EqualitySpoofBundle(**values)

    def _validate(self, candidate):
        return validate_future_remediation_evidence_bundle(
            candidate,
            self.plan,
            self.report,
            self.preview,
            self.proposal,
            (self.resolution,),
            (self.context,),
            self.state,
        )

    def test_exact_canonical_bundle_remains_green(self):
        before = self._state_counts()
        self.assertIs(self._validate(self.bundle).__class__, FutureRemediationEvidenceBundle)
        self.assertEqual(self._state_counts(), before)

    def test_equality_spoofing_bundle_subclass_fails_closed(self):
        candidate = self._spoof()
        before_candidate = candidate.as_dict()
        before_state = self._state_counts()

        with self.assertRaisesRegex(
            ValueError,
            "exact FutureRemediationEvidenceBundle",
        ):
            self._validate(candidate)

        self.assertEqual(candidate.as_dict(), before_candidate)
        self.assertEqual(self._state_counts(), before_state)

    def test_authority_widening_subclass_cannot_be_normalized_into_acceptance(self):
        candidate = self._spoof(execution_allowed=True)
        before_candidate = candidate.as_dict()
        before_state = self._state_counts()

        with self.assertRaisesRegex(
            ValueError,
            "exact FutureRemediationEvidenceBundle",
        ):
            self._validate(candidate)

        self.assertTrue(candidate.execution_allowed)
        self.assertEqual(candidate.as_dict(), before_candidate)
        self.assertEqual(self._state_counts(), before_state)


if __name__ == "__main__":
    unittest.main()
