from __future__ import annotations

import dataclasses
import unittest

import test_future_security_remediation_retest_plan_handoff as handoff_tests
from lightup.future_attack_path_security_delta_report import (
    build_future_attack_path_security_delta_report,
)
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
    build_future_security_remediation_retest_plan,
)
from lightup.future_security_remediation_retest_plan_handoff import (
    validate_future_security_remediation_retest_plan_handoff,
)


class _EqualitySpoofPlan(FutureSecurityRemediationRetestPlan):
    """Producer-impossible subtype that can lie about value equality."""

    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False


class FutureSecurityRemediationRetestPlanValidatorExactObjectAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.h = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)
        self.state = self.h.state

        (
            _,
            self.proposal,
            self.context,
            self.resolution,
            self.preview,
        ) = self.h.r._inputs(
            AttackPathTransitionClassification.WORSENED,
            suffix="plan-validator-exact-object",
        )
        self.report = build_future_attack_path_security_delta_report(
            self.preview,
            self.proposal,
            (self.resolution,),
            (self.context,),
            self.state,
        )
        self.plan = build_future_security_remediation_retest_plan(
            self.report,
            self.preview,
            self.proposal,
            (self.resolution,),
            (self.context,),
            self.state,
        )

    def _state_counts(self) -> tuple[int, int, int]:
        with self.state.connect() as con:
            return tuple(
                int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("runs", "capability_leases", "evidence")
            )

    def _spoof(self, **mutations) -> _EqualitySpoofPlan:
        values = {
            field.name: getattr(self.plan, field.name)
            for field in dataclasses.fields(FutureSecurityRemediationRetestPlan)
        }
        values.update(mutations)
        return _EqualitySpoofPlan(**values)

    def _validate(self, candidate):
        return validate_future_security_remediation_retest_plan_handoff(
            candidate,
            self.report,
            self.preview,
            self.proposal,
            (self.resolution,),
            (self.context,),
            self.state,
        )

    def test_exact_canonical_plan_remains_green(self):
        before = self._state_counts()
        validated = self._validate(self.plan)
        self.assertIs(type(validated), FutureSecurityRemediationRetestPlan)
        self.assertEqual(validated, self.plan)
        self.assertEqual(self._state_counts(), before)

    def test_equality_spoofing_plan_subclass_fails_closed(self):
        candidate = self._spoof()
        before_candidate = candidate.as_dict()
        before_state = self._state_counts()

        with self.assertRaisesRegex(
            ValueError,
            "exact FutureSecurityRemediationRetestPlan",
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
            "exact FutureSecurityRemediationRetestPlan",
        ):
            self._validate(candidate)

        self.assertTrue(candidate.execution_allowed)
        self.assertEqual(candidate.as_dict(), before_candidate)
        self.assertEqual(self._state_counts(), before_state)


if __name__ == "__main__":
    unittest.main()
