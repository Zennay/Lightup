from __future__ import annotations

import dataclasses
import unittest

import test_future_attack_path_security_delta_report as report_tests
from lightup.future_attack_path_security_delta_report import (
    FutureAttackPathSecurityDeltaReport,
    build_future_attack_path_security_delta_report,
)
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan import (
    FutureRemediationNextAction,
    build_future_security_remediation_retest_plan,
)


class _EqualityTrapReport(FutureAttackPathSecurityDeltaReport):
    def __ne__(self, other):
        raise AssertionError(
            "caller-controlled report comparison ran before exact-type validation"
        )


class _EqualitySpoofingReport(FutureAttackPathSecurityDeltaReport):
    def __ne__(self, other):
        return False


class FutureSecurityRemediationRetestPlanReportObjectIdentityTest(unittest.TestCase):
    def setUp(self):
        self.r = report_tests.FutureAttackPathSecurityDeltaReportTest(
            "test_all_st4_outcomes_render_exact_evidence_linked_items"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        self.state = self.r.state

    @staticmethod
    def _as_subclass(report, cls, **changes):
        values = {
            field.name: getattr(report, field.name)
            for field in dataclasses.fields(FutureAttackPathSecurityDeltaReport)
        }
        values.update(changes)
        return cls(**values)

    def _inputs(self, *, suffix):
        _, proposal, context, resolution, preview = self.r._inputs(
            AttackPathTransitionClassification.INTRODUCED,
            suffix=suffix,
        )
        resolutions = (resolution,)
        contexts = (context,)
        report = build_future_attack_path_security_delta_report(
            preview,
            proposal,
            resolutions,
            contexts,
            self.state,
        )
        return report, preview, proposal, resolutions, contexts

    def _state_rows(self):
        with self.state.connect() as con:
            runs = tuple(
                tuple(row)
                for row in con.execute(
                    "SELECT run_id,target,authorization_ref,activation_mode,status,created_at "
                    "FROM runs ORDER BY run_id"
                )
            )
            leases = tuple(
                tuple(row)
                for row in con.execute(
                    "SELECT run_id,capability_id,worker_id,expires_at "
                    "FROM capability_leases ORDER BY run_id,capability_id"
                )
            )
            evidence = tuple(
                tuple(row)
                for row in con.execute(
                    "SELECT evidence_id,run_id,capability_id,kind,source,sha256,"
                    "metadata_json,created_at FROM evidence ORDER BY evidence_id"
                )
            )
        return runs, leases, evidence

    def test_exact_canonical_report_remains_green(self):
        report, preview, proposal, resolutions, contexts = self._inputs(
            suffix="report-object-exact-control"
        )
        plan = build_future_security_remediation_retest_plan(
            report,
            preview,
            proposal,
            resolutions,
            contexts,
            self.state,
        )

        self.assertEqual(
            plan.items[0].next_action,
            FutureRemediationNextAction.AUTHOR_REMEDIATION_THEN_RETEST,
        )
        self.assertTrue(plan.items[0].remediation_required)
        self.assertTrue(plan.items[0].future_state_retest_required)
        self.assertFalse(plan.execution_allowed)
        self.assertFalse(plan.deployment_authorized)
        self.assertFalse(plan.attack_path_mutation_allowed)

    def test_report_subclass_is_rejected_before_polymorphic_comparison(self):
        report, preview, proposal, resolutions, contexts = self._inputs(
            suffix="report-object-comparison-trap"
        )
        trapped = self._as_subclass(report, _EqualityTrapReport)
        before = dataclasses.asdict(trapped)
        before_state = self._state_rows()

        with self.assertRaisesRegex(
            ValueError,
            "report must be an exact FutureAttackPathSecurityDeltaReport",
        ):
            build_future_security_remediation_retest_plan(
                trapped,
                preview,
                proposal,
                resolutions,
                contexts,
                self.state,
            )

        self.assertEqual(dataclasses.asdict(trapped), before)
        self.assertEqual(self._state_rows(), before_state)

    def test_equality_spoof_cannot_change_remediation_semantics(self):
        report, preview, proposal, resolutions, contexts = self._inputs(
            suffix="report-object-equality-spoof"
        )
        tampered_item = dataclasses.replace(
            report.items[0],
            classification=AttackPathTransitionClassification.IMPROVED,
        )
        spoofed = self._as_subclass(
            report,
            _EqualitySpoofingReport,
            items=(tampered_item,),
        )
        before = dataclasses.asdict(spoofed)
        before_state = self._state_rows()

        with self.assertRaisesRegex(
            ValueError,
            "report must be an exact FutureAttackPathSecurityDeltaReport",
        ):
            build_future_security_remediation_retest_plan(
                spoofed,
                preview,
                proposal,
                resolutions,
                contexts,
                self.state,
            )

        self.assertEqual(dataclasses.asdict(spoofed), before)
        self.assertEqual(self._state_rows(), before_state)


if __name__ == "__main__":
    unittest.main()
