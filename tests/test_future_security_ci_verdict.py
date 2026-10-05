from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_attack_path_graph_diff_preview as preview_tests
from lightup.future_attack_path_graph_diff_policy import (
    decide_future_attack_path_graph_diff_policy,
)
from lightup.future_attack_path_graph_diff_preview import (
    build_future_attack_path_graph_diff_preview,
)
from lightup.future_attack_path_security_delta_report import (
    build_future_attack_path_security_delta_report,
)
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_effects import RiskDirection
from lightup.future_security_ci_verdict import (
    VERDICT_SCHEMA_VERSION,
    FutureSecurityCIVerdictPolicy,
    SecurityCIVerdict,
    decide_future_security_ci_verdict,
)


class FutureSecurityCIVerdictTest(unittest.TestCase):
    def setUp(self):
        self.p = preview_tests.FutureAttackPathGraphDiffPreviewTest(
            "test_introduced_preview_is_deterministic_and_read_only"
        )
        self.p.setUp()
        self.addCleanup(self.p.tearDown)
        self.state = self.p.state
        self.policy = FutureSecurityCIVerdictPolicy(
            policy_id="strict-default",
            policy_version=1,
        )

    def _inputs(self, classification, *, suffix):
        existing = {
            AttackPathTransitionClassification.WORSENED: RiskDirection.INCREASED,
            AttackPathTransitionClassification.IMPROVED: RiskDirection.DECREASED,
            AttackPathTransitionClassification.REMOVED: RiskDirection.DECREASED,
        }
        if classification in existing:
            current, proposal, context, resolution = (
                self.p._existing_path_resolved_preview_input(
                    classification,
                    direction=existing[classification],
                    suffix=suffix,
                )
            )
        else:
            proposal, context, resolution = self.p._resolved_preview_input(
                classification,
                suffix=suffix,
            )
            current = self.p.r.t.f.f.current

        preview = build_future_attack_path_graph_diff_preview(
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        report = build_future_attack_path_security_delta_report(
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        graph_policy = decide_future_attack_path_graph_diff_policy(
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return current, proposal, context, resolution, preview, report, graph_policy

    def _verdict(self, classification, *, suffix, policy=None):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            graph_policy,
        ) = self._inputs(classification, suffix=suffix)
        result = decide_future_security_ci_verdict(
            report,
            graph_policy,
            policy or self.policy,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            graph_policy,
            result,
        )

    def test_default_introduced_delta_blocks_without_authorizing_deployment(self):
        current = self.p.r.t.f.f.current
        before = dataclasses.asdict(current)
        *_, result = self._verdict(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="ci-block",
        )

        self.assertEqual(result.schema_version, VERDICT_SCHEMA_VERSION)
        self.assertEqual(result.verdict, SecurityCIVerdict.BLOCK)
        self.assertEqual(result.security_verdict, "BLOCK")
        self.assertEqual(result.ci_conclusion, "failure")
        self.assertFalse(result.deployment_authorized)
        self.assertFalse(result.attack_path_mutation_allowed)
        self.assertEqual(result.future_semantics, "unresolved")
        self.assertEqual(len(result.verdict_sha256), 64)
        int(result.verdict_sha256, 16)
        self.assertEqual(dataclasses.asdict(current), before)

    def test_improved_delta_passes_under_strict_default(self):
        *_, result = self._verdict(
            AttackPathTransitionClassification.IMPROVED,
            suffix="ci-pass",
        )
        self.assertEqual(result.verdict, SecurityCIVerdict.PASS)
        self.assertEqual(result.ci_conclusion, "success")
        self.assertFalse(result.deployment_authorized)

    def test_verified_delta_mapping_is_configurable(self):
        policy = FutureSecurityCIVerdictPolicy(
            policy_id="warn-introduced",
            policy_version=2,
            introduced=SecurityCIVerdict.PASS_WITH_WARNING,
            worsened=SecurityCIVerdict.REVIEW_REQUIRED,
            improved=SecurityCIVerdict.PASS,
            removed=SecurityCIVerdict.PASS,
        )
        *_, result = self._verdict(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="ci-warning",
            policy=policy,
        )
        self.assertEqual(result.verdict, SecurityCIVerdict.PASS_WITH_WARNING)
        self.assertEqual(result.ci_conclusion, "neutral")
        self.assertIn(
            "policy:introduced:pass_with_warning",
            result.reason_codes,
        )

    def test_insufficient_evidence_can_never_become_pass(self):
        permissive = FutureSecurityCIVerdictPolicy(
            policy_id="permissive-verified-only",
            policy_version=1,
            introduced=SecurityCIVerdict.PASS,
            worsened=SecurityCIVerdict.PASS,
            improved=SecurityCIVerdict.PASS,
            removed=SecurityCIVerdict.PASS,
        )
        *_, result = self._verdict(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="ci-unknown",
            policy=permissive,
        )
        self.assertEqual(result.verdict, SecurityCIVerdict.REVIEW_REQUIRED)
        self.assertEqual(result.ci_conclusion, "action_required")
        self.assertIn("insufficient_evidence", result.reason_codes)
        self.assertFalse(result.deployment_authorized)

    def test_verdict_is_deterministic_and_json_serializable(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            graph_policy,
            first,
        ) = self._verdict(
            AttackPathTransitionClassification.REMOVED,
            suffix="ci-deterministic",
        )
        second = decide_future_security_ci_verdict(
            report,
            graph_policy,
            self.policy,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        self.assertEqual(first, second)
        exported = json.loads(first.to_json())
        self.assertEqual(exported["security_verdict"], first.verdict.value)
        self.assertEqual(exported["deployment_authorized"], False)
        self.assertEqual(exported["policy_sha256"], first.policy_sha256)

    def test_tampered_report_is_rejected_by_independent_revalidation(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            graph_policy,
        ) = self._inputs(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="ci-tampered-report",
        )
        tampered = dataclasses.replace(report, report_sha256="0" * 64)

        with self.assertRaisesRegex(ValueError, "security delta report is stale"):
            decide_future_security_ci_verdict(
                tampered,
                graph_policy,
                self.policy,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_tampered_graph_policy_decision_is_rejected(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            graph_policy,
        ) = self._inputs(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="ci-tampered-policy",
        )
        tampered = dataclasses.replace(graph_policy, decision_sha256="0" * 64)

        with self.assertRaisesRegex(ValueError, "graph diff policy decision is stale"):
            decide_future_security_ci_verdict(
                report,
                tampered,
                self.policy,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_policy_identity_and_mapping_are_bound_into_digest(self):
        *prefix, first = self._verdict(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="ci-policy-digest",
        )
        current, proposal, context, resolution, preview, report, graph_policy = prefix
        alternate = FutureSecurityCIVerdictPolicy(
            policy_id="strict-default",
            policy_version=2,
        )
        second = decide_future_security_ci_verdict(
            report,
            graph_policy,
            alternate,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        self.assertNotEqual(first.policy_sha256, second.policy_sha256)
        self.assertNotEqual(first.verdict_sha256, second.verdict_sha256)


if __name__ == "__main__":
    unittest.main()
