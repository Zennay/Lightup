"""Offline ST5 plan digest and action classification regression tests.

No targets, network, capability execution, or production mutation.
"""
import unittest
from dataclasses import replace
from types import SimpleNamespace

from lightup.future_security_remediation_retest_plan import (
    FutureRemediationNextAction,
    FutureSecurityRemediationRetestPlanItem,
    _plan_digest,
    _planning_action,
)
from lightup.future_attack_path_transition_resolution import AttackPathTransitionClassification
from lightup.future_attack_path_graph_diff_preview import AttackPathGraphDiffAction


def report():
    return SimpleNamespace(
        client_id="tenant-a", current_twin_id="current-a",
        current_twin_version=1, twin_id="future-a", twin_version=2,
        changeset_id="change-a", proposal_sha256="a" * 64,
        impact_analysis_sha256="b" * 64, preview_sha256="c" * 64,
        report_sha256="d" * 64, contains_insufficient_evidence=False,
    )


def item():
    return FutureSecurityRemediationRetestPlanItem(
        change_node_id="change-node", subject_node_id="subject",
        resolution_id="resolution-a", resolution_sha256="e" * 64,
        classification=AttackPathTransitionClassification.INTRODUCED,
        graph_diff_action=AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS,
        next_action=FutureRemediationNextAction.AUTHOR_REMEDIATION_THEN_RETEST,
        remediation_required=True, future_state_retest_required=True,
        evidence_required=False, current_attack_path_ids=("path-a",),
        effect_ids=("effect-a",), evidence_ids=("evidence-a",),
        capability_ids=("capability-a",),
    )


def digest(r=None, items=None):
    return _plan_digest(
        report=r if r is not None else report(),
        items=items if items is not None else (item(),),
        remediation_item_count=1, retest_item_count=1,
        evidence_gap_count=0,
    )


class RemediationPlanDigestBoundaryTests(unittest.TestCase):
    def test_replay_is_deterministic(self):
        self.assertEqual(digest(), digest())
        self.assertRegex(digest(), r"^[0-9a-f]{64}$")

    def test_report_lineage_changes_digest(self):
        original = digest()
        for field, value in (
            ("client_id", "tenant-b"),
            ("current_twin_version", 2),
            ("report_sha256", "f" * 64),
            ("changeset_id", "change-b"),
            ("contains_insufficient_evidence", True),
        ):
            with self.subTest(field=field):
                r = report()
                setattr(r, field, value)
                self.assertNotEqual(original, digest(r=r))

    def test_item_evidence_and_decision_changes_digest(self):
        original = digest()
        for changed in (
            replace(item(), evidence_ids=("evidence-b",)),
            replace(item(), resolution_sha256="f" * 64),
            replace(item(), capability_ids=("capability-b",)),
            replace(item(), remediation_required=False),
            replace(item(), future_state_retest_required=False),
            replace(item(), next_action=FutureRemediationNextAction.COLLECT_MORE_EVIDENCE),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(original, digest(items=(changed,)))

    def test_all_report_digest_lineage_fields_are_bound(self):
        original = digest()
        for field, value in (
            ("proposal_sha256", "f" * 64),
            ("impact_analysis_sha256", "f" * 64),
            ("preview_sha256", "f" * 64),
            ("current_twin_id", "current-b"),
            ("twin_id", "future-b"),
            ("twin_version", 3),
        ):
            with self.subTest(field=field):
                r = report()
                setattr(r, field, value)
                self.assertNotEqual(original, digest(r=r))

    def test_all_item_reference_collections_are_bound(self):
        original = digest()
        for changed in (
            replace(item(), current_attack_path_ids=("path-b",)),
            replace(item(), effect_ids=("effect-b",)),
            replace(item(), change_node_id="other-change-node"),
            replace(item(), subject_node_id="other-subject"),
            replace(item(), resolution_id="other-resolution"),
            replace(item(), graph_diff_action=AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM),
            replace(item(), evidence_required=True),
            replace(item(), classification=AttackPathTransitionClassification.WORSENED),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(original, digest(items=(changed,)))

    def test_counter_and_membership_changes_alter_digest(self):
        baseline = digest()
        for counters in (
            (0, 1, 0),
            (1, 0, 0),
            (1, 1, 1),
        ):
            with self.subTest(counters=counters):
                candidate = _plan_digest(
                    report=report(), items=(item(),),
                    remediation_item_count=counters[0],
                    retest_item_count=counters[1],
                    evidence_gap_count=counters[2],
                )
                self.assertNotEqual(baseline, candidate)
        self.assertNotEqual(
            baseline,
            _plan_digest(
                report=report(), items=(),
                remediation_item_count=1, retest_item_count=1,
                evidence_gap_count=0,
            ),
        )

    def test_digest_does_not_mutate_input_references(self):
        r = report()
        entries = (item(),)
        before_report = vars(r).copy()
        before_item = entries[0].as_dict()
        digest(r=r, items=entries)
        self.assertEqual(vars(r), before_report)
        self.assertEqual(entries[0].as_dict(), before_item)

    def test_digest_matches_independent_canonical_json_reconstruction(self):
        from hashlib import sha256
        import json

        r = report()
        entry = item()
        payload = {
            "schema_version": "st5.remediation_retest_plan.v1",
            "client_id": r.client_id,
            "current_twin_id": r.current_twin_id,
            "current_twin_version": r.current_twin_version,
            "twin_id": r.twin_id,
            "twin_version": r.twin_version,
            "changeset_id": r.changeset_id,
            "proposal_sha256": r.proposal_sha256,
            "impact_analysis_sha256": r.impact_analysis_sha256,
            "preview_sha256": r.preview_sha256,
            "report_sha256": r.report_sha256,
            "items": [{
                "change_node_id": entry.change_node_id,
                "subject_node_id": entry.subject_node_id,
                "resolution_id": entry.resolution_id,
                "resolution_sha256": entry.resolution_sha256,
                "classification": entry.classification.value,
                "graph_diff_action": entry.graph_diff_action.value,
                "next_action": entry.next_action.value,
                "remediation_required": entry.remediation_required,
                "future_state_retest_required": entry.future_state_retest_required,
                "evidence_required": entry.evidence_required,
                "current_attack_path_ids": list(entry.current_attack_path_ids),
                "effect_ids": list(entry.effect_ids),
                "evidence_ids": list(entry.evidence_ids),
                "capability_ids": list(entry.capability_ids),
            }],
            "remediation_item_count": 1,
            "retest_item_count": 1,
            "evidence_gap_count": 0,
            "plan_complete": True,
            "contains_insufficient_evidence": False,
            "execution_allowed": False,
            "deployment_authorized": False,
            "attack_path_mutation_allowed": False,
            "future_semantics": "unresolved",
            "security_verdict": "not_evaluated",
        }
        expected = sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")).hexdigest()
        self.assertEqual(digest(), expected)

    def test_order_is_lineage_significant(self):
        other = replace(item(), resolution_id="resolution-b")
        self.assertNotEqual(digest(items=(item(), other)), digest(items=(other, item())))

    def test_actions_never_grant_execution(self):
        expected = {
            AttackPathTransitionClassification.INTRODUCED:
                (FutureRemediationNextAction.AUTHOR_REMEDIATION_THEN_RETEST, True, True, False),
            AttackPathTransitionClassification.WORSENED:
                (FutureRemediationNextAction.AUTHOR_REMEDIATION_THEN_RETEST, True, True, False),
            AttackPathTransitionClassification.IMPROVED:
                (FutureRemediationNextAction.VERIFY_IMPROVEMENT_WITH_RETEST, False, True, False),
            AttackPathTransitionClassification.REMOVED:
                (FutureRemediationNextAction.VERIFY_IMPROVEMENT_WITH_RETEST, False, True, False),
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE:
                (FutureRemediationNextAction.COLLECT_MORE_EVIDENCE, False, False, True),
        }
        for classification, outcome in expected.items():
            with self.subTest(classification=classification):
                self.assertEqual(_planning_action(classification), outcome)

    def test_unknown_classification_rejected(self):
        with self.assertRaises(ValueError):
            _planning_action("unsupported_classification")


if __name__ == "__main__":
    unittest.main()
