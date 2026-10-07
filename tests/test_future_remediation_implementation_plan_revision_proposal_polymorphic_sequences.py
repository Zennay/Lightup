from __future__ import annotations

import unittest

from lightup.future_remediation_implementation_plan import (
    RemediationImplementationPlanItem,
)
from lightup.future_remediation_implementation_plan_revision_proposal import (
    REMEDIATION_IMPLEMENTATION_PLAN_REVISION_PROPOSAL_SCHEMA_VERSION,
    _revision_plan_digest,
)
from lightup.future_remediation_implementation_plan_revision_proposal_handoff import (
    future_remediation_implementation_plan_revision_proposal_from_dict,
)


class _SpoofingList(list):
    """List whose stored values differ from the values exposed by iteration."""

    def __init__(self, stored: list[object], presented: list[object]) -> None:
        super().__init__(stored)
        self._presented = presented

    def __iter__(self):
        return iter(self._presented)


def _canonical_payload() -> dict:
    item = RemediationImplementationPlanItem(
        plan_item_id="rev-1",
        change_area="configuration",
        intent="Tighten the defensive configuration boundary.",
        verification_intent="Re-run the bounded verification checks.",
        rollback_intent="Restore the prior reviewed configuration.",
    )
    assumptions = ("The change remains planning-only.",)
    unresolved_questions = ("Which owner will schedule implementation review?",)
    digest = _revision_plan_digest(
        revision_request_sha256="1" * 64,
        prior_review_sha256="2" * 64,
        prior_plan_sha256="3" * 64,
        implementation_request_sha256="4" * 64,
        provider_id="scripted",
        model_id="remediation-advisor-test",
        summary="Revise the defensive implementation plan without execution authority.",
        plan_items=(item,),
        assumptions=assumptions,
        unresolved_questions=unresolved_questions,
    )
    return {
        "schema_version": REMEDIATION_IMPLEMENTATION_PLAN_REVISION_PROPOSAL_SCHEMA_VERSION,
        "revision_request_sha256": "1" * 64,
        "prior_review_sha256": "2" * 64,
        "prior_plan_sha256": "3" * 64,
        "implementation_request_sha256": "4" * 64,
        "provider_id": "scripted",
        "model_id": "remediation-advisor-test",
        "summary": "Revise the defensive implementation plan without execution authority.",
        "plan_items": [item.as_dict()],
        "assumptions": list(assumptions),
        "unresolved_questions": list(unresolved_questions),
        "revised_plan_sha256": digest,
        "revised_implementation_plan_created": True,
        "implementation_plan_accepted": False,
        "code_change_authorized": False,
        "tool_call_created": False,
        "execution_allowed": False,
        "target_interaction_allowed": False,
        "future_state_retest_allowed": False,
        "deployment_authorized": False,
        "attack_path_mutation_allowed": False,
        "future_semantics": "unresolved",
        "security_verdict": "not_evaluated",
    }


class RevisedPlanPolymorphicSequenceContractTest(unittest.TestCase):
    def test_exact_builtin_sequence_control_is_accepted(self) -> None:
        payload = _canonical_payload()

        parsed = future_remediation_implementation_plan_revision_proposal_from_dict(
            payload
        )

        self.assertEqual(parsed.revised_plan_sha256, payload["revised_plan_sha256"])
        self.assertFalse(parsed.implementation_plan_accepted)
        self.assertFalse(parsed.execution_allowed)
        self.assertFalse(parsed.target_interaction_allowed)

    def test_plan_items_list_subclass_fails_closed_before_iteration(self) -> None:
        payload = _canonical_payload()
        canonical_item = payload["plan_items"][0]
        spoofed = _SpoofingList(
            stored=[
                {
                    "plan_item_id": "stored-hidden",
                    "change_area": "configuration",
                    "intent": "stored content must not be ignored",
                    "verification_intent": "stored content must not be ignored",
                    "rollback_intent": "stored content must not be ignored",
                    "unexpected_executable_payload": "must never be hidden by iteration",
                }
            ],
            presented=[canonical_item],
        )
        payload["plan_items"] = spoofed
        stored_before = list(list.__iter__(spoofed))

        with self.assertRaisesRegex(ValueError, "plan_items.*list"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                payload
            )

        self.assertEqual(list(list.__iter__(spoofed)), stored_before)

    def test_assumptions_list_subclass_fails_closed_before_iteration(self) -> None:
        payload = _canonical_payload()
        spoofed = _SpoofingList(
            stored=["\x00stored-invalid-assumption"],
            presented=["The change remains planning-only."],
        )
        payload["assumptions"] = spoofed
        stored_before = list(list.__iter__(spoofed))

        with self.assertRaisesRegex(ValueError, "assumptions.*list"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                payload
            )

        self.assertEqual(list(list.__iter__(spoofed)), stored_before)

    def test_unresolved_questions_list_subclass_fails_closed_before_iteration(self) -> None:
        payload = _canonical_payload()
        spoofed = _SpoofingList(
            stored=[""],
            presented=["Which owner will schedule implementation review?"],
        )
        payload["unresolved_questions"] = spoofed
        stored_before = list(list.__iter__(spoofed))

        with self.assertRaisesRegex(ValueError, "unresolved_questions.*list"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                payload
            )

        self.assertEqual(list(list.__iter__(spoofed)), stored_before)


if __name__ == "__main__":
    unittest.main()
