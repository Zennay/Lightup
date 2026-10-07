from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_request_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_revision_request_handoff import (
    future_remediation_implementation_plan_revision_request_from_dict,
)


class _IterationSpoofList(list):
    def __init__(self, stored, *, visible):
        super().__init__(stored)
        self._visible = tuple(visible)

    def __iter__(self):
        return iter(self._visible)


class FutureRemediationImplementationPlanRevisionRequestSequenceTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.request = handoff_tests._request()

    def test_exact_builtin_list_control_remains_accepted(self):
        payload = self.request.as_dict()
        payload["required_revisions"] = list(self.request.required_revisions)

        parsed = future_remediation_implementation_plan_revision_request_from_dict(
            payload
        )

        self.assertEqual(parsed, self.request)
        self.assertIs(type(payload["required_revisions"]), list)
        self.assertIs(type(parsed.required_revisions), tuple)

    def test_required_revisions_list_subclass_fails_closed_before_iteration(self):
        spoofed = _IterationSpoofList(
            ["not_a_real_review_check"],
            visible=self.request.required_revisions,
        )
        self.assertEqual(
            list.__getitem__(spoofed, 0),
            "not_a_real_review_check",
        )
        self.assertEqual(tuple(spoofed), self.request.required_revisions)

        payload = self.request.as_dict()
        payload["required_revisions"] = spoofed

        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_revision_request_from_dict(
                payload
            )

        self.assertIs(payload["required_revisions"], spoofed)
        self.assertEqual(
            list.__getitem__(payload["required_revisions"], 0),
            "not_a_real_review_check",
        )


if __name__ == "__main__":
    unittest.main()
