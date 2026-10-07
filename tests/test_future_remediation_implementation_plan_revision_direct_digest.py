from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_implementation_plan_revision_proposal as revision_tests


class FutureRemediationImplementationPlanRevisionDirectDigestTest(unittest.TestCase):
    def setUp(self):
        self.base = revision_tests.FutureRemediationImplementationPlanRevisionProposalTest(
            "test_live_revision_request_generates_unaccepted_non_executable_revised_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.revised_plan = self.base._generate(gateway)

    def test_canonical_revised_plan_digest_is_stable(self):
        plan = self.revised_plan

        self.assertEqual(len(plan.revised_plan_sha256), 64)
        self.assertEqual(plan, replace(plan))

    def test_direct_lineage_change_with_stale_digest_fails_closed(self):
        replacement = (
            "f" * 64
            if self.revised_plan.revision_request_sha256 != "f" * 64
            else "e" * 64
        )

        with self.assertRaisesRegex(ValueError, "digest"):
            replace(
                self.revised_plan,
                revision_request_sha256=replacement,
            )

    def test_direct_content_change_with_stale_digest_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "digest"):
            replace(
                self.revised_plan,
                summary=self.revised_plan.summary + " Additional bounded context.",
            )


if __name__ == "__main__":
    unittest.main()
