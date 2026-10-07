from __future__ import annotations

from dataclasses import replace
import unittest

from lightup.future_remediation_implementation_plan_review_request import (
    REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
)
from lightup.future_remediation_implementation_plan_revision_request import (
    REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION,
    FutureRemediationImplementationPlanRevisionRequest,
    _revision_request_digest,
)


class _StringSubclass(str):
    pass


class FutureRemediationImplementationPlanRevisionRequestCheckStringTypesTest(
    unittest.TestCase
):
    def setUp(self):
        required_revisions = (REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[0],)
        digest = _revision_request_digest(
            review_sha256="1" * 64,
            review_request_sha256="2" * 64,
            plan_sha256="3" * 64,
            implementation_request_sha256="4" * 64,
            reviewer_provider_id="provider",
            reviewer_model_id="model",
            required_revisions=required_revisions,
        )
        self.request = FutureRemediationImplementationPlanRevisionRequest(
            schema_version=(
                REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION
            ),
            review_sha256="1" * 64,
            review_request_sha256="2" * 64,
            plan_sha256="3" * 64,
            implementation_request_sha256="4" * 64,
            reviewer_provider_id="provider",
            reviewer_model_id="model",
            required_revisions=required_revisions,
            revision_request_sha256=digest,
        )

    def test_canonical_required_revision_items_are_exact_strings(self):
        self.assertTrue(
            all(type(item) is str for item in self.request.required_revisions)
        )

    def test_required_revision_string_subclass_fails_closed(self):
        subclassed = (_StringSubclass(self.request.required_revisions[0]),)

        with self.assertRaises(ValueError):
            replace(self.request, required_revisions=subclassed)


if __name__ == "__main__":
    unittest.main()
