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


class _EqualitySpoofString(str):
    """Stored text can disagree with the value exposed through equality."""

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False


class _TupleSubclass(tuple):
    pass


class FutureRemediationImplementationPlanRevisionRequestDirectMetadataTypesTest(
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

    def test_canonical_request_uses_exact_builtin_metadata_types(self):
        self.assertIs(type(self.request.schema_version), str)
        self.assertIs(type(self.request.required_revisions), tuple)
        self.assertTrue(
            all(type(item) is str for item in self.request.required_revisions)
        )
        self.assertIs(type(self.request.source_review_decision), str)
        self.assertIs(type(self.request.future_semantics), str)
        self.assertIs(type(self.request.security_verdict), str)

    def test_schema_version_string_subclass_fails_closed(self):
        with self.assertRaises(ValueError):
            replace(
                self.request,
                schema_version=_EqualitySpoofString("st5.invalid.schema"),
            )

    def test_required_revisions_tuple_subclass_fails_closed(self):
        with self.assertRaises(ValueError):
            replace(
                self.request,
                required_revisions=_TupleSubclass(self.request.required_revisions),
            )

    def test_source_review_decision_string_subclass_fails_closed(self):
        with self.assertRaises(ValueError):
            replace(
                self.request,
                source_review_decision=_EqualitySpoofString("approved"),
            )

    def test_future_semantics_string_subclass_fails_closed(self):
        with self.assertRaises(ValueError):
            replace(
                self.request,
                future_semantics=_EqualitySpoofString("resolved"),
            )

    def test_security_verdict_string_subclass_fails_closed(self):
        with self.assertRaises(ValueError):
            replace(
                self.request,
                security_verdict=_EqualitySpoofString("pass"),
            )


if __name__ == "__main__":
    unittest.main()
