from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_implementation_plan_revision_review_request as request_tests


class _EqualitySpoofString(str):
    """A str subclass whose stored value disagrees with equality-visible value."""

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False


class _EqualitySpoofTuple(tuple):
    """A tuple subclass whose stored items disagree with equality-visible value."""

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False


class FutureRemediationImplementationPlanRevisionReviewRequestMetadataTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            request_tests.FutureRemediationImplementationPlanRevisionReviewRequestTest(
                "test_live_valid_revised_plan_produces_review_only_request"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def test_canonical_builder_output_uses_exact_builtin_metadata_types(self):
        self.assertIs(type(self.request.schema_version), str)
        self.assertIs(type(self.request.required_checks), tuple)
        self.assertIs(type(self.request.future_semantics), str)
        self.assertIs(type(self.request.security_verdict), str)

    def test_schema_version_string_subclass_fails_closed(self):
        with self.assertRaises(ValueError):
            replace(
                self.request,
                schema_version=_EqualitySpoofString("st5.invalid.schema"),
            )

    def test_required_checks_tuple_subclass_fails_closed(self):
        with self.assertRaises(ValueError):
            replace(
                self.request,
                required_checks=_EqualitySpoofTuple(("not-the-review-rubric",)),
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
