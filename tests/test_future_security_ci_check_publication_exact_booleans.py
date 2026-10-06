from __future__ import annotations

import dataclasses
import unittest

import test_future_security_ci_check_publication as publication_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_ci_check_publication import (
    publish_future_security_ci_verdict_check,
)


class FutureSecurityCIPublicationExactBooleanTest(unittest.TestCase):
    def setUp(self):
        self.fixture_owner = publication_tests.FutureSecurityCICheckPublicationTest(
            "test_all_four_verdicts_map_to_exact_github_check_conclusions"
        )
        self.fixture_owner.setUp()
        self.addCleanup(self.fixture_owner.doCleanups)
        self.publisher = publication_tests.FakeGitHubCheckPublisher()

    def _inputs(self, suffix):
        return self.fixture_owner._fixture(
            AttackPathTransitionClassification.IMPROVED,
            suffix=suffix,
        )

    def test_reporting_authority_rejects_truthy_non_booleans(self):
        for value in (1, "false"):
            with self.subTest(value=value):
                inputs = self._inputs(f"exact-reporting-{type(value).__name__}")
                inputs["authorization"] = dataclasses.replace(
                    inputs["authorization"],
                    reporting_allowed=value,
                )

                with self.assertRaisesRegex(
                    ValueError,
                    r"authorization\.reporting_allowed must be an exact bool",
                ):
                    publish_future_security_ci_verdict_check(
                        publisher=self.publisher,
                        **inputs,
                    )

        self.assertEqual(self.publisher.calls, 0)

    def test_non_merge_authority_rejects_falsey_non_booleans(self):
        for field, value in (("merge_allowed", 0), ("deployment_allowed", "")):
            with self.subTest(field=field):
                inputs = self._inputs(f"exact-auth-{field}")
                inputs["authorization"] = dataclasses.replace(
                    inputs["authorization"],
                    **{field: value},
                )

                with self.assertRaisesRegex(
                    ValueError,
                    rf"authorization\.{field} must be an exact bool",
                ):
                    publish_future_security_ci_verdict_check(
                        publisher=self.publisher,
                        **inputs,
                    )

        self.assertEqual(self.publisher.calls, 0)

    def test_verdict_authority_flags_reject_falsey_non_booleans(self):
        cases = (
            ("deployment_authorized", 0),
            ("attack_path_mutation_allowed", ""),
        )
        for field, value in cases:
            with self.subTest(field=field):
                inputs = self._inputs(f"exact-verdict-{field}")
                inputs["decision"] = dataclasses.replace(
                    inputs["decision"],
                    **{field: value},
                )

                with self.assertRaisesRegex(
                    ValueError,
                    rf"decision\.{field} must be an exact bool",
                ):
                    publish_future_security_ci_verdict_check(
                        publisher=self.publisher,
                        **inputs,
                    )

        self.assertEqual(self.publisher.calls, 0)

    def test_exact_false_merge_and_deployment_flags_remain_valid(self):
        inputs = self._inputs("exact-canonical-bools")

        receipt = publish_future_security_ci_verdict_check(
            publisher=self.publisher,
            **inputs,
        )

        self.assertEqual(self.publisher.calls, 1)
        self.assertFalse(receipt.merge_authorized)
        self.assertFalse(receipt.deployment_authorized)


if __name__ == "__main__":
    unittest.main()
