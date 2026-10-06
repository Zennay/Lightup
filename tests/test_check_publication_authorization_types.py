from __future__ import annotations

import dataclasses
from types import SimpleNamespace
import unittest

from lightup.future_security_ci_check_publication import (
    GitHubCheckPublicationAuthorization,
    _validate_authorization,
)


class GitHubCheckPublicationAuthorizationTypeTest(unittest.TestCase):
    REPOSITORY = "Zennay/Lightup"
    SOURCE_SHA = "a" * 40
    VERDICT_SHA256 = "b" * 64

    def setUp(self):
        self.authorization = GitHubCheckPublicationAuthorization(
            client_id="client-1",
            repository=self.REPOSITORY,
            source_sha=self.SOURCE_SHA,
            verdict_sha256=self.VERDICT_SHA256,
            reporting_allowed=True,
            merge_allowed=False,
            deployment_allowed=False,
        )
        self.decision = SimpleNamespace(
            client_id="client-1",
            verdict_sha256=self.VERDICT_SHA256,
            deployment_authorized=False,
            attack_path_mutation_allowed=False,
            future_semantics="unresolved",
        )

    def validate(self, *, authorization=None, decision=None):
        _validate_authorization(
            authorization=authorization or self.authorization,
            decision=decision or self.decision,
            repository=self.REPOSITORY,
            source_sha=self.SOURCE_SHA,
        )

    def test_exact_boolean_authority_contract_is_accepted(self):
        self.validate()

    def test_reporting_authority_rejects_truthy_non_booleans(self):
        for value in (1, "false", object()):
            with self.subTest(value=value):
                authorization = dataclasses.replace(
                    self.authorization,
                    reporting_allowed=value,
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "authorization.reporting_allowed must be an exact boolean",
                ):
                    self.validate(authorization=authorization)

    def test_negative_authority_flags_reject_falsy_non_booleans(self):
        for field in ("merge_allowed", "deployment_allowed"):
            for value in (0, "", None):
                with self.subTest(field=field, value=value):
                    authorization = dataclasses.replace(
                        self.authorization,
                        **{field: value},
                    )
                    with self.assertRaisesRegex(
                        ValueError,
                        f"authorization.{field} must be an exact boolean",
                    ):
                        self.validate(authorization=authorization)

    def test_verdict_authority_flags_reject_falsy_non_booleans(self):
        for field in ("deployment_authorized", "attack_path_mutation_allowed"):
            for value in (0, "", None):
                with self.subTest(field=field, value=value):
                    decision = SimpleNamespace(**vars(self.decision))
                    setattr(decision, field, value)
                    with self.assertRaisesRegex(
                        ValueError,
                        f"decision.{field} must be an exact boolean",
                    ):
                        self.validate(decision=decision)


if __name__ == "__main__":
    unittest.main()
