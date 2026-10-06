from __future__ import annotations

import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy


class LegacyAuthorizationProvenanceAcceptanceTest(unittest.TestCase):
    @staticmethod
    def _policy() -> ScopePolicy:
        return ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            require_authorization_for_public=True,
        )

    def _assert_invalid_provenance_rejected(self, **overrides: object) -> None:
        values: dict[str, object] = {
            "owner": "client-owner",
            "reference": "client-auth-ref",
        }
        values.update(overrides)
        authorization = Authorization(
            owner=values["owner"],  # type: ignore[arg-type]
            reference=values["reference"],  # type: ignore[arg-type]
            assets=("security.example.test",),
        )
        try:
            decision = self._policy().decide(
                Target("security.example.test", authorization=authorization)
            )
        except (TypeError, ValueError):
            return
        if decision.allowed:
            self.fail("invalid legacy authorization provenance was accepted")

    def test_invalid_owner_provenance_fails_closed(self):
        for value in ("", "   ", 123):
            with self.subTest(value=value):
                self._assert_invalid_provenance_rejected(owner=value)

    def test_invalid_reference_provenance_fails_closed(self):
        for value in ("", "   ", 123):
            with self.subTest(value=value):
                self._assert_invalid_provenance_rejected(reference=value)

    def test_canonical_provenance_keeps_public_host_authorized(self):
        decision = self._policy().decide(
            Target(
                "security.example.test",
                authorization=Authorization(
                    owner="client-owner",
                    reference="client-auth-ref",
                    assets=("security.example.test",),
                ),
            )
        )
        self.assertTrue(decision.allowed)


if __name__ == "__main__":
    unittest.main()
