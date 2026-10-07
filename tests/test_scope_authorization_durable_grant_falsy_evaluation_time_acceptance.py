from __future__ import annotations

import unittest
from datetime import datetime, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition


def _wide_grant() -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id="grant-falsy-clock",
        client_id="client-1",
        engagement_id="engagement-1",
        approved_by="operator-1",
        reference="AUTH-FALSY-CLOCK",
        scope=ScopeDefinition(
            assets=("example.test",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        ),
        valid_from=datetime(2000, 1, 1, tzinfo=timezone.utc),
        valid_until=datetime(2100, 1, 1, tzinfo=timezone.utc),
    )


class DurableGrantFalsyEvaluationTimeAcceptanceTests(unittest.TestCase):
    def _assert_controlled_rejection(self, supplied: object) -> None:
        try:
            _wide_grant().is_current(supplied)  # type: ignore[arg-type]
        except Exception as exc:  # acceptance distinguishes controlled validation from accidental errors
            self.assertIs(type(exc), ValueError)
            self.assertIn("authorization time", str(exc))
        else:
            self.fail("malformed explicit authorization time must fail closed")

    def test_none_keeps_omitted_clock_semantics(self) -> None:
        self.assertTrue(_wide_grant().is_current(None))

    def test_exact_builtin_aware_datetime_remains_valid(self) -> None:
        now = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
        self.assertTrue(_wide_grant().is_current(now))

    def test_false_is_not_silently_replaced_with_wall_clock(self) -> None:
        self._assert_controlled_rejection(False)

    def test_zero_is_not_silently_replaced_with_wall_clock(self) -> None:
        self._assert_controlled_rejection(0)

    def test_empty_text_is_not_silently_replaced_with_wall_clock(self) -> None:
        self._assert_controlled_rejection("")

    def test_positive_integer_is_rejected_as_explicit_clock(self) -> None:
        self._assert_controlled_rejection(1)

    def test_nonempty_text_is_rejected_as_explicit_clock(self) -> None:
        self._assert_controlled_rejection("2026-10-07T12:00:00Z")

    def test_plain_object_is_rejected_as_explicit_clock(self) -> None:
        self._assert_controlled_rejection(object())


if __name__ == "__main__":
    unittest.main()
