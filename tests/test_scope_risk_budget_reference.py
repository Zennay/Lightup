"""Offline reference: a budget is consumed only by exact authorized attempts.

This is NOT a production authorization implementation or permission grant.
No sockets, targets, or executor imports are used.
"""
from dataclasses import dataclass, replace
import re
import unittest


@dataclass(frozen=True)
class Budget:
    tenant: str
    request: str
    revision: int
    limit: int
    used: int
    active: bool


@dataclass(frozen=True)
class Attempt:
    tenant: str
    request: str
    revision: int
    units: int
    approved: bool


_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\\Z", re.ASCII)


def reserve(budget: Budget, attempt: Attempt):
    """Return a new budget or None, failing closed on malformed or exhausted state."""
    if type(budget) is not Budget or type(attempt) is not Attempt:
        return None
    if any(type(v) is not str or _IDENTITY.fullmatch(v) is None
           for v in (budget.tenant, budget.request, attempt.tenant, attempt.request)):
        return None
    if any(type(v) is not int for v in
           (budget.revision, budget.limit, budget.used, attempt.revision, attempt.units)):
        return None
    if type(budget.active) is not bool or type(attempt.approved) is not bool:
        return None
    if not budget.active or not attempt.approved:
        return None
    if budget.revision < 1 or budget.limit < 1 or budget.used < 0 or attempt.units < 1:
        return None
    if budget.used > budget.limit:
        return None
    if (budget.tenant, budget.request, budget.revision) != (
        attempt.tenant, attempt.request, attempt.revision
    ):
        return None
    if attempt.units > budget.limit - budget.used:
        return None
    return replace(budget, used=budget.used + attempt.units)


class RiskBudgetReferenceTests(unittest.TestCase):
    def setUp(self):
        self.budget = Budget("tenant-a", "request-a", 3, 5, 1, True)
        self.attempt = Attempt("tenant-a", "request-a", 3, 2, True)

    def test_reservation_consumes_exact_units_without_mutation(self):
        result = reserve(self.budget, self.attempt)
        self.assertEqual(result.used, 3)
        self.assertEqual(self.budget.used, 1)

    def test_exact_boundary_and_exhaustion(self):
        full = reserve(self.budget, replace(self.attempt, units=4))
        self.assertEqual(full.used, 5)
        self.assertIsNone(reserve(full, self.attempt))

    def test_over_budget_or_zero_or_negative_units_denied(self):
        for n in (0, -1, 5, 999):
            with self.subTest(n=n):
                self.assertIsNone(reserve(self.budget, replace(self.attempt, units=n)))

    def test_tenant_request_revision_changes_denied(self):
        for change in ({"tenant": "tenant-b"}, {"request": "request-b"}, {"revision": 4}):
            self.assertIsNone(reserve(self.budget, replace(self.attempt, **change)))

    def test_inactive_or_unapproved_denied(self):
        self.assertIsNone(reserve(replace(self.budget, active=False), self.attempt))
        self.assertIsNone(reserve(self.budget, replace(self.attempt, approved=False)))

    def test_truthy_flags_denied(self):
        self.assertIsNone(reserve(replace(self.budget, active=1), self.attempt))
        self.assertIsNone(reserve(self.budget, replace(self.attempt, approved=1)))

    def test_boolean_numeric_type_confusion_denied(self):
        for change in ({"units": True}, {"revision": True}):
            self.assertIsNone(reserve(self.budget, replace(self.attempt, **change)))
        self.assertIsNone(reserve(replace(self.budget, limit=True), self.attempt))

    def test_invalid_budget_state_denied(self):
        for change in ({"used": -1}, {"used": 6}, {"limit": 0}, {"revision": 0}):
            self.assertIsNone(reserve(replace(self.budget, **change), self.attempt))

    def test_noncanonical_identity_denied(self):
        for value in ("", "ténant", "x" * 129):
            with self.subTest(value=value):
                self.assertIsNone(reserve(replace(self.budget, tenant=value), self.attempt))

    def test_identity_controls_whitespace_and_invisible_aliases_denied(self):
        for value in (" tenant-a", "tenant-a ", "tenant\\na", "tenant\\ra",
                      "tenant\\x00a", "tenant\\x7fa", "tenant/a",
                      "tenant:a", "tenant\\u200ba", "tenant\\u202ea"):
            with self.subTest(value=repr(value)):
                self.assertIsNone(reserve(replace(self.budget, tenant=value), self.attempt))
                self.assertIsNone(reserve(self.budget, replace(self.attempt, request=value)))

    def test_budget_and_attempt_wrong_type_fields_denied(self):
        for value in (None, 1, b"tenant-a", ["tenant-a"]):
            with self.subTest(value=repr(value)):
                self.assertIsNone(reserve(replace(self.budget, request=value), self.attempt))
                self.assertIsNone(reserve(self.budget, replace(self.attempt, tenant=value)))

    def test_units_are_never_implicitly_coerced(self):
        for value in (2.0, "2", None, b"2", [2]):
            with self.subTest(value=repr(value)):
                self.assertIsNone(reserve(self.budget, replace(self.attempt, units=value)))

    def test_overspent_budget_not_repaired_by_new_attempt(self):
        self.assertIsNone(reserve(replace(self.budget, used=6), replace(self.attempt, units=1)))

    def test_sequential_spending_accumulates_with_no_oversubscription(self):
        current = self.budget
        for units, expected in ((1, 2), (1, 3), (2, 5)):
            current = reserve(current, replace(self.attempt, units=units))
            self.assertIsNotNone(current)
            self.assertEqual(current.used, expected)
        self.assertIsNone(reserve(current, replace(self.attempt, units=1)))
        self.assertEqual(self.budget.used, 1)

    def test_revision_change_cannot_reuse_budget_snapshot(self):
        increased_revision = replace(self.attempt, revision=4)
        self.assertIsNone(reserve(self.budget, increased_revision))
        self.assertIsNone(reserve(replace(self.budget, revision=4, active=False), increased_revision))

    def test_spending_is_monotonic_for_valid_sequential_calls(self):
        current = replace(self.budget, used=0)
        history = [current.used]
        for _ in range(5):
            current = reserve(current, replace(self.attempt, units=1))
            self.assertIsNotNone(current)
            history.append(current.used)
        self.assertEqual(history, [0, 1, 2, 3, 4, 5])
        self.assertIsNone(reserve(current, replace(self.attempt, units=1)))

    def test_polymorphic_envelopes_denied(self):
        class SubBudget(Budget):
            pass
        class SubAttempt(Attempt):
            pass
        self.assertIsNone(reserve(SubBudget(**vars(self.budget)), self.attempt))
        self.assertIsNone(reserve(self.budget, SubAttempt(**vars(self.attempt))))


if __name__ == "__main__":
    unittest.main()
