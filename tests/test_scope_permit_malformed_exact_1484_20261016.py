"""Second-wave malformed exact-instance quarantine (#1484); synthetic-only."""
from __future__ import annotations

from datetime import datetime, timezone
import unittest

from lightup.activation import ActivationMode, ExecutionPermit
from lightup.permit_claim_review_1484 import review_fictional_permit_claim_batch

CLOCK = datetime(2026, 10, 16, 10, tzinfo=timezone.utc)
TOKEN = "a" * 32

def valid():
    return ExecutionPermit(
        permit_id=TOKEN,
        target="localhost",
        capability_id="lab.review",
        mode=ActivationMode.LAB_ONLY,
        activation_reference="LAB",
        issued_at=CLOCK,
    )

def review(*claims):
    return review_fictional_permit_claim_batch(tuple(claims), review_cutoff=CLOCK)

class MalformedExactPermit1484Tests(unittest.TestCase):
    def assertAtomicHold(self, result):
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.reason_code, "invalid_claim")
        self.assertEqual(result.inspected, 0)
        self.assertIs(result.execution_allowed, False)
        self.assertIs(result.release_allowed, False)

    def test_empty_exact_dataclass_constructed_without_init(self):
        crafted = object.__new__(ExecutionPermit)
        self.assertAtomicHold(review(crafted))

    def test_single_missing_field_is_not_an_exception(self):
        crafted = valid()
        object.__delattr__(crafted, "capability_id")
        self.assertAtomicHold(review(crafted))

    def test_all_fields_but_issued_at_is_still_hold(self):
        crafted = valid()
        object.__delattr__(crafted, "issued_at")
        self.assertAtomicHold(review(crafted))

    def test_injected_approval_marker_disallows_entire_record(self):
        crafted = valid()
        object.__setattr__(crafted, "approved", True)
        self.assertAtomicHold(review(crafted))

    def test_injected_authority_marker_disallows_entire_record(self):
        crafted = valid()
        object.__setattr__(crafted, "authorized", True)
        self.assertAtomicHold(review(crafted))

    def test_injected_execution_override_disallows_entire_record(self):
        crafted = valid()
        object.__setattr__(crafted, "execution_allowed", True)
        self.assertAtomicHold(review(crafted))

    def test_injected_unknown_empty_attribute_is_denied(self):
        crafted = valid()
        object.__setattr__(crafted, "other", None)
        self.assertAtomicHold(review(crafted))

    def test_malformed_after_valid_is_atomic(self):
        self.assertAtomicHold(review(valid(), object.__new__(ExecutionPermit)))

    def test_malformed_before_valid_is_atomic(self):
        self.assertAtomicHold(review(object.__new__(ExecutionPermit), valid()))

    def test_reordered_fields_are_allowed_only_as_shape(self):
        crafted = valid()
        values = crafted.__dict__
        saved = list(values.items())
        values.clear()
        values.update(reversed(saved))
        outcome = review(crafted)
        self.assertEqual(outcome.status, "REVIEW_ONLY")
        self.assertFalse(outcome.execution_allowed)
        self.assertFalse(outcome.release_allowed)

    def test_normal_claim_can_never_be_represented_as_permission(self):
        outcome = review(valid())
        self.assertEqual(outcome.status, "REVIEW_ONLY")
        self.assertEqual(outcome.inspected, 1)
        self.assertFalse(outcome.execution_allowed)
        self.assertFalse(outcome.release_allowed)


if __name__ == "__main__":
    unittest.main()
