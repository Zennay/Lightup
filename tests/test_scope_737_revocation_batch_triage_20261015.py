"""#737 batch triage acceptance: atomic structural validity, no authority."""
from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

from scripts.scope_737_revocation_batch_triage import review_revocation_batch


NOW = datetime(2026, 10, 15, 10, tzinfo=timezone.utc)


def record(at=None, actor=None, reason=None):
    return {"revoked_at": at, "revoked_by": actor, "revocation_reason": reason}


class EvilKey(str):
    def __hash__(self):
        return hash("revoked_at")

    def __eq__(self, other):
        return other == "revoked_at"


class EvilDict(dict):
    def keys(self):
        raise AssertionError("subclass dictionary invoked")


class EvilTuple(tuple):
    def __iter__(self):
        raise AssertionError("subclass iterator invoked")


class UntrustedObject:
    def __bool__(self):
        raise AssertionError("untrusted truthiness invoked")

    def __str__(self):
        raise AssertionError("private data leaked")


class BatchTriageTests(unittest.TestCase):
    def assertHold(self, r):
        self.assertEqual(r.decision, "HOLD")
        self.assertFalse(r.can_authorize)
        self.assertFalse(r.can_dispatch)
        self.assertFalse(r.can_release)

    def test_one_no_revocation_claim_is_still_hold(self):
        r = review_revocation_batch((record(),))
        self.assertHold(r)
        self.assertEqual(r.result, "review_only")
        self.assertEqual(r.classifications, ("no_revocation_claim",))
        self.assertEqual(dict(r.class_counts)["no_revocation_claim"], 1)

    def test_one_recorded_revocation_is_still_hold(self):
        r = review_revocation_batch((record(NOW, "fictional-actor", "fixture-reason"),))
        self.assertHold(r)
        self.assertEqual(r.classifications, ("revocation_recorded",))

    def test_stale_provenance_is_not_treated_as_current_authority(self):
        r = review_revocation_batch((record(actor="fictional-actor"),))
        self.assertHold(r)
        self.assertEqual(r.classifications, ("inconsistent",))

    def test_mixed_batch_has_stable_counts(self):
        rows = (
            record(),
            record(NOW, "fictional-actor", "fixture-reason"),
            record(actor="fictional-actor"),
            record(),
        )
        r = review_revocation_batch(rows)
        self.assertHold(r)
        self.assertEqual(r.class_counts, (
            ("inconsistent", 1),
            ("revocation_recorded", 1),
            ("no_revocation_claim", 2),
        ))
        self.assertEqual(len(r.classifications), 4)

    def test_batch_is_bounded_to_64(self):
        for size in (0, 65, 1000):
            with self.subTest(size=size):
                r = review_revocation_batch(tuple(record() for _ in range(size)))
                self.assertHold(r)
                self.assertEqual(r.result, "invalid_batch")
                self.assertEqual(r.classifications, ())
        r = review_revocation_batch(tuple(record() for _ in range(64)))
        self.assertHold(r)
        self.assertEqual(len(r.classifications), 64)

    def test_list_and_tuple_subclass_cannot_enter(self):
        for candidate in ([record()], EvilTuple((record(),)), (), False, "", 0):
            with self.subTest(t=type(candidate).__name__):
                r = review_revocation_batch(candidate)
                self.assertHold(r)
                self.assertEqual(r.result, "invalid_batch")

    def test_dict_subclass_cannot_override_entry_logic(self):
        r = review_revocation_batch((EvilDict(record()),))
        self.assertHold(r)
        self.assertEqual(r.reason_codes, ("noncanonical_batch_item",))

    def test_non_mapping_record_fails_entire_batch_atomically(self):
        for value in (None, False, 0, "x", [], tuple()):
            with self.subTest(t=type(value).__name__):
                r = review_revocation_batch((record(), value, record()))
                self.assertHold(r)
                self.assertEqual(r.result, "invalid_batch")
                self.assertEqual(r.classifications, ())
                self.assertEqual(r.class_counts, ())

    def test_missing_field_fails_entire_batch_atomically(self):
        for field in ("revoked_at", "revoked_by", "revocation_reason"):
            value = record()
            del value[field]
            r = review_revocation_batch((record(), value))
            self.assertHold(r)
            self.assertEqual(r.reason_codes, ("invalid_batch_schema",))
            self.assertEqual(r.classifications, ())

    def test_extra_field_fails_entire_batch_atomically(self):
        value = record()
        value["client_secret"] = "fictional-sensitive"
        r = review_revocation_batch((record(), value))
        self.assertHold(r)
        self.assertEqual(r.result, "invalid_batch")
        self.assertNotIn("fictional-sensitive", repr(r))

    def test_subclassed_string_key_cannot_spoof_known_field(self):
        value = record()
        value[EvilKey("foreign")] = value.pop("revoked_at")
        r = review_revocation_batch((value,))
        self.assertHold(r)
        self.assertEqual(r.reason_codes, ("noncanonical_batch_key",))

    def test_unexpected_key_with_correct_record_size_is_denied(self):
        value = record()
        value["not-an-authority"] = value.pop("revoked_by")
        r = review_revocation_batch((value,))
        self.assertHold(r)
        self.assertEqual(r.reason_codes, ("invalid_batch_schema",))

    def test_payload_object_does_not_execute_untrusted_callbacks(self):
        v = UntrustedObject()
        r = review_revocation_batch((record(v, v, v),))
        self.assertHold(r)
        self.assertEqual(r.classifications, ("inconsistent",))

    def test_raw_privacy_fields_never_appear_in_result(self):
        a = "fictional-secret-operator"
        why = "fictional-private-reason"
        r = review_revocation_batch((record(NOW, a, why),))
        self.assertHold(r)
        self.assertNotIn(a, repr(r))
        self.assertNotIn(why, repr(r))

    def test_inputs_not_mutated(self):
        rows = (record(NOW, "fictional-actor", "fixture-reason"),)
        snapshot = dict(rows[0])
        review_revocation_batch(rows)
        self.assertEqual(rows[0], snapshot)

    def test_result_is_frozen(self):
        r = review_revocation_batch((record(),))
        with self.assertRaises(FrozenInstanceError):
            r.can_release = True

    def test_even_all_consistent_records_cannot_authorize(self):
        rows = tuple(record(NOW, "fictional-actor", "fixture-reason") for _ in range(64))
        r = review_revocation_batch(rows)
        self.assertHold(r)
        self.assertEqual(r.class_counts[1], ("revocation_recorded", 64))

    def test_all_inconsistent_records_remain_hold(self):
        rows = tuple(record(reason="withdrawn") for _ in range(64))
        r = review_revocation_batch(rows)
        self.assertHold(r)
        self.assertEqual(r.class_counts[0], ("inconsistent", 64))


if __name__ == "__main__":
    unittest.main()
