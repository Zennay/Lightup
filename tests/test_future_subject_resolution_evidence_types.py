from __future__ import annotations

import dataclasses
import unittest

import test_future_subject_resolution as subject_tests


class _TupleSubclass(tuple):
    pass


class _StringSubclass(str):
    pass


class FutureSubjectResolutionEvidenceTypeTest(unittest.TestCase):
    def setUp(self):
        self.t = subject_tests.FutureSubjectResolutionTest(
            "test_verified_subject_resolution_preserves_candidate_and_attack_paths"
        )
        self.t.setUp()
        self.addCleanup(self.t.tearDown)

    def test_exact_tuple_and_exact_string_remain_valid(self):
        self.assertIs(type(self.t.resolution.evidence_ids), tuple)
        self.assertIs(type(self.t.resolution.evidence_ids[0]), str)
        self.t.resolution.validate()

    def test_list_and_tuple_subclass_fail_closed(self):
        malformed_values = (
            [self.t.evidence_id],
            _TupleSubclass((self.t.evidence_id,)),
        )
        for malformed in malformed_values:
            with self.subTest(container_type=type(malformed).__name__):
                candidate = dataclasses.replace(
                    self.t.resolution,
                    evidence_ids=malformed,
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "evidence_ids must be an exact built-in tuple",
                ):
                    candidate.validate()

    def test_string_subclass_fails_closed_before_bounded_string_validation(self):
        candidate = dataclasses.replace(
            self.t.resolution,
            evidence_ids=(_StringSubclass(self.t.evidence_id),),
        )
        with self.assertRaisesRegex(
            ValueError,
            "evidence_ids must contain exact built-in strings",
        ):
            candidate.validate()

    def test_rejected_shape_does_not_repair_or_mutate_input(self):
        malformed = [_StringSubclass(self.t.evidence_id)]
        candidate = dataclasses.replace(
            self.t.resolution,
            evidence_ids=malformed,
        )
        before = list(malformed)

        with self.assertRaises(ValueError):
            candidate.validate()

        self.assertEqual(malformed, before)
        self.assertIs(candidate.evidence_ids, malformed)


if __name__ == "__main__":
    unittest.main()
