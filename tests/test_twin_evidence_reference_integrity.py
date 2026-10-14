from __future__ import annotations

import unittest

from lightup.twin import (
    AttackPath,
    AttackStep,
    FactProvenance,
    TwinFact,
    TwinRelationship,
)


class _EvidenceTuple(tuple):
    pass


class _EvidenceText(str):
    pass


class SecurityTwinEvidenceReferenceIntegrityTest(unittest.TestCase):
    def _objects(self, evidence_refs):
        return (
            TwinFact(
                "fact-1",
                "node-1",
                "predicate",
                "value",
                FactProvenance.OBSERVED,
                1.0,
                evidence_refs,
            ),
            TwinRelationship(
                "rel-1",
                "node-1",
                "node-2",
                "related_to",
                FactProvenance.OBSERVED,
                1.0,
                evidence_refs,
            ),
            AttackStep(
                "node-1",
                "node-2",
                "related_to",
                evidence_refs,
            ),
            AttackPath(
                "path-1",
                "Synthetic path",
                (AttackStep("node-1", "node-2", "related_to"),),
                evidence_refs,
            ),
        )

    def _assert_all_reject(self, evidence_refs):
        for value in self._objects(evidence_refs):
            with self.subTest(type=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "evidence_refs"):
                    value.validate()

    def test_exact_tuple_of_exact_nonblank_strings_is_canonical(self):
        refs = ("evidence:one", "evidence:two")

        for value in self._objects(refs):
            with self.subTest(type=type(value).__name__):
                value.validate()
                self.assertIs(value.evidence_refs, refs)

    def test_empty_tuple_remains_valid_where_evidence_is_optional(self):
        for value in self._objects(()):
            with self.subTest(type=type(value).__name__):
                value.validate()
                self.assertEqual(value.evidence_refs, ())

    def test_verified_fact_and_relationship_still_require_evidence(self):
        fact = TwinFact(
            "fact-verified",
            "node-1",
            "predicate",
            "value",
            FactProvenance.VERIFIED,
            1.0,
            (),
        )
        relationship = TwinRelationship(
            "rel-verified",
            "node-1",
            "node-2",
            "related_to",
            FactProvenance.VERIFIED,
            1.0,
            (),
        )

        with self.assertRaisesRegex(ValueError, "require evidence_refs"):
            fact.validate()
        with self.assertRaisesRegex(ValueError, "require evidence_refs"):
            relationship.validate()

    def test_list_container_is_rejected_instead_of_normalized(self):
        self._assert_all_reject(["evidence:one"])

    def test_tuple_subclass_is_rejected(self):
        self._assert_all_reject(_EvidenceTuple(("evidence:one",)))

    def test_string_subclass_reference_is_rejected(self):
        self._assert_all_reject((_EvidenceText("evidence:one"),))

    def test_blank_reference_is_rejected(self):
        self._assert_all_reject(("   ",))

    def test_duplicate_references_are_rejected(self):
        self._assert_all_reject(("evidence:duplicate", "evidence:duplicate"))


if __name__ == "__main__":
    unittest.main()
