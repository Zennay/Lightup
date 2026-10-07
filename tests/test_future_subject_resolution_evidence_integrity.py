from __future__ import annotations

import unittest

from lightup.future_subject_resolution import (
    FutureSubjectResolution,
    SubjectResolutionBasis,
)


class _EvidenceTuple(tuple):
    pass


class _EvidenceText(str):
    pass


class FutureSubjectResolutionEvidenceIntegrityTest(unittest.TestCase):
    def _resolution(self, evidence_ids):
        return FutureSubjectResolution(
            decision_id="decision-1",
            client_id="client-1",
            changeset_id="changeset-1",
            change_node_id="change:node-1",
            subject_node_id="asset-1",
            run_id="run-1",
            basis=SubjectResolutionBasis.INTEGRATION_VERIFIED,
            evidence_ids=evidence_ids,
        )

    def _assert_rejected(self, evidence_ids):
        with self.assertRaisesRegex(ValueError, "evidence_ids"):
            self._resolution(evidence_ids).validate()

    def test_exact_non_empty_tuple_of_exact_strings_remains_green(self):
        refs = ("evidence-one", "evidence-two")
        resolution = self._resolution(refs)

        resolution.validate()

        self.assertIs(resolution.evidence_ids, refs)

    def test_list_container_is_rejected(self):
        self._assert_rejected(["evidence-one"])

    def test_tuple_subclass_is_rejected(self):
        self._assert_rejected(_EvidenceTuple(("evidence-one",)))

    def test_string_subclass_member_is_rejected(self):
        self._assert_rejected((_EvidenceText("evidence-one"),))

    def test_non_string_member_remains_rejected(self):
        self._assert_rejected(("evidence-one", 7))

    def test_existing_blank_identifier_rule_remains_rejected(self):
        self._assert_rejected(("   ",))

    def test_existing_duplicate_rule_remains_rejected(self):
        self._assert_rejected(("evidence-one", "evidence-one"))


if __name__ == "__main__":
    unittest.main()
