from __future__ import annotations

import unittest

from lightup.future_materialization import (
    EnvironmentEquivalence,
    FutureMaterializationResolution,
    MaterializationOutcome,
)


class _EvidenceTuple(tuple):
    pass


class _EvidenceText(str):
    pass


class FutureMaterializationEvidenceIntegrityTest(unittest.TestCase):
    def _resolution(self, evidence_ids):
        return FutureMaterializationResolution(
            resolution_id="resolution-1",
            client_id="client-1",
            changeset_id="changeset-1",
            change_node_id="change:node-1",
            run_id="run-1",
            outcome=MaterializationOutcome.CONFIRMED,
            equivalence=EnvironmentEquivalence.REPRESENTATIVE,
            evidence_ids=evidence_ids,
            capability_ids=("web",),
        )

    def _assert_rejected(self, evidence_ids):
        with self.assertRaisesRegex(ValueError, "evidence"):
            self._resolution(evidence_ids).validate()

    def test_exact_non_empty_tuple_of_exact_strings_remains_green(self):
        refs = ("evidence-one", "evidence-two")
        resolution = self._resolution(refs)

        resolution.validate()

        self.assertIs(resolution.evidence_ids, refs)

    def test_empty_tuple_remains_rejected(self):
        self._assert_rejected(())

    def test_list_container_is_rejected(self):
        self._assert_rejected(["evidence-one"])

    def test_tuple_subclass_is_rejected(self):
        self._assert_rejected(_EvidenceTuple(("evidence-one",)))

    def test_non_string_member_is_rejected_before_stringification(self):
        self._assert_rejected(("evidence-one", 7))

    def test_string_subclass_member_is_rejected(self):
        self._assert_rejected((_EvidenceText("evidence-one"),))

    def test_blank_member_is_rejected(self):
        self._assert_rejected(("   ",))

    def test_duplicate_members_are_rejected(self):
        self._assert_rejected(("evidence-one", "evidence-one"))


if __name__ == "__main__":
    unittest.main()
