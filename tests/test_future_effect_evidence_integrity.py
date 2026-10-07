from __future__ import annotations

import unittest

from lightup.future_effects import (
    FutureSecurityEffect,
    RiskDirection,
    SecurityEffectKind,
)


class _EvidenceTuple(tuple):
    pass


class _EvidenceText(str):
    pass


class FutureSecurityEffectEvidenceIntegrityTest(unittest.TestCase):
    def _effect(self, evidence_ids):
        return FutureSecurityEffect(
            effect_id="effect-1",
            resolution_id="resolution-1",
            client_id="client-1",
            changeset_id="changeset-1",
            change_node_id="change:node-1",
            capability_id="web",
            kind=SecurityEffectKind.ATTACK_SURFACE_ADDED,
            risk_direction=RiskDirection.INCREASED,
            evidence_ids=evidence_ids,
        )

    def _assert_rejected(self, evidence_ids):
        with self.assertRaisesRegex(ValueError, "evidence_ids"):
            self._effect(evidence_ids).validate()

    def test_exact_non_empty_tuple_of_exact_strings_remains_green(self):
        refs = ("evidence-one", "evidence-two")
        effect = self._effect(refs)

        effect.validate()

        self.assertIs(effect.evidence_ids, refs)

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
