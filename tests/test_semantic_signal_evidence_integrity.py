from __future__ import annotations

import unittest

from lightup.changes import (
    SemanticChangeSignal,
    SemanticSignalDirection,
    SemanticSignalKind,
)


class _EvidenceTuple(tuple):
    pass


class _EvidenceText(str):
    pass


class SemanticSignalEvidenceIntegrityTest(unittest.TestCase):
    def _signal(self, evidence_refs):
        return SemanticChangeSignal(
            signal_id="signal:one",
            object_path="openapi.yaml",
            kind=SemanticSignalKind.API_SURFACE,
            direction=SemanticSignalDirection.MODIFIED,
            summary="API route changed",
            evidence_refs=evidence_refs,
        )

    def _assert_rejected(self, evidence_refs):
        with self.assertRaisesRegex(ValueError, "evidence_refs"):
            self._signal(evidence_refs).validate()

    def test_exact_non_empty_tuple_of_exact_strings_remains_green(self):
        refs = ("content-sha256:" + "a" * 64, "content-sha256:" + "b" * 64)
        signal = self._signal(refs)

        signal.validate()

        self.assertIs(signal.evidence_refs, refs)

    def test_empty_tuple_remains_rejected(self):
        self._assert_rejected(())

    def test_list_container_is_rejected(self):
        self._assert_rejected(["content-sha256:" + "a" * 64])

    def test_tuple_subclass_is_rejected(self):
        self._assert_rejected(_EvidenceTuple(("content-sha256:" + "a" * 64,)))

    def test_non_string_member_is_rejected(self):
        self._assert_rejected(("content-sha256:" + "a" * 64, 7))

    def test_string_subclass_member_is_rejected(self):
        self._assert_rejected((_EvidenceText("content-sha256:" + "a" * 64),))

    def test_blank_member_is_rejected(self):
        self._assert_rejected(("   ",))

    def test_duplicate_members_are_rejected(self):
        ref = "content-sha256:" + "a" * 64
        self._assert_rejected((ref, ref))


if __name__ == "__main__":
    unittest.main()
