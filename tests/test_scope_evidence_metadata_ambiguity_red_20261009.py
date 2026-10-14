"""Isolated RED contract for non-ambiguous handler evidence metadata.

Never invokes ToolExecutor, handlers, StateStore, network or real targets.
"""
import unittest
from lightup.ai.orchestration import ToolOutput


_RESERVED = frozenset({"asset", "client_id", "engagement_id", "mode", "is_lab"})


def metadata_is_canonical(output: ToolOutput) -> bool:
    """Reference admission check; not production enforcement."""
    if type(output) is not ToolOutput or type(output.metadata) is not tuple:
        return False
    seen = set()
    for pair in output.metadata:
        if type(pair) is not tuple or len(pair) != 2:
            return False
        key, value = pair
        if type(key) is not str or type(value) is not str:
            return False
        if key in seen or key in _RESERVED:
            return False
        seen.add(key)
    return True


class EvidenceMetadataContract(unittest.TestCase):
    def make_output(self, metadata):
        return ToolOutput(summary="synthetic", evidence_kind="offline", evidence_payload=b"fixture", metadata=metadata)

    def test_unique_nonreserved_metadata_is_admissible(self):
        self.assertTrue(metadata_is_canonical(self.make_output((("finding", "synthetic"),))))

    def test_duplicate_keys_are_rejected_by_reference(self):
        self.assertFalse(metadata_is_canonical(self.make_output((("finding", "first"), ("finding", "second")))))

    def test_reserved_identity_is_rejected_by_reference(self):
        self.assertFalse(metadata_is_canonical(self.make_output((("asset", "untrusted"),))))

    def test_malformed_pair_is_rejected_by_reference(self):
        self.assertFalse(metadata_is_canonical(self.make_output((("finding", "valid", "extra"),))))

    @unittest.expectedFailure
    def test_production_projection_must_not_silently_collapse_duplicate_metadata(self):
        # Current ToolExecutor uses dict(output.metadata), which loses duplicates.
        output = self.make_output((("finding", "first"), ("finding", "second")))
        self.assertEqual(len(dict(output.metadata)), len(output.metadata))

    @unittest.expectedFailure
    def test_production_projection_must_preserve_every_reserved_key_collision(self):
        # A reserved key is overwritten by trusted context; it should instead
        # be rejected before evidence write for unambiguous provenance.
        output = self.make_output((("asset", "forged"),))
        self.assertFalse(metadata_is_canonical(output))
        self.assertNotIn("asset", dict(output.metadata))


if __name__ == "__main__":
    unittest.main()
