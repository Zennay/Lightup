"""Stdlib-only synthetic acceptance tests for the offline manifest reference."""
import copy
import hashlib
import unittest
from lightup.evidence_manifest_reference import verify_artifact_manifest


def record(data=b"fixed"):
    return {"artifact_id": "proof-1", "media_type": "application/json",
            "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def fixture():
    return {"tenant_id": "tenant-a", "finding_id": "finding-a",
            "remediation_id": "fix-a", "artifacts": [record()]}, {"proof-1": b"fixed"}


class EvidenceManifestReferenceTests(unittest.TestCase):
    def test_matching_manifest(self):
        self.assertTrue(verify_artifact_manifest(*fixture()))

    def test_tamper_denied(self):
        m, b = fixture()
        b["proof-1"] = b"altered"
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_missing_blob_denied(self):
        m, b = fixture()
        self.assertFalse(verify_artifact_manifest(m, {}))

    def test_extra_blob_denied(self):
        m, b = fixture()
        b["unexpected"] = b"secret"
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_duplicate_artifact_denied(self):
        m, b = fixture()
        m["artifacts"].append(copy.deepcopy(m["artifacts"][0]))
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_digest_case_denied(self):
        m, b = fixture()
        m["artifacts"][0]["sha256"] = m["artifacts"][0]["sha256"].upper()
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_bool_size_denied(self):
        m, b = fixture()
        m["artifacts"][0]["size"] = True
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_unknown_mime_denied(self):
        m, b = fixture()
        m["artifacts"][0]["media_type"] = "text/html"
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_identity_type_denied(self):
        m, b = fixture()
        m["tenant_id"] = 123
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_extra_manifest_keys_denied(self):
        m, b = fixture()
        m["trusted"] = True
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_no_artifacts_denied(self):
        m, b = fixture()
        m["artifacts"] = []
        self.assertFalse(verify_artifact_manifest(m, {}))

    def test_caller_input_unchanged(self):
        m, b = fixture()
        before_m, before_b = copy.deepcopy(m), copy.deepcopy(b)
        verify_artifact_manifest(m, b)
        self.assertEqual(m, before_m)
        self.assertEqual(b, before_b)

    def test_reject_dict_subclass(self):
        m, b = fixture()
        self.assertFalse(verify_artifact_manifest(type("FakeDict", (dict,), {})(m), b))

    def test_empty_blob_valid_when_declared(self):
        m, b = fixture()
        m["artifacts"] = [record(b"")]
        b["proof-1"] = b""
        self.assertTrue(verify_artifact_manifest(m, b))


    def test_blob_bytearray_denied(self):
        m, b = fixture()
        b["proof-1"] = bytearray(b"fixed")
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_nested_dict_subclass_denied(self):
        m, b = fixture()
        m["artifacts"][0] = type("PretendArtifact", (dict,), {})(m["artifacts"][0])
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_oversized_declared_artifact_denied(self):
        m, b = fixture()
        m["artifacts"][0]["size"] = 1048577
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_oversized_artifact_count_denied(self):
        m, b = fixture()
        m["artifacts"] = [
            {"artifact_id": f"item-{n}", "media_type": "text/plain",
             "size": 0, "sha256": hashlib.sha256(b"").hexdigest()}
            for n in range(33)
        ]
        blobs = {f"item-{n}": b"" for n in range(33)}
        self.assertFalse(verify_artifact_manifest(m, blobs))

    def test_noncanonical_unicode_identity_denied(self):
        m, b = fixture()
        m["finding_id"] = "finding-é"
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_zero_width_identity_denied(self):
        m, b = fixture()
        m["remediation_id"] = "fix-\u200b1"
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_wrong_artifact_list_container_denied(self):
        m, b = fixture()
        m["artifacts"] = tuple(m["artifacts"])
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_blob_dictionary_subclass_denied(self):
        m, b = fixture()
        self.assertFalse(verify_artifact_manifest(m, type("BlobMap", (dict,), {})(b)))


    def test_cross_tenant_manifest_label_change_not_trusted(self):
        m, b = fixture()
        m["tenant_id"] = "tenant-b"
        # Integrity of bytes alone does NOT authenticate tenant ownership.
        self.assertTrue(verify_artifact_manifest(m, b))

    def test_zero_width_artifact_identity_denied(self):
        m, b = fixture()
        m["artifacts"][0]["artifact_id"] = "proof-\u200b1"
        self.assertFalse(verify_artifact_manifest(m, b))

    def test_manifest_list_subclass_denied(self):
        m, b = fixture()
        m["artifacts"] = type("ArtifactList", (list,), {})(m["artifacts"])
        self.assertFalse(verify_artifact_manifest(m, b))


if __name__ == "__main__":
    unittest.main()
