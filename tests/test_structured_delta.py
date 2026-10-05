from __future__ import annotations

import unittest

from lightup.github_changes import github_pull_request_changeset
from lightup.structured_changes import (
    StructuredDocumentDelta,
    enrich_changeset_with_structured_deltas,
)
from lightup.twin import FactProvenance


class StructuredDeltaTest(unittest.TestCase):
    def _changeset(self, path: str, *, status: str = "modified"):
        return github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=101,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": path,
                    "status": status,
                    "additions": 1,
                    "deletions": 1,
                },
            ),
        )

    def test_identical_openapi_documents_emit_no_delta_signal(self):
        changeset = self._changeset("openapi.json")
        document = (
            '{"openapi":"3.1.0","paths":'
            '{"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}'
        )

        enriched = enrich_changeset_with_structured_deltas(
            changeset,
            {
                "openapi.json": StructuredDocumentDelta(
                    base_content=document,
                    head_content=document,
                )
            },
        )

        self.assertEqual(enriched.semantic_signals, changeset.semantic_signals)
        metadata = dict(enriched.objects[0].metadata)
        self.assertEqual(metadata["structured_delta_analyzed"], "true")
        self.assertEqual(metadata["structured_delta_parser"], "openapi-json-delta")

    def test_openapi_operation_body_change_is_modified_not_all_operations(self):
        changeset = self._changeset("openapi.json")
        base = (
            '{"openapi":"3.1.0","paths":{'
            '"/health":{"get":{"responses":{"200":{"description":"ok"}}}},'
            '"/invoice":{"post":{"responses":{"201":{"description":"created"}}}}}}'
        )
        head = (
            '{"openapi":"3.1.0","paths":{'
            '"/health":{"get":{"responses":{"200":{"description":"ok"}}}},'
            '"/invoice":{"post":{"responses":{"202":{"description":"accepted"}}}}}}'
        )

        enriched = enrich_changeset_with_structured_deltas(
            changeset,
            {
                "openapi.json": StructuredDocumentDelta(
                    base_content=base,
                    head_content=head,
                )
            },
        )

        delta_signals = [
            signal
            for signal in enriched.semantic_signals
            if signal.summary.startswith("OpenAPI operation ")
        ]
        self.assertEqual(len(delta_signals), 1)
        signal = delta_signals[0]
        self.assertEqual(
            signal.summary,
            "OpenAPI operation modified: POST /invoice",
        )
        self.assertEqual(signal.direction.value, "modified")
        self.assertEqual(len(signal.evidence_refs), 2)
        self.assertIs(signal.provenance, FactProvenance.INFERRED)

    def test_openapi_added_and_removed_operations_are_separate(self):
        changeset = self._changeset("openapi.json")
        base = (
            '{"openapi":"3.1.0","paths":'
            '{"/old":{"get":{"responses":{}}}}}'
        )
        head = (
            '{"openapi":"3.1.0","paths":'
            '{"/new":{"post":{"responses":{}}}}}'
        )

        enriched = enrich_changeset_with_structured_deltas(
            changeset,
            {
                "openapi.json": StructuredDocumentDelta(
                    base_content=base,
                    head_content=head,
                )
            },
        )
        summaries = {signal.summary for signal in enriched.semantic_signals}
        self.assertIn("OpenAPI operation removed: GET /old", summaries)
        self.assertIn("OpenAPI operation added: POST /new", summaries)

    def test_terraform_same_resource_value_change_is_modified_without_value_retention(self):
        changeset = self._changeset("terraform/security.tf")
        secret = "sensitive-cidr-or-token"
        base = """
resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
  }
}
"""
        head = f"""
resource "aws_security_group" "web" {{
  ingress {{
    cidr_blocks = ["{secret}"]
  }}
}}
"""

        enriched = enrich_changeset_with_structured_deltas(
            changeset,
            {
                "terraform/security.tf": StructuredDocumentDelta(
                    base_content=base,
                    head_content=head,
                )
            },
        )

        matches = [
            signal
            for signal in enriched.semantic_signals
            if signal.summary
            == (
                "Terraform network-boundary declaration modified: "
                "resource.aws_security_group.web"
            )
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].direction.value, "modified")
        self.assertEqual(len(matches[0].evidence_refs), 2)
        self.assertNotIn(secret, repr(enriched))
        self.assertNotIn(secret, enriched.stable_digest())

    def test_added_file_uses_head_content_as_evidence(self):
        changeset = self._changeset("openapi.json", status="added")
        head = (
            '{"openapi":"3.1.0","paths":'
            '{"/new":{"get":{"responses":{}}}}}'
        )

        enriched = enrich_changeset_with_structured_deltas(
            changeset,
            {
                "openapi.json": StructuredDocumentDelta(
                    base_content=None,
                    head_content=head,
                )
            },
        )

        matches = [
            signal for signal in enriched.semantic_signals
            if signal.summary == "OpenAPI operation added: GET /new"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(len(matches[0].evidence_refs), 1)
        self.assertTrue(matches[0].evidence_refs[0].startswith("content-sha256:"))

    def test_modified_file_requires_both_base_and_head(self):
        changeset = self._changeset("openapi.json", status="modified")
        head = (
            '{"openapi":"3.1.0","paths":'
            '{"/new":{"get":{"responses":{}}}}}'
        )

        enriched = enrich_changeset_with_structured_deltas(
            changeset,
            {
                "openapi.json": StructuredDocumentDelta(
                    base_content=None,
                    head_content=head,
                )
            },
        )

        self.assertIn(
            "structured_delta_incomplete_pair:openapi.json",
            enriched.uncertainties,
        )
        self.assertEqual(enriched.semantic_signals, changeset.semantic_signals)
        metadata = dict(enriched.objects[0].metadata)
        self.assertEqual(metadata["structured_delta_analyzed"], "false")
        self.assertEqual(metadata["structured_delta_parser"], "incomplete-pair")

    def test_added_and_removed_files_require_operation_consistent_pairs(self):
        added = self._changeset("openapi.json", status="added")
        document = '{"openapi":"3.1.0","paths":{}}'
        added_bad = enrich_changeset_with_structured_deltas(
            added,
            {
                "openapi.json": StructuredDocumentDelta(
                    base_content=document,
                    head_content=document,
                )
            },
        )
        self.assertIn(
            "structured_delta_incomplete_pair:openapi.json",
            added_bad.uncertainties,
        )

        removed = self._changeset("openapi.json", status="removed")
        removed_bad = enrich_changeset_with_structured_deltas(
            removed,
            {
                "openapi.json": StructuredDocumentDelta(
                    base_content=document,
                    head_content=document,
                )
            },
        )
        self.assertIn(
            "structured_delta_incomplete_pair:openapi.json",
            removed_bad.uncertainties,
        )

    def test_invalid_head_content_records_uncertainty(self):
        changeset = self._changeset("openapi.json")

        enriched = enrich_changeset_with_structured_deltas(
            changeset,
            {
                "openapi.json": StructuredDocumentDelta(
                    base_content='{"openapi":"3.1.0","paths":{}}',
                    head_content='{"openapi":',
                )
            },
        )

        self.assertIn(
            "structured_delta_parse_failed:openapi.json",
            enriched.uncertainties,
        )
        self.assertEqual(
            dict(enriched.objects[0].metadata)["structured_delta_analyzed"],
            "false",
        )

    def test_oversized_delta_records_uncertainty_without_parsing(self):
        changeset = self._changeset("openapi.json")
        huge = '{"openapi":"3.1.0","paths":{},"pad":"' + ("x" * (512 * 1024)) + '"}'

        enriched = enrich_changeset_with_structured_deltas(
            changeset,
            {
                "openapi.json": StructuredDocumentDelta(
                    base_content='{"openapi":"3.1.0","paths":{}}',
                    head_content=huge,
                )
            },
        )

        self.assertIn(
            "structured_delta_too_large:openapi.json",
            enriched.uncertainties,
        )
        self.assertEqual(
            dict(enriched.objects[0].metadata)["structured_delta_analyzed"],
            "false",
        )


if __name__ == "__main__":
    unittest.main()
