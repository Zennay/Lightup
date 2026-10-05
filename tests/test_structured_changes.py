from __future__ import annotations

import unittest

from lightup.github_changes import github_pull_request_changeset
from lightup.structured_changes import enrich_changeset_with_structured_documents
from lightup.twin import FactProvenance


class StructuredChangeParsingTest(unittest.TestCase):
    def test_openapi_json_emits_operations_with_content_hash_evidence(self):
        changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=90,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": "openapi.json",
                    "status": "modified",
                    "additions": 4,
                    "deletions": 0,
                },
            ),
        )
        document = (
            '{"openapi":"3.1.0","paths":{'
            '"/admin":{"get":{"responses":{}},"post":{"responses":{}}}}}'
        )

        enriched = enrich_changeset_with_structured_documents(
            changeset, {"openapi.json": document}
        )

        summaries = {signal.summary for signal in enriched.semantic_signals}
        self.assertEqual(
            summaries,
            {
                "OpenAPI operation declared: GET /admin",
                "OpenAPI operation declared: POST /admin",
            },
        )
        self.assertTrue(
            all(signal.provenance is FactProvenance.INFERRED for signal in enriched.semantic_signals)
        )
        self.assertTrue(
            all(
                signal.evidence_refs[0].startswith("content-sha256:")
                for signal in enriched.semantic_signals
            )
        )
        metadata = dict(enriched.objects[0].metadata)
        self.assertEqual(metadata["structured_parser"], "openapi-json")
        self.assertEqual(metadata["structured_analyzed"], "true")

    def test_openapi_yaml_bounded_parser_emits_declared_operations(self):
        changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=91,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": "openapi.yaml",
                    "status": "added",
                    "additions": 7,
                    "deletions": 0,
                },
            ),
        )
        document = """openapi: 3.1.0
paths:
  /health:
    get:
      responses: {}
  /login:
    post:
      responses: {}
"""

        enriched = enrich_changeset_with_structured_documents(
            changeset, {"openapi.yaml": document}
        )

        summaries = {signal.summary for signal in enriched.semantic_signals}
        self.assertIn("OpenAPI operation declared: GET /health", summaries)
        self.assertIn("OpenAPI operation declared: POST /login", summaries)
        self.assertTrue(all(signal.direction.value == "added" for signal in enriched.semantic_signals))

    def test_terraform_parser_marks_network_and_iam_declarations(self):
        changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=92,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": "terraform/security.tf",
                    "status": "modified",
                    "additions": 12,
                    "deletions": 0,
                },
            ),
        )
        document = """
resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "app" {
  assume_role_policy = "hashed-evidence-only"
}
"""

        enriched = enrich_changeset_with_structured_documents(
            changeset, {"terraform/security.tf": document}
        )

        kinds = {signal.kind.value for signal in enriched.semantic_signals}
        self.assertIn("network_boundary", kinds)
        self.assertIn("iam_policy", kinds)
        summaries = " ".join(signal.summary for signal in enriched.semantic_signals)
        self.assertIn("aws_security_group.web", summaries)
        self.assertIn("aws_iam_role.app", summaries)

    def test_raw_structured_content_is_not_retained(self):
        secret = "do-not-retain-this-value"
        changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=93,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": "openapi.json",
                    "status": "modified",
                    "additions": 1,
                    "deletions": 0,
                },
            ),
        )
        document = (
            '{"openapi":"3.1.0","x-secret":"' + secret + '",'
            '"paths":{"/health":{"get":{"responses":{}}}}}'
        )

        enriched = enrich_changeset_with_structured_documents(
            changeset, {"openapi.json": document}
        )

        self.assertNotIn(secret, repr(enriched))
        self.assertNotIn(secret, enriched.stable_digest())

    def test_unknown_change_object_path_is_rejected(self):
        changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=94,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(),
        )
        with self.assertRaises(ValueError):
            enrich_changeset_with_structured_documents(
                changeset, {"openapi.json": '{"openapi":"3.1.0","paths":{}}'}
            )

    def test_oversized_structured_content_is_hashed_but_not_parsed(self):
        changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=95,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": "openapi.json",
                    "status": "modified",
                    "additions": 1,
                    "deletions": 0,
                },
            ),
        )
        document = "{" + ("x" * (512 * 1024 + 1))

        enriched = enrich_changeset_with_structured_documents(
            changeset, {"openapi.json": document}
        )

        self.assertIn("structured_content_too_large:openapi.json", enriched.uncertainties)
        self.assertEqual(enriched.semantic_signals, ())
        metadata = dict(enriched.objects[0].metadata)
        self.assertEqual(metadata["structured_analyzed"], "false")
        self.assertIn("structured_sha256", metadata)


    def test_terraform_single_line_security_block_is_valid(self):
        changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=96,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": "terraform/security.tf",
                    "status": "added",
                    "additions": 1,
                    "deletions": 0,
                },
            ),
        )

        enriched = enrich_changeset_with_structured_documents(
            changeset,
            {"terraform/security.tf": 'resource "aws_security_group" "empty" {}'},
        )

        self.assertNotIn(
            "structured_parse_failed:terraform/security.tf",
            enriched.uncertainties,
        )
        self.assertTrue(
            any(signal.kind.value == "network_boundary" for signal in enriched.semantic_signals)
        )


if __name__ == "__main__":
    unittest.main()
