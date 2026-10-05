from __future__ import annotations

import json
import unittest

from lightup.changes import (
    ChangeObjectKind,
    SemanticSignalDirection,
    SemanticSignalKind,
)
from lightup.github_changes import github_commit_changeset
from lightup.structured_changes import enrich_changeset_with_structured_content
from lightup.twin import FactProvenance


class StructuredChangeParserTest(unittest.TestCase):
    def _changeset(self, path: str):
        return github_commit_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            parent_sha="a" * 40,
            commit_sha="b" * 40,
            files=(
                {
                    "filename": path,
                    "status": "modified",
                    "additions": 1,
                    "deletions": 1,
                },
            ),
        )

    def test_openapi_json_addition_emits_inferred_operation_signal(self):
        changeset = self._changeset("openapi.json")
        base = json.dumps(
            {
                "openapi": "3.0.3",
                "paths": {
                    "/health": {"get": {"responses": {"200": {}}}},
                },
            }
        )
        head = json.dumps(
            {
                "openapi": "3.0.3",
                "paths": {
                    "/health": {"get": {"responses": {"200": {}}}},
                    "/invoice/export": {"post": {"responses": {"200": {}}}},
                },
            }
        )

        enriched = enrich_changeset_with_structured_content(
            changeset,
            path="openapi.json",
            base_content=base,
            head_content=head,
        )

        signals = [
            signal
            for signal in enriched.semantic_signals
            if signal.summary == "OpenAPI operation added: POST /invoice/export"
        ]
        self.assertEqual(len(signals), 1)
        signal = signals[0]
        self.assertIs(signal.kind, SemanticSignalKind.API_SURFACE)
        self.assertIs(signal.direction, SemanticSignalDirection.ADDED)
        self.assertIs(signal.provenance, FactProvenance.INFERRED)
        self.assertGreater(signal.confidence, 0.55)
        self.assertTrue(signal.evidence_refs[0].startswith("content-sha256:"))

        metadata = dict(enriched.objects[0].metadata)
        self.assertEqual(metadata["structured_parser"], "openapi_json")
        self.assertEqual(metadata["structured_analyzed"], "true")
        self.assertIn("base_content_sha256", metadata)
        self.assertIn("head_content_sha256", metadata)
        self.assertNotIn("/invoice/export", repr(enriched.objects[0].metadata))

    def test_openapi_removed_operation_is_explicit(self):
        changeset = self._changeset("openapi.json")
        base = json.dumps(
            {
                "openapi": "3.0.3",
                "paths": {"/admin": {"delete": {"responses": {"204": {}}}}},
            }
        )
        head = json.dumps({"openapi": "3.0.3", "paths": {}})

        enriched = enrich_changeset_with_structured_content(
            changeset,
            path="openapi.json",
            base_content=base,
            head_content=head,
        )
        matches = [
            signal
            for signal in enriched.semantic_signals
            if signal.summary == "OpenAPI operation removed: DELETE /admin"
        ]
        self.assertEqual(len(matches), 1)
        self.assertIs(matches[0].direction, SemanticSignalDirection.REMOVED)

    def test_terraform_json_detects_network_and_iam_fields_without_values(self):
        changeset = self._changeset("main.tf.json")
        self.assertIs(changeset.objects[0].kind, ChangeObjectKind.IAC)

        base = json.dumps(
            {
                "resource": {
                    "aws_security_group": {
                        "web": {
                            "ingress": [{"cidr_blocks": ["10.0.0.0/8"]}],
                        }
                    },
                    "aws_iam_role": {
                        "app": {
                            "assume_role_policy": {"Principal": {"Service": "ecs.amazonaws.com"}},
                        }
                    },
                }
            }
        )
        head = json.dumps(
            {
                "resource": {
                    "aws_security_group": {
                        "web": {
                            "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}],
                        }
                    },
                    "aws_iam_role": {
                        "app": {
                            "assume_role_policy": {
                                "Principal": {"AWS": "arn:example:secret-value"}
                            },
                        }
                    },
                }
            }
        )

        enriched = enrich_changeset_with_structured_content(
            changeset,
            path="main.tf.json",
            base_content=base,
            head_content=head,
        )

        kinds = {signal.kind for signal in enriched.semantic_signals}
        self.assertIn(SemanticSignalKind.NETWORK_BOUNDARY, kinds)
        self.assertIn(SemanticSignalKind.IAM_POLICY, kinds)
        self.assertTrue(
            any(
                signal.direction is SemanticSignalDirection.MODIFIED
                for signal in enriched.semantic_signals
            )
        )
        rendered = repr(enriched)
        self.assertNotIn("0.0.0.0/0", rendered)
        self.assertNotIn("arn:example:secret-value", rendered)
        self.assertTrue(
            all(
                signal.provenance is FactProvenance.INFERRED
                for signal in enriched.semantic_signals
            )
        )

    def test_invalid_structured_json_records_uncertainty_instead_of_signal(self):
        changeset = self._changeset("openapi.json")
        enriched = enrich_changeset_with_structured_content(
            changeset,
            path="openapi.json",
            base_content='{"openapi":"3.0.3","paths":{}}',
            head_content='{"openapi":',
        )

        self.assertIn(
            "structured_content_invalid:openapi.json",
            enriched.uncertainties,
        )
        metadata = dict(enriched.objects[0].metadata)
        self.assertEqual(metadata["structured_analyzed"], "false")
        self.assertEqual(enriched.semantic_signals, changeset.semantic_signals)

    def test_oversized_structured_content_fails_closed(self):
        changeset = self._changeset("openapi.json")
        huge = '{"openapi":"3.0.3","paths":{},"padding":"' + ("x" * (512 * 1024)) + '"}'
        enriched = enrich_changeset_with_structured_content(
            changeset,
            path="openapi.json",
            base_content='{"openapi":"3.0.3","paths":{}}',
            head_content=huge,
        )

        self.assertIn(
            "structured_content_too_large:openapi.json",
            enriched.uncertainties,
        )
        self.assertEqual(dict(enriched.objects[0].metadata)["structured_analyzed"], "false")

    def test_unsupported_yaml_parser_is_explicit_uncertainty(self):
        changeset = self._changeset("openapi.yaml")
        enriched = enrich_changeset_with_structured_content(
            changeset,
            path="openapi.yaml",
            base_content="openapi: 3.0.3\npaths: {}\n",
            head_content="openapi: 3.0.3\npaths:\n  /admin: {}\n",
        )

        self.assertIn(
            "structured_parser_unsupported:openapi.yaml",
            enriched.uncertainties,
        )

    def test_raw_documents_are_not_retained_in_changeset(self):
        changeset = self._changeset("main.tf.json")
        secret = "do-not-retain-this-secret"
        head = json.dumps(
            {
                "resource": {
                    "aws_iam_role": {
                        "app": {
                            "policy": {"token": secret},
                        }
                    }
                }
            }
        )
        enriched = enrich_changeset_with_structured_content(
            changeset,
            path="main.tf.json",
            base_content='{"resource":{}}',
            head_content=head,
        )

        self.assertNotIn(secret, repr(enriched))
        self.assertNotIn(secret, enriched.stable_digest())
        self.assertIn("head_content_sha256", dict(enriched.objects[0].metadata))


if __name__ == "__main__":
    unittest.main()
