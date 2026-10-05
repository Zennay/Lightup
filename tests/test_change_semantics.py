from __future__ import annotations

import unittest

from lightup.changes import (
    ChangeObjectKind,
    SemanticChangeSignal,
    SemanticSignalDirection,
    SemanticSignalKind,
)
from lightup.github_changes import (
    github_commit_changeset,
    github_pull_request_changeset,
)
from lightup.twin import FactProvenance, SecurityTwin


class ChangeSemanticIngestionTest(unittest.TestCase):
    def test_openapi_patch_emits_inferred_route_signal_with_patch_evidence(self):
        changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=77,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": "openapi.yaml",
                    "status": "modified",
                    "additions": 3,
                    "deletions": 0,
                    "patch": "@@ -10,0 +11,3 @@\n+  /invoice/export:\n+    get:\n+      responses: {}",
                },
            ),
        )

        self.assertEqual(len(changeset.semantic_signals), 1)
        signal = changeset.semantic_signals[0]
        self.assertIs(signal.kind, SemanticSignalKind.API_SURFACE)
        self.assertIs(signal.direction, SemanticSignalDirection.ADDED)
        self.assertIs(signal.provenance, FactProvenance.INFERRED)
        self.assertIn("/invoice/export", signal.summary)
        self.assertTrue(signal.evidence_refs[0].startswith("patch-sha256:"))
        self.assertNotIn("patch_content_not_ingested", changeset.uncertainties)

    def test_iac_patch_emits_network_and_iam_hints_without_claiming_verification(self):
        changeset = github_commit_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            parent_sha="a" * 40,
            commit_sha="b" * 40,
            files=(
                {
                    "filename": "terraform/security.tf",
                    "status": "modified",
                    "additions": 2,
                    "deletions": 0,
                    "patch": (
                        "@@ -1,0 +1,2 @@\n"
                        "+  cidr_blocks = [\"0.0.0.0/0\"]\n"
                        "+  principal = \"*\""
                    ),
                },
            ),
        )

        kinds = {signal.kind for signal in changeset.semantic_signals}
        self.assertIn(SemanticSignalKind.NETWORK_BOUNDARY, kinds)
        self.assertIn(SemanticSignalKind.IAM_POLICY, kinds)
        self.assertTrue(
            all(
                signal.provenance is FactProvenance.INFERRED
                for signal in changeset.semantic_signals
            )
        )
        self.assertIn("semantic_security_effects_unresolved", changeset.uncertainties)

    def test_config_patch_keeps_raw_secret_out_of_changeset(self):
        secret = "super-secret-value-that-must-not-be-retained"
        patch = (
            "@@ -1,2 +1,3 @@\n"
            f"+API_SECRET={secret}\n"
            "+DEBUG=true\n"
            "+TLS_ENABLED=false"
        )
        changeset = github_commit_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            parent_sha="a" * 40,
            commit_sha="b" * 40,
            files=(
                {
                    "filename": "config/app.conf",
                    "status": "modified",
                    "additions": 3,
                    "deletions": 0,
                    "patch": patch,
                },
            ),
        )

        obj = changeset.objects[0]
        metadata = dict(obj.metadata)
        self.assertEqual(obj.kind, ChangeObjectKind.CONFIG)
        self.assertEqual(metadata["patch_analyzed"], "true")
        self.assertIn("patch_sha256", metadata)
        self.assertNotIn(secret, repr(changeset))
        self.assertNotIn(secret, changeset.stable_digest())
        summaries = " ".join(signal.summary for signal in changeset.semantic_signals)
        self.assertIn("debug/exposure control", summaries)
        self.assertIn("TLS/transport control", summaries)

    def test_oversized_patch_is_hashed_but_not_semantically_parsed(self):
        huge_patch = "+" + ("x" * (128 * 1024 + 1))
        changeset = github_commit_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            parent_sha="a" * 40,
            commit_sha="b" * 40,
            files=(
                {
                    "filename": "config/app.conf",
                    "status": "modified",
                    "additions": 1,
                    "deletions": 0,
                    "patch": huge_patch,
                },
            ),
        )

        metadata = dict(changeset.objects[0].metadata)
        self.assertEqual(metadata["patch_analyzed"], "false")
        self.assertIn(
            "patch_content_too_large:config/app.conf",
            changeset.uncertainties,
        )
        self.assertEqual(changeset.semantic_signals, ())

    def test_semantic_signal_cannot_be_promoted_to_verified_in_changeset(self):
        signal = SemanticChangeSignal(
            signal_id="signal-1",
            object_path="openapi.yaml",
            kind=SemanticSignalKind.API_SURFACE,
            direction=SemanticSignalDirection.ADDED,
            summary="API route declaration changed: /admin",
            evidence_refs=("patch-sha256:abc",),
            provenance=FactProvenance.VERIFIED,
        )
        with self.assertRaises(ValueError):
            signal.validate()

    def test_future_twin_records_signal_count_but_does_not_apply_graph_effects(self):
        from lightup.changes import derive_future_twin

        changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=78,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": "openapi.yaml",
                    "status": "modified",
                    "additions": 1,
                    "deletions": 0,
                    "patch": "@@ -1,0 +1 @@\n+/admin/export:",
                },
            ),
        )
        current = SecurityTwin.current("client-1")
        future = derive_future_twin(current, changeset)

        self.assertEqual(future.nodes[: len(current.nodes)], current.nodes)
        self.assertEqual(future.facts[: len(current.facts)], current.facts)
        self.assertEqual(future.relationships, current.relationships)
        self.assertEqual(future.attack_paths, current.attack_paths)

        change_nodes = [
            node for node in future.nodes[len(current.nodes) :]
            if node.kind.value == "change"
        ]
        self.assertEqual(len(change_nodes), 1)
        change_facts = [
            fact for fact in future.facts[len(current.facts) :]
            if fact.subject_id == change_nodes[0].node_id
        ]
        self.assertTrue(change_facts)
        self.assertTrue(
            all(fact.provenance is FactProvenance.INFERRED for fact in change_facts)
        )

        metadata = dict(future.metadata)
        self.assertEqual(metadata["changeset_signal_count"], "1")
        self.assertEqual(metadata["future_change_projection"], "inferred_only")
        self.assertEqual(metadata["future_base_twin_id"], current.twin_id)
        self.assertEqual(metadata["future_base_twin_version"], str(current.version))
        self.assertEqual(metadata["future_semantics"], "unresolved")


if __name__ == "__main__":
    unittest.main()
