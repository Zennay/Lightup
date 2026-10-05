from __future__ import annotations

import unittest

from lightup.changes import (
    ChangeObjectKind,
    ChangeSourceKind,
    derive_future_twin,
)
from lightup.github_changes import (
    github_commit_changeset,
    github_pull_request_changeset,
)
from lightup.twin import (
    FactProvenance,
    SecurityTwin,
    TwinNode,
    TwinNodeKind,
    TwinSnapshotKind,
)


class GitHubChangeSetTest(unittest.TestCase):
    def test_pull_request_ingestion_classifies_changed_objects_conservatively(self):
        changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=42,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": "infra/main.tf",
                    "status": "modified",
                    "additions": 8,
                    "deletions": 2,
                },
                {
                    "filename": "openapi.yaml",
                    "status": "modified",
                    "additions": 3,
                    "deletions": 1,
                },
                {
                    "filename": ".github/workflows/ci.yml",
                    "status": "added",
                    "additions": 20,
                    "deletions": 0,
                },
            ),
        )

        self.assertIs(changeset.source_kind, ChangeSourceKind.GITHUB_PULL_REQUEST)
        kinds = {obj.path: obj.kind for obj in changeset.objects}
        self.assertIs(kinds["infra/main.tf"], ChangeObjectKind.IAC)
        self.assertIs(kinds["openapi.yaml"], ChangeObjectKind.API_SPEC)
        self.assertIs(
            kinds[".github/workflows/ci.yml"],
            ChangeObjectKind.CI,
        )
        self.assertIn(
            "semantic_security_effects_unresolved",
            changeset.uncertainties,
        )
        self.assertIn("patch_content_not_ingested", changeset.uncertainties)

    def test_digest_is_stable_for_equivalent_file_order(self):
        files = (
            {
                "filename": "src/app.py",
                "status": "modified",
                "additions": 1,
                "deletions": 1,
            },
            {
                "filename": "docs/readme.md",
                "status": "modified",
                "additions": 2,
                "deletions": 0,
            },
        )
        first = github_commit_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            parent_sha="a" * 40,
            commit_sha="b" * 40,
            files=files,
        )
        second = github_commit_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            parent_sha="a" * 40,
            commit_sha="b" * 40,
            files=tuple(reversed(files)),
        )
        self.assertEqual(first.changeset_id, second.changeset_id)
        self.assertEqual(first.stable_digest(), second.stable_digest())

    def test_rename_requires_previous_filename(self):
        with self.assertRaises(ValueError):
            github_commit_changeset(
                client_id="client-1",
                repository="Zennay/Lightup",
                parent_sha="a" * 40,
                commit_sha="b" * 40,
                files=(
                    {
                        "filename": "src/new.py",
                        "status": "renamed",
                        "additions": 0,
                        "deletions": 0,
                    },
                ),
            )

    def test_repository_path_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            github_commit_changeset(
                client_id="client-1",
                repository="Zennay/Lightup",
                parent_sha="a" * 40,
                commit_sha="b" * 40,
                files=(
                    {
                        "filename": "../secret",
                        "status": "modified",
                        "additions": 1,
                        "deletions": 0,
                    },
                ),
            )

    def test_unknown_github_status_fails_closed(self):
        with self.assertRaises(ValueError):
            github_commit_changeset(
                client_id="client-1",
                repository="Zennay/Lightup",
                parent_sha="a" * 40,
                commit_sha="b" * 40,
                files=(
                    {
                        "filename": "src/app.py",
                        "status": "mystery",
                        "additions": 1,
                        "deletions": 0,
                    },
                ),
            )

    def test_too_large_compare_is_explicit_uncertainty(self):
        changeset = github_commit_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            parent_sha="a" * 40,
            commit_sha="b" * 40,
            files=(),
            too_large=True,
        )
        self.assertIn("github_compare_too_large", changeset.uncertainties)
        self.assertIn("no_changed_files_reported", changeset.uncertainties)

    def test_changeset_derives_separate_future_twin_without_graph_mutation(self):
        app = TwinNode("app-1", TwinNodeKind.APPLICATION, "Portal")
        current = SecurityTwin.current("client-1").next_snapshot(nodes=(app,))
        changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=42,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": "src/app.py",
                    "status": "modified",
                    "additions": 5,
                    "deletions": 1,
                },
            ),
        )

        future = derive_future_twin(current, changeset)

        self.assertIs(future.kind, TwinSnapshotKind.FUTURE)
        self.assertNotEqual(future.twin_id, current.twin_id)
        self.assertEqual(future.parent_twin_id, current.twin_id)
        self.assertEqual(future.nodes[: len(current.nodes)], current.nodes)
        self.assertEqual(future.facts[: len(current.facts)], current.facts)
        self.assertEqual(future.relationships, current.relationships)
        self.assertEqual(future.attack_paths, current.attack_paths)
        metadata = dict(future.metadata)
        self.assertEqual(metadata["changeset_id"], changeset.changeset_id)
        self.assertEqual(metadata["future_semantics"], "unresolved")
        self.assertEqual(current.source_ref, None)

    def test_semantic_signals_project_to_future_only_change_nodes_and_facts(self):
        current = SecurityTwin.current("client-1")
        changeset = github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=43,
            base_sha="a" * 40,
            head_sha="b" * 40,
            files=(
                {
                    "filename": "openapi.yaml",
                    "status": "modified",
                    "additions": 2,
                    "deletions": 0,
                    "patch": "@@ -1 +1,3 @@\n paths:\n+  /admin:\n+    get:\n",
                },
            ),
        )

        self.assertEqual(len(changeset.semantic_signals), 1)
        future = derive_future_twin(current, changeset)

        self.assertEqual(current.nodes, ())
        self.assertEqual(current.facts, ())
        change_nodes = [node for node in future.nodes if node.kind is TwinNodeKind.CHANGE]
        self.assertEqual(len(change_nodes), 1)
        self.assertEqual(dict(change_nodes[0].attributes)["object_path"], "openapi.yaml")

        change_facts = [
            fact for fact in future.facts if fact.subject_id == change_nodes[0].node_id
        ]
        self.assertEqual(
            {fact.predicate for fact in change_facts},
            {"change.signal_kind", "change.direction", "change.summary"},
        )
        self.assertTrue(
            all(fact.provenance is FactProvenance.INFERRED for fact in change_facts)
        )
        self.assertTrue(all(fact.evidence_refs for fact in change_facts))
        self.assertEqual(future.relationships, current.relationships)
        self.assertEqual(future.attack_paths, current.attack_paths)

        metadata = dict(future.metadata)
        self.assertEqual(metadata["future_change_projection"], "inferred_only")
        self.assertEqual(metadata["future_change_node_count"], "1")
        self.assertEqual(metadata["future_change_fact_count"], "3")
        self.assertEqual(metadata["future_semantics"], "unresolved")

    def test_changeset_cannot_cross_tenants(self):
        current = SecurityTwin.current("client-a")
        changeset = github_commit_changeset(
            client_id="client-b",
            repository="Zennay/Lightup",
            parent_sha="a" * 40,
            commit_sha="b" * 40,
            files=(),
        )
        with self.assertRaises(ValueError):
            derive_future_twin(current, changeset)


if __name__ == "__main__":
    unittest.main()
