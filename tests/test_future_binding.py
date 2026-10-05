from __future__ import annotations

import unittest

from lightup.changes import derive_future_twin
from lightup.future_binding import (
    SubjectBindingStatus,
    bind_future_change_candidates,
    suggest_subject_candidates,
)
from lightup.github_changes import github_pull_request_changeset
from lightup.twin import (
    FactProvenance,
    SecurityTwin,
    TwinNode,
    TwinNodeKind,
)


class FutureSubjectBindingTest(unittest.TestCase):
    def _changeset(self):
        return github_pull_request_changeset(
            client_id="client-1",
            repository="Zennay/Lightup",
            pr_number=120,
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

    def test_exact_source_path_produces_single_candidate(self):
        api = TwinNode(
            "api-1",
            TwinNodeKind.API,
            "Admin API",
            attributes=(("source_path", "openapi.yaml"),),
        )
        current = SecurityTwin.current("client-1").next_snapshot(nodes=(api,))
        changeset = self._changeset()
        future = derive_future_twin(current, changeset)

        bound, bindings = bind_future_change_candidates(future, changeset)

        self.assertEqual(len(bindings), 1)
        self.assertIs(bindings[0].status, SubjectBindingStatus.SINGLE_CANDIDATE)
        self.assertEqual(bindings[0].candidate_node_ids, ("api-1",))
        candidate_links = [
            rel for rel in bound.relationships if rel.relation == "candidate_affects"
        ]
        self.assertEqual(len(candidate_links), 1)
        self.assertEqual(candidate_links[0].target_id, "api-1")
        self.assertIs(candidate_links[0].provenance, FactProvenance.INFERRED)
        self.assertEqual(bound.attack_paths, future.attack_paths)
        self.assertEqual(current.relationships, ())

    def test_multiple_exact_matches_remain_ambiguous(self):
        nodes = (
            TwinNode(
                "api-1",
                TwinNodeKind.API,
                "API one",
                attributes=(("repo_path", "openapi.yaml"),),
            ),
            TwinNode(
                "api-2",
                TwinNodeKind.API,
                "API two",
                attributes=(("source_path", "openapi.yaml"),),
            ),
        )
        current = SecurityTwin.current("client-1").next_snapshot(nodes=nodes)
        changeset = self._changeset()
        future = derive_future_twin(current, changeset)

        bound, bindings = bind_future_change_candidates(future, changeset)

        self.assertIs(bindings[0].status, SubjectBindingStatus.AMBIGUOUS)
        self.assertEqual(bindings[0].candidate_node_ids, ("api-1", "api-2"))
        metadata = dict(bound.metadata)
        self.assertEqual(metadata["future_subject_binding_ambiguous"], "1")
        self.assertEqual(metadata["future_semantics"], "unresolved")
        self.assertEqual(
            len([r for r in bound.relationships if r.relation == "candidate_affects"]),
            2,
        )

    def test_no_exact_match_is_explicit_not_silently_selected(self):
        api = TwinNode(
            "api-1",
            TwinNodeKind.API,
            "Other API",
            attributes=(("source_path", "other.yaml"),),
        )
        current = SecurityTwin.current("client-1").next_snapshot(nodes=(api,))
        changeset = self._changeset()
        future = derive_future_twin(current, changeset)

        bound, bindings = bind_future_change_candidates(future, changeset)

        self.assertIs(bindings[0].status, SubjectBindingStatus.NO_CANDIDATE)
        self.assertEqual(bindings[0].candidate_node_ids, ())
        self.assertFalse(
            any(rel.relation == "candidate_affects" for rel in bound.relationships)
        )
        status_facts = [
            fact
            for fact in bound.facts
            if fact.predicate == "change.binding_status"
        ]
        self.assertEqual([fact.value for fact in status_facts], ["no_candidate"])

    def test_explicit_candidates_can_refine_an_ambiguous_binding(self):
        nodes = (
            TwinNode(
                "api-1",
                TwinNodeKind.API,
                "API one",
                attributes=(("source_path", "openapi.yaml"),),
            ),
            TwinNode(
                "api-2",
                TwinNodeKind.API,
                "API two",
                attributes=(("source_path", "openapi.yaml"),),
            ),
        )
        current = SecurityTwin.current("client-1").next_snapshot(nodes=nodes)
        changeset = self._changeset()
        future = derive_future_twin(current, changeset)
        first, bindings = bind_future_change_candidates(future, changeset)
        signal_id = bindings[0].signal_id

        refined, refined_bindings = bind_future_change_candidates(
            first,
            changeset,
            candidates={signal_id: ("api-2",)},
        )

        self.assertIs(
            refined_bindings[0].status,
            SubjectBindingStatus.SINGLE_CANDIDATE,
        )
        links = [
            rel for rel in refined.relationships if rel.relation == "candidate_affects"
        ]
        self.assertEqual(
            [(rel.source_id, rel.target_id) for rel in links],
            [(refined_bindings[0].change_node_id, "api-2")],
        )
        self.assertEqual(
            dict(refined.metadata)["future_subject_binding"],
            "explicit_candidates",
        )

    def test_unknown_or_ineligible_explicit_candidates_fail_closed(self):
        finding = TwinNode("finding-1", TwinNodeKind.FINDING, "Finding")
        current = SecurityTwin.current("client-1").next_snapshot(nodes=(finding,))
        changeset = self._changeset()
        future = derive_future_twin(current, changeset)
        signal_id = changeset.semantic_signals[0].signal_id

        with self.assertRaises(ValueError):
            bind_future_change_candidates(
                future,
                changeset,
                candidates={signal_id: ("missing-node",)},
            )
        with self.assertRaises(ValueError):
            bind_future_change_candidates(
                future,
                changeset,
                candidates={signal_id: ("finding-1",)},
            )
        with self.assertRaises(ValueError):
            bind_future_change_candidates(
                future,
                changeset,
                candidates={"unknown-signal": ()},
            )

    def test_scalar_candidate_mapping_is_rejected(self):
        api = TwinNode("api-1", TwinNodeKind.API, "API")
        current = SecurityTwin.current("client-1").next_snapshot(nodes=(api,))
        changeset = self._changeset()
        future = derive_future_twin(current, changeset)
        signal_id = changeset.semantic_signals[0].signal_id

        with self.assertRaises(ValueError):
            bind_future_change_candidates(
                future,
                changeset,
                candidates={signal_id: "api-1"},
            )

    def test_suggestions_ignore_invalid_candidate_path_metadata(self):
        api = TwinNode(
            "api-1",
            TwinNodeKind.API,
            "Bad metadata",
            attributes=(("source_path", "../outside"),),
        )
        current = SecurityTwin.current("client-1").next_snapshot(nodes=(api,))
        changeset = self._changeset()
        future = derive_future_twin(current, changeset)

        suggestions = suggest_subject_candidates(future, changeset)

        self.assertEqual(
            suggestions[changeset.semantic_signals[0].signal_id],
            (),
        )

    def test_non_string_path_metadata_is_ignored(self):
        api = TwinNode(
            "api-1",
            TwinNodeKind.API,
            "Malformed metadata",
            attributes=(("source_path", 123),),
        )
        current = SecurityTwin.current("client-1").next_snapshot(nodes=(api,))
        changeset = self._changeset()
        future = derive_future_twin(current, changeset)

        suggestions = suggest_subject_candidates(future, changeset)

        self.assertEqual(
            suggestions[changeset.semantic_signals[0].signal_id],
            (),
        )

    def test_non_string_explicit_candidate_id_is_rejected(self):
        api = TwinNode("api-1", TwinNodeKind.API, "API")
        current = SecurityTwin.current("client-1").next_snapshot(nodes=(api,))
        changeset = self._changeset()
        future = derive_future_twin(current, changeset)
        signal_id = changeset.semantic_signals[0].signal_id

        with self.assertRaises(ValueError):
            bind_future_change_candidates(
                future,
                changeset,
                candidates={signal_id: (123,)},
            )

    def test_binding_requires_matching_future_changeset_pair(self):
        current = SecurityTwin.current("client-1")
        changeset = self._changeset()
        with self.assertRaises(ValueError):
            bind_future_change_candidates(current, changeset)


if __name__ == "__main__":
    unittest.main()
