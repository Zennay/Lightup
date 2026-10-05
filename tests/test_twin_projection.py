from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role, TenantIsolationError
from lightup.models import RetestStatus, Severity
from lightup.twin import FactProvenance, TwinNodeKind
from lightup.twin_projection import (
    explain_attack_path,
    project_current_twin,
    query_attack_paths,
)


class SecurityTwinProjectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("operator", Role.OPERATOR)
        self.client_a = self.store.create_client(self.operator, "Client A")
        self.client_b = self.store.create_client(self.operator, "Client B")
        self.engagement_a = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Web assessment"
        )
        self.engagement_b = self.store.create_engagement(
            self.operator, self.client_b.client_id, "Other tenant"
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _record(
        self,
        *,
        engagement_id: str | None = None,
        title: str = "Missing HSTS",
        asset: str = "https://app.test",
        evidence_ids: tuple[str, ...] = ("evidence-1",),
    ):
        return self.store.record_finding(
            self.operator,
            engagement_id or self.engagement_a.engagement_id,
            title=title,
            severity=Severity.MEDIUM,
            asset=asset,
            impact="Downgrade protection is incomplete.",
            remediation="Enable HSTS.",
            evidence_ids=evidence_ids,
        )

    def test_projects_only_evidence_backed_findings_and_coverage(self):
        verified = self._record()
        self._record(title="No evidence yet", evidence_ids=())
        self.store.set_coverage(
            self.operator,
            self.engagement_a.engagement_id,
            "web",
            "assessed",
        )

        twin = project_current_twin(
            self.store,
            self.operator,
            self.client_a.client_id,
        )

        finding_nodes = [
            node for node in twin.nodes if node.kind is TwinNodeKind.FINDING
        ]
        self.assertEqual([node.label for node in finding_nodes], [verified.title])
        self.assertTrue(
            any(
                fact.predicate == "coverage:web"
                and fact.value == "assessed"
                and fact.provenance is FactProvenance.OBSERVED
                for fact in twin.facts
            )
        )
        self.assertEqual(
            [path.path_id for path in twin.attack_paths],
            [f"path:{verified.finding_id}"],
        )

    def test_fixed_finding_remains_evidence_but_leaves_current_attack_paths(self):
        finding = self._record()
        self.store.set_retest_status(
            self.operator,
            finding.finding_id,
            RetestStatus.FIXED,
        )

        twin = project_current_twin(
            self.store,
            self.operator,
            self.client_a.client_id,
        )

        self.assertTrue(
            any(node.node_id == f"finding:{finding.finding_id}" for node in twin.nodes)
        )
        self.assertFalse(
            any(
                path.path_id == f"path:{finding.finding_id}"
                for path in twin.attack_paths
            )
        )

    def test_client_context_is_hard_tenant_isolated(self):
        client_ctx = AccessContext(
            "client-b-user",
            Role.CLIENT_ADMIN,
            self.client_b.client_id,
        )
        with self.assertRaises(TenantIsolationError):
            project_current_twin(
                self.store,
                client_ctx,
                self.client_a.client_id,
            )

    def test_client_context_can_project_own_tenant_without_explicit_client_id(self):
        self._record()
        client_ctx = AccessContext(
            "client-a-user",
            Role.CLIENT_MEMBER,
            self.client_a.client_id,
        )
        twin = project_current_twin(self.store, client_ctx)
        self.assertEqual(twin.client_id, self.client_a.client_id)

    def test_explainable_path_query_preserves_labels_and_evidence(self):
        finding = self._record(evidence_ids=("ev-b", "ev-a"))
        twin = project_current_twin(
            self.store,
            self.operator,
            self.client_a.client_id,
        )

        explanation = explain_attack_path(twin, f"path:{finding.finding_id}")
        self.assertEqual(explanation.evidence_refs, ("ev-a", "ev-b"))
        self.assertEqual(
            explanation.steps,
            ("https://app.test --has_verified_finding--> Missing HSTS",),
        )
        self.assertEqual(
            query_attack_paths(twin, evidence_ref="ev-a"),
            (explanation,),
        )
        self.assertEqual(query_attack_paths(twin, evidence_ref="missing"), ())


if __name__ == "__main__":
    unittest.main()
