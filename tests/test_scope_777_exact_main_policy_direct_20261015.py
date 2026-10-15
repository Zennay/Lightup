"""Issue #777: actual mainline direct ExecutionPolicy provenance RED witness.

No SQLite, handler, target contact or deployment. The policy and grant types
are imported from the real mainline source, never mocked. An expected failure
remains a security defect; the production owner must remove expectedFailure
decorators after implementing canonical direct-grant provenance admission.
"""
from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import (
    ExecutionPolicy, ExecutionRequest, InteractionKind, PolicyDecision,
)


class ForgedApproval(str):
    pass


class DirectGrantProvenancePolicyAcceptance(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="fictional-grant", client_id="fictional-client",
            engagement_id="fictional-engagement", approved_by="fictional-operator",
            reference="ROE-FICTIONAL", scope=ScopeDefinition(
                assets=("example.test",), max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("fictional-check",),
            ), valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(hours=1),
        )
        self.policy = ExecutionPolicy()

    def _decide(self, grant):
        return self.policy.decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="example.test", capability_id="fictional-check",
            requested_risk=RiskLevel.LOW_IMPACT, authorization=grant,
        ))

    def _deny_noncanonical(self, **changes):
        before = self.grant.__dict__.copy()
        modified = replace(self.grant, **changes)
        snapshot = modified.__dict__.copy()
        verdict = self._decide(modified)
        self.assertIs(type(verdict), PolicyDecision)
        self.assertEqual(self.grant.__dict__, before)
        self.assertEqual(modified.__dict__, snapshot)
        self.assertFalse(verdict.allowed, "malformed direct grant must not authorize")

    def test_canonical_direct_grant_still_allows(self):
        self.assertIs(self._decide(self.grant).allowed, True)

    def test_missing_direct_grant_denied(self):
        self.assertIs(self._decide(None).allowed, False)

    def test_expired_direct_grant_denied(self):
        expired = replace(self.grant,
                          valid_from=self.grant.valid_from - timedelta(days=3),
                          valid_until=self.grant.valid_from - timedelta(days=1))
        self.assertIs(self._decide(expired).allowed, False)

    def test_outside_scope_denied(self):
        out = replace(self.grant, scope=replace(
            self.grant.scope, assets=("other.example",)))
        self.assertIs(self._decide(out).allowed, False)

    def test_all_provenance_probes_return_typed_no_write(self):
        cases = (
            {"approved_by": ""}, {"approved_by": " \t "},
            {"approved_by": " fictional-operator "},
            {"approved_by": ForgedApproval("fictional-operator")},
            {"approved_by": None}, {"approved_by": b"fictional-operator"},
            {"approved_by": "\u2003fictional-operator"},
            {"reference": ""}, {"reference": " \t "},
            {"reference": " ROE-FICTIONAL "},
            {"reference": ForgedApproval("ROE-FICTIONAL")},
            {"reference": None}, {"reference": 123},
            {"reference": "ROE-FICTIONAL\u00a0"},
        )
        for patch in cases:
            with self.subTest(patch=patch):
                grant = replace(self.grant, **patch)
                original = grant.__dict__.copy()
                decision = self._decide(grant)
                self.assertIs(type(decision), PolicyDecision)
                self.assertEqual(grant.__dict__, original)

    # Current main's direct policy wrongly ALLOWS all fourteen below.
    # These are explicitly expected-RED, not evidence of secure authorization.
    @unittest.expectedFailure
    def test_red_blank_approver(self): self._deny_noncanonical(approved_by="")

    @unittest.expectedFailure
    def test_red_space_approver(self): self._deny_noncanonical(approved_by=" \t ")

    @unittest.expectedFailure
    def test_red_padded_approver(self): self._deny_noncanonical(approved_by=" fictional-operator ")

    @unittest.expectedFailure
    def test_red_subclass_approver(self): self._deny_noncanonical(approved_by=ForgedApproval("fictional-operator"))

    @unittest.expectedFailure
    def test_red_none_approver(self): self._deny_noncanonical(approved_by=None)

    @unittest.expectedFailure
    def test_red_bytes_approver(self): self._deny_noncanonical(approved_by=b"fictional-operator")

    @unittest.expectedFailure
    def test_red_unicode_padded_approver(self): self._deny_noncanonical(approved_by="\u2003fictional-operator")

    @unittest.expectedFailure
    def test_red_blank_reference(self): self._deny_noncanonical(reference="")

    @unittest.expectedFailure
    def test_red_space_reference(self): self._deny_noncanonical(reference=" \t ")

    @unittest.expectedFailure
    def test_red_padded_reference(self): self._deny_noncanonical(reference=" ROE-FICTIONAL ")

    @unittest.expectedFailure
    def test_red_subclass_reference(self): self._deny_noncanonical(reference=ForgedApproval("ROE-FICTIONAL"))

    @unittest.expectedFailure
    def test_red_none_reference(self): self._deny_noncanonical(reference=None)

    @unittest.expectedFailure
    def test_red_int_reference(self): self._deny_noncanonical(reference=123)

    @unittest.expectedFailure
    def test_red_unicode_reference(self): self._deny_noncanonical(reference="ROE-FICTIONAL\u00a0")


if __name__ == "__main__":
    unittest.main()
