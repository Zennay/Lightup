"""Offline, fictional cross-grant comparison regression suite — no authority. #1493."""
import dataclasses
import os
import socket
import sqlite3
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationPolicy
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy
from lightup.cross_grant_lineage_review_1493 import (
    CrossGrantCandidate, review_cross_grant_batch, review_cross_grant_lineage,
)

NOW = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
START, END = NOW - timedelta(hours=1), NOW + timedelta(hours=1)


def fixture():
    legacy = Authorization("reviewer@example.test", "SYNTH-REF-1", START, END)
    scope = ScopeDefinition(("app.example.test",), RiskLevel.STANDARD,
                            ("web-baseline",), ("excluded.example.test",))
    grant = AuthorizationGrant("G-1", "CLIENT-1", "ENG-1",
                               "reviewer@example.test", "SYNTH-REF-1",
                               scope, START - timedelta(hours=1),
                               END + timedelta(hours=1))
    params = dict(asset="app.example.test", capability_id="web-baseline",
                  client_id="CLIENT-1", engagement_id="ENG-1",
                  requested_risk=RiskLevel.LOW_IMPACT, evaluated_at=NOW)
    return legacy, grant, params


class CrossGrantLineageTests(unittest.TestCase):
    def check(self, legacy=None, durable=None, **change):
        good_legacy, good_grant, params = fixture()
        params.update(change)
        return review_cross_grant_lineage(
            good_legacy if legacy is None else legacy,
            good_grant if durable is None else durable, **params)

    def assert_hold(self, **overrides):
        self.assertEqual(self.check(**overrides).status, "HOLD")

    def test_coherent_assertions_are_review_only_not_permission(self):
        result = self.check()
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertFalse(result.authorized)
        self.assertFalse(result.consent_verified)
        self.assertFalse(result.dispatch_allowed)
        self.assertFalse(result.release_allowed)

    def test_result_immutable(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.check().dispatch_allowed = True

    def test_reference_mismatch(self):
        a, b, _ = fixture()
        self.assert_hold(legacy=dataclasses.replace(a, reference="UNRELATED"))

    def test_actor_mismatch(self):
        a, _, _ = fixture()
        self.assert_hold(legacy=dataclasses.replace(a, owner="another@example.test"))

    def test_client_mismatch(self):
        self.assert_hold(client_id="OTHER")

    def test_engagement_mismatch(self):
        self.assert_hold(engagement_id="OTHER")

    def test_ambiguous_reference_alias(self):
        a, _, _ = fixture()
        self.assert_hold(legacy=dataclasses.replace(a, reference=" SYNTH-REF-1"))

    def test_polymorphic_reference_rejected(self):
        a, _, _ = fixture()
        class StrAlias(str): pass
        self.assert_hold(legacy=dataclasses.replace(a, reference=StrAlias(a.reference)))

    def test_wrong_legacy_shape(self):
        self.assert_hold(legacy={"owner": "reviewer@example.test"})

    def test_wrong_durable_shape(self):
        self.assert_hold(durable={"scope": "forged"})

    def test_missing_legacy_expiry(self):
        a, _, _ = fixture()
        self.assert_hold(legacy=dataclasses.replace(a, valid_until=None))

    def test_missing_legacy_start(self):
        a, _, _ = fixture()
        self.assert_hold(legacy=dataclasses.replace(a, valid_from=None))

    def test_timezone_naive_rejected(self):
        self.assert_hold(evaluated_at=NOW.replace(tzinfo=None))

    def test_offset_utc_alias_rejected(self):
        self.assert_hold(evaluated_at=NOW.astimezone(timezone(timedelta(0), "ALIAS")))

    def test_datetime_subclass_rejected(self):
        class ForgedDate(datetime): pass
        self.assert_hold(evaluated_at=ForgedDate(2026, 10, 16, 12, tzinfo=timezone.utc))

    def test_evaluation_before_window(self):
        self.assert_hold(evaluated_at=START - timedelta(minutes=1))

    def test_evaluation_after_window(self):
        self.assert_hold(evaluated_at=END + timedelta(minutes=1))

    def test_inverted_durable_window(self):
        _, b, _ = fixture()
        self.assert_hold(durable=dataclasses.replace(b, valid_from=END + timedelta(hours=2)))

    def test_legacy_wider_than_durable(self):
        a, b, _ = fixture()
        self.assert_hold(legacy=dataclasses.replace(a, valid_from=b.valid_from - timedelta(seconds=1)))

    def test_legacy_expiry_beyond_durable(self):
        a, b, _ = fixture()
        self.assert_hold(legacy=dataclasses.replace(a, valid_until=b.valid_until + timedelta(seconds=1)))

    def test_unknown_asset(self):
        self.assert_hold(asset="other.example.test")

    def test_capability_wildcard_is_not_review_proof(self):
        _, b, _ = fixture()
        scope = dataclasses.replace(b.scope, allowed_capabilities=())
        self.assert_hold(durable=dataclasses.replace(b, scope=scope))

    def test_explicit_capability_mismatch(self):
        self.assert_hold(capability_id="other-tool")

    def test_ambiguous_scope_list_rejected(self):
        _, b, _ = fixture()
        scope = dataclasses.replace(b.scope, assets=["app.example.test"])
        self.assert_hold(durable=dataclasses.replace(b, scope=scope))

    def test_duplicate_asset_rejected(self):
        _, b, _ = fixture()
        scope = dataclasses.replace(b.scope, assets=("app.example.test", "app.example.test"))
        self.assert_hold(durable=dataclasses.replace(b, scope=scope))

    def test_excluded_asset_rejected(self):
        _, b, _ = fixture()
        scope = dataclasses.replace(b.scope, excluded_assets=("app.example.test",))
        self.assert_hold(durable=dataclasses.replace(b, scope=scope))

    def test_mixed_case_alias_rejected(self):
        self.assert_hold(asset="App.example.test")

    def test_missing_scope_identity_rejected(self):
        _, b, _ = fixture()
        self.assert_hold(durable=dataclasses.replace(b, scope="caller-claims-scope"))

    def test_risk_escalation(self):
        self.assert_hold(requested_risk=RiskLevel.ELEVATED)

    def test_destructive_risk_even_if_scope_claims_it(self):
        _, b, _ = fixture()
        scope = dataclasses.replace(b.scope, max_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY)
        self.assert_hold(durable=dataclasses.replace(b, scope=scope),
                         requested_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY)

    def test_risk_polymorphism(self):
        self.assert_hold(requested_risk=2)

    def test_invalid_retest_boolean(self):
        _, b, _ = fixture()
        self.assert_hold(durable=dataclasses.replace(b, recurring_retest_allowed="false"))

    def test_oversize_asset_collection(self):
        _, b, _ = fixture()
        scope = dataclasses.replace(b.scope, assets=tuple(f"a{i}.example.test" for i in range(257)))
        self.assert_hold(durable=dataclasses.replace(b, scope=scope))

    def test_no_io_even_when_both_inputs_are_coherent(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("sqlite")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")), \
             patch("builtins.open", side_effect=AssertionError("file")):
            self.assertEqual(self.check().status, "REVIEW_ONLY")

    def test_real_original_policies_have_separate_untrusted_slots(self):
        # Synthetic one-record decision; no gate issues a permit or dispatches tools.
        a, b, _ = fixture()
        scope = ScopePolicy(explicit_hosts=frozenset({"app.example.test"}))
        # Legacy public request with expired approval is denied by original source.
        denied = scope.decide(Target("app.example.test", authorization=a))
        self.assertFalse(denied.allowed)
        # Separate durable request is also denied when historical window expired.
        req = ExecutionRequest(InteractionKind.TARGET_ACTIVE, "app.example.test",
                               "web-baseline", RiskLevel.LOW_IMPACT,
                               authorization=b)
        self.assertFalse(ExecutionPolicy().decide(req).allowed)
        with self.assertRaises(PermissionError):
            ActivationGate(scope, ActivationPolicy()).issue(Target("app.example.test", authorization=a),
                                                            "web-baseline")
        # The independent review can still call matching, historical assertions
        # REVIEW_ONLY because its explicit clock is not authenticated.
        self.assertEqual(self.check().status, "REVIEW_ONLY")




def batch_candidate(*, asset="app.example.test", capability="web-baseline",
                    client="CLIENT-1", engagement="ENG-1", grant_id="G-1"):
    a, b, _ = fixture()
    b = dataclasses.replace(b, grant_id=grant_id,
                            scope=dataclasses.replace(
                                b.scope, assets=(asset,),
                                allowed_capabilities=(capability,)))
    return CrossGrantCandidate(a, b, asset, capability, client, engagement,
                               RiskLevel.LOW_IMPACT)


class CrossGrantBatchTests(unittest.TestCase):
    def review(self, candidates):
        return review_cross_grant_batch(candidates, evaluated_at=NOW)

    def test_coherent_single_record_never_authorizes(self):
        r = self.review((batch_candidate(),))
        self.assertEqual((r.status, r.reviewed), ("REVIEW_ONLY", 1))
        self.assertEqual((r.authorized, r.consent_verified, r.dispatch_allowed,
                          r.release_allowed), (False, False, False, False))

    def test_coherent_two_distinct_assets_same_fictional_cohort(self):
        r = self.review((batch_candidate(),
                         batch_candidate(asset="second.example.test", grant_id="G-2")))
        self.assertEqual((r.status, r.reviewed), ("REVIEW_ONLY", 2))

    def test_empty_batch_hold(self):
        self.assertEqual(self.review(()).status, "HOLD")

    def test_wrong_container_hold(self):
        self.assertEqual(self.review([batch_candidate()]).status, "HOLD")

    def test_over_32_batch_hold(self):
        self.assertEqual(self.review(tuple(batch_candidate(grant_id=f"G-{i}") for i in range(33))).status, "HOLD")

    def test_malformed_record_hold(self):
        self.assertEqual(self.review((batch_candidate(), object())).status, "HOLD")

    def test_mixed_client_hold_atomic(self):
        r = self.review((batch_candidate(),
                         batch_candidate(client="CLIENT-2", grant_id="G-2")))
        self.assertEqual((r.status, r.reviewed, r.authorized), ("HOLD", 0, False))

    def test_mixed_engagement_hold_atomic(self):
        r = self.review((batch_candidate(),
                         batch_candidate(engagement="ENG-2", grant_id="G-2")))
        self.assertEqual((r.status, r.reviewed), ("HOLD", 0))

    def test_exact_duplicate_record_hold(self):
        candidate = batch_candidate()
        self.assertEqual(self.review((candidate, candidate)).status, "HOLD")

    def test_duplicate_grant_asset_capability_claim_hold(self):
        x = batch_candidate()
        y = dataclasses.replace(x, legacy=dataclasses.replace(x.legacy))
        self.assertEqual(self.review((x, y)).status, "HOLD")

    def test_incoherent_second_grant_atomic_hold(self):
        x = batch_candidate()
        y = batch_candidate(grant_id="G-2")
        y = dataclasses.replace(y, legacy=dataclasses.replace(y.legacy, reference="WRONG"))
        self.assertEqual((self.review((x, y)).status, self.review((x, y)).reviewed),
                         ("HOLD", 0))

    def test_second_record_invalid_capability_denied(self):
        x = batch_candidate()
        y = dataclasses.replace(batch_candidate(grant_id="G-2"), capability_id="OTHER")
        self.assertEqual(self.review((x, y)).status, "HOLD")

    def test_unhashable_asset_is_hold_not_exception(self):
        x = dataclasses.replace(batch_candidate(), asset=["forged"])
        self.assertEqual(self.review((x,)).status, "HOLD")

    def test_unhashable_capability_is_hold_not_exception(self):
        x = dataclasses.replace(batch_candidate(), capability_id=["forged"])
        self.assertEqual(self.review((x,)).status, "HOLD")

    def test_invalid_id_shape_denied_before_hash(self):
        x = batch_candidate()
        x = dataclasses.replace(x, durable=dataclasses.replace(x.durable, grant_id=[]))
        self.assertEqual(self.review((x,)).status, "HOLD")

    def test_untrusted_first_tenant_equality_is_never_called(self):
        class HostileEquality:
            def __eq__(self, other):
                raise AssertionError("untrusted equality executed")
            def __ne__(self, other):
                raise AssertionError("untrusted inequality executed")
        forged = dataclasses.replace(batch_candidate(), client_id=HostileEquality())
        self.assertEqual(self.review((forged,)).status, "HOLD")

    def test_untrusted_second_engagement_equality_is_never_called(self):
        class HostileEquality:
            def __eq__(self, other):
                raise AssertionError("untrusted equality executed")
            def __ne__(self, other):
                raise AssertionError("untrusted inequality executed")
        forged = dataclasses.replace(
            batch_candidate(grant_id="G-2"), engagement_id=HostileEquality())
        self.assertEqual(self.review((batch_candidate(), forged)).status, "HOLD")

    def test_naive_batch_clock_denied(self):
        self.assertEqual(review_cross_grant_batch(
            (batch_candidate(),), evaluated_at=NOW.replace(tzinfo=None)).status, "HOLD")

    def test_batch_bounds_32_accepted_with_distinct_synthetic_grants(self):
        batch = tuple(batch_candidate(grant_id=f"G-{i}") for i in range(32))
        r = self.review(batch)
        self.assertEqual((r.status, r.reviewed), ("REVIEW_ONLY", 32))

    def test_standalone_batch_never_reads_network_db_file_or_exec(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("sqlite")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
             patch("builtins.open", side_effect=AssertionError("file")):
            self.assertEqual(self.review((batch_candidate(),)).status, "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
