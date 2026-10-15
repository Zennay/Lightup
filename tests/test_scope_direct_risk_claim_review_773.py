"""No-network synthetic regression for #773 risk-only non-authorizing review."""
from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone
from enum import IntEnum

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind
from review_scope_direct_risk_claim_773 import (
    ReviewStatus,
    RiskReviewReceipt,
    MAX_SYNTHETIC_REVIEW_ITEMS,
    inspect_direct_scope_risk,
    inspect_direct_scope_risk_batch,
)


class ForeignRisk(IntEnum):
    PASSIVE = 1
    ELEVATED = 4
    SPOOFED = 99


class MisleadingRisk:
    def __int__(self):
        raise AssertionError("foreign risk value was evaluated")

    def __repr__(self):
        raise AssertionError("untrusted details were logged")


class ExplodingScope(ScopeDefinition):
    def __getattribute__(self, item):
        raise AssertionError("foreign scope descriptor was accessed")


class ExplodingComparator:
    def __lt__(self, other):
        raise AssertionError("foreign risk comparator should not be called")

    def __gt__(self, other):
        raise AssertionError("foreign risk comparator should not be called")

    def __repr__(self):
        raise AssertionError("foreign risk value should not be reflected")


class DirectRiskReviewTests(unittest.TestCase):
    def scope(self, risk=RiskLevel.STANDARD):
        return ScopeDefinition(
            assets=("fictional.invalid",),
            max_risk=risk,
            allowed_capabilities=("fictional-capability",),
            excluded_assets=(),
        )

    def assert_non_authorizing(self, receipt):
        self.assertIs(type(receipt.status), ReviewStatus)
        self.assertIn(receipt.status, (ReviewStatus.HOLD, ReviewStatus.REVIEW_ONLY))
        for key in (
            "authorized", "may_scan", "may_dispatch",
            "may_issue_grant", "release_ready", "may_deploy",
        ):
            self.assertIs(getattr(receipt, key), False)

    def test_canonical_levels_never_grant_authority(self):
        levels = (
            RiskLevel.ANALYSIS_ONLY, RiskLevel.PASSIVE,
            RiskLevel.LOW_IMPACT, RiskLevel.STANDARD, RiskLevel.ELEVATED,
        )
        for ceiling in levels:
            for requested in levels:
                with self.subTest(ceiling=ceiling, requested=requested):
                    receipt = inspect_direct_scope_risk(self.scope(ceiling), requested)
                    expected = (ReviewStatus.REVIEW_ONLY if requested.value <= ceiling.value
                                else ReviewStatus.HOLD)
                    self.assertIs(receipt.status, expected)
                    self.assert_non_authorizing(receipt)

    def test_single_review_detects_risk_mutation_during_enum_comparison(self):
        """A deterministic side effect during numeric comparison must HOLD."""
        from unittest.mock import patch

        original_getattribute = RiskLevel.__getattribute__
        for variant in ("different_enum", "raw_integer", "removed_field"):
            with self.subTest(variant=variant):
                scope = self.scope(RiskLevel.STANDARD)
                changes = []

                def mutate_during_value(member, name):
                    if name == "value" and member is RiskLevel.LOW_IMPACT and not changes:
                        changes.append(True)
                        if variant == "different_enum":
                            object.__setattr__(scope, "max_risk", RiskLevel.ELEVATED)
                        elif variant == "raw_integer":
                            scope.__dict__["max_risk"] = 99
                        else:
                            scope.__dict__.pop("max_risk", None)
                    return original_getattribute(member, name)

                with patch.object(RiskLevel, "__getattribute__", mutate_during_value):
                    receipt = inspect_direct_scope_risk(scope, RiskLevel.LOW_IMPACT)
                self.assertEqual(len(changes), 1)
                self.assertIs(receipt.status, ReviewStatus.HOLD)
                self.assertEqual(receipt.reason_code, "noncanonical_risk")
                self.assert_non_authorizing(receipt)
                self.assertIs(receipt.to_dict()["may_dispatch"], False)

    def test_missing_exact_scope_risk_ceiling_is_opaque_hold(self):
        """Partially built and field-deleted exact frozen scopes must not crash."""
        partial = object.__new__(ScopeDefinition)
        deleted = self.scope(RiskLevel.STANDARD)
        deleted.__dict__.pop("max_risk")
        for scope in (partial, deleted):
            receipt = inspect_direct_scope_risk(scope, RiskLevel.LOW_IMPACT)
            self.assertIs(receipt.status, ReviewStatus.HOLD)
            self.assertEqual(receipt.reason_code, "noncanonical_risk")
            self.assert_non_authorizing(receipt)
            self.assertEqual(receipt.to_dict()["may_dispatch"], False)

    def test_noncanonical_ceiling_types_all_hold(self):
        foreign = (
            -1, 0, 1, 3, 4, 99, True, False, 3.0, 4.0,
            "3", None, ForeignRisk.ELEVATED, ForeignRisk.SPOOFED,
            float("nan"), float("inf"), -float("inf"),
            ExplodingComparator(), MisleadingRisk(),
        )
        for max_risk in foreign:
            with self.subTest(case=type(max_risk).__name__):
                receipt = inspect_direct_scope_risk(
                    self.scope(max_risk), RiskLevel.STANDARD
                )
                self.assertIs(receipt.status, ReviewStatus.HOLD)
                self.assertEqual(receipt.reason_code, "noncanonical_risk")
                self.assert_non_authorizing(receipt)

    def test_noncanonical_requested_types_all_hold(self):
        foreign = (
            -1, 0, 1, 3, 4, 99, True, False, 3.0, 4.0,
            "3", None, ForeignRisk.ELEVATED, float("nan"),
            float("inf"), ExplodingComparator(), MisleadingRisk(),
        )
        for request in foreign:
            receipt = inspect_direct_scope_risk(self.scope(), request)
            self.assertIs(receipt.status, ReviewStatus.HOLD)
            self.assert_non_authorizing(receipt)

    def test_batch_noncanonical_numeric_and_comparator_claims_hold_opaquely(self):
        """Installed RED cases must never reach synthetic reviewer comparisons."""
        bad = (
            0, 4, 99, True, False, 0.0, 2.5,
            float("nan"), float("inf"),
            ForeignRisk.ELEVATED, ExplodingComparator(),
        )
        known_good = (self.scope(RiskLevel.STANDARD), RiskLevel.LOW_IMPACT)
        for ceiling in bad:
            with self.subTest(type=type(ceiling).__name__):
                receipt = inspect_direct_scope_risk_batch((
                    known_good,
                    (self.scope(ceiling), RiskLevel.ANALYSIS_ONLY),
                ))
                self.assertIs(receipt.status, ReviewStatus.HOLD)
                self.assertEqual(receipt.reason_code, "batch_hold")
                self.assert_non_authorizing(receipt)
                self.assertEqual(receipt.to_dict()["status"], "HOLD")

    def test_destructive_lab_tier_always_holds(self):
        for max_risk, requested in (
            (RiskLevel.DESTRUCTIVE_LAB_ONLY, RiskLevel.ANALYSIS_ONLY),
            (RiskLevel.DESTRUCTIVE_LAB_ONLY, RiskLevel.ELEVATED),
            (RiskLevel.DESTRUCTIVE_LAB_ONLY, RiskLevel.DESTRUCTIVE_LAB_ONLY),
            (RiskLevel.ELEVATED, RiskLevel.DESTRUCTIVE_LAB_ONLY),
        ):
            receipt = inspect_direct_scope_risk(self.scope(max_risk), requested)
            self.assertIs(receipt.status, ReviewStatus.HOLD)
            self.assertEqual(receipt.reason_code, "lab_only_risk")
            self.assert_non_authorizing(receipt)

    def test_scope_subclasses_and_other_objects_hold_without_access(self):
        foreign = (
            ExplodingScope(("fictional.invalid",), RiskLevel.STANDARD),
            {"max_risk": RiskLevel.STANDARD},
            None,
        )
        for scope in foreign:
            receipt = inspect_direct_scope_risk(scope, RiskLevel.STANDARD)
            self.assertIs(receipt.status, ReviewStatus.HOLD)
            self.assert_non_authorizing(receipt)

    def test_output_is_constant_size_and_contains_no_input(self):
        secret = "fictional-sensitive-opaque-marker-773"
        malicious = ScopeDefinition(
            assets=(secret,),
            max_risk=99,
            allowed_capabilities=(secret,),
        )
        receipt = inspect_direct_scope_risk(malicious, RiskLevel.STANDARD)
        self.assertNotIn(secret, repr(receipt))
        self.assertNotIn("fictional.invalid", repr(receipt))
        self.assert_non_authorizing(receipt)
        with self.assertRaises(AttributeError):
            receipt.authorized = True

    def test_receipt_constructor_cannot_set_release_flags(self):
        with self.assertRaises(TypeError):
            RiskReviewReceipt(
                ReviewStatus.REVIEW_ONLY, "risk_shape_only", authorized=True
            )
        valid = inspect_direct_scope_risk(
            self.scope(RiskLevel.ELEVATED), RiskLevel.PASSIVE
        )
        denied = inspect_direct_scope_risk(self.scope(99), RiskLevel.PASSIVE)
        for receipt in (valid, denied):
            serialized = receipt.to_dict()
            self.assertEqual(
                set(serialized), {
                    "status", "reason_code", "authorized", "may_scan",
                    "may_dispatch", "may_issue_grant", "release_ready",
                    "may_deploy",
                }
            )
            for key in (
                "authorized", "may_scan", "may_dispatch",
                "may_issue_grant", "release_ready", "may_deploy",
            ):
                self.assertIs(serialized[key], False)
            with self.assertRaises(AttributeError):
                receipt.authorized = True
            with self.assertRaises(AttributeError):
                object.__setattr__(receipt, "may_scan", True)
            serialized["may_scan"] = True
            self.assertIs(receipt.may_scan, False)
            self.assertIs(receipt.to_dict()["may_scan"], False)

    def test_forged_receipt_status_or_reason_cannot_escape_as_output(self):
        class HostilePayload:
            def __repr__(self):
                raise AssertionError("untrusted receipt was reflected")
            @property
            def value(self):
                raise AssertionError("untrusted status property was evaluated")

        fake_claim = "fictional-secret-claim-773"
        forged = (
            RiskReviewReceipt("APPROVED", fake_claim),
            RiskReviewReceipt(ReviewStatus.REVIEW_ONLY, fake_claim),
            RiskReviewReceipt(ReviewStatus.HOLD, fake_claim),
            RiskReviewReceipt(ReviewStatus.HOLD, "risk_shape_only"),
            RiskReviewReceipt(ReviewStatus.REVIEW_ONLY, "batch_hold"),
            RiskReviewReceipt(ReviewStatus.REVIEW_ONLY, 17),
            RiskReviewReceipt(HostilePayload(), fake_claim),
            RiskReviewReceipt(ReviewStatus.HOLD, HostilePayload()),
        )
        expected = {
            "status": "HOLD",
            "reason_code": "invalid_receipt",
            "authorized": False,
            "may_scan": False,
            "may_dispatch": False,
            "may_issue_grant": False,
            "release_ready": False,
            "may_deploy": False,
        }
        for receipt in forged:
            with self.subTest(case=type(receipt.status).__name__):
                self.assertEqual(receipt.to_dict(), expected)
                self.assertNotIn(fake_claim, str(receipt.to_dict()))
                for flag in (
                    "authorized", "may_scan", "may_dispatch",
                    "may_issue_grant", "release_ready", "may_deploy",
                ):
                    self.assertIs(receipt.to_dict()[flag], False)

    def test_polymorphic_reason_equality_is_never_called(self):
        class PoisonStr(str):
            def __eq__(self, other):
                raise AssertionError("untrusted equality hook evaluated")
            def __hash__(self):
                raise AssertionError("untrusted hash hook evaluated")
        bad = RiskReviewReceipt(ReviewStatus.REVIEW_ONLY, PoisonStr("risk_shape_only"))
        self.assertEqual(
            bad.to_dict()["reason_code"], "invalid_receipt",
        )
        self.assertEqual(bad.to_dict()["status"], "HOLD")
        self.assertIs(bad.to_dict()["may_dispatch"], False)

    def test_subclass_receipt_serialization_does_not_use_overrides(self):
        class HostileReceipt(RiskReviewReceipt):
            def __getattribute__(self, name):
                raise AssertionError("noncanonical receipt attribute accessed")
        forged = HostileReceipt(ReviewStatus.REVIEW_ONLY, "risk_shape_only")
        exported = RiskReviewReceipt.to_dict(forged)
        self.assertEqual(exported["status"], "HOLD")
        self.assertEqual(exported["reason_code"], "invalid_receipt")
        self.assertIs(exported["authorized"], False)
        self.assertIs(exported["may_dispatch"], False)

    def test_legitimate_single_and_batch_receipts_remain_canonical(self):
        single = inspect_direct_scope_risk(self.scope(), RiskLevel.LOW_IMPACT)
        batch = inspect_direct_scope_risk_batch(
            ((self.scope(), RiskLevel.LOW_IMPACT),)
        )
        denied = inspect_direct_scope_risk(self.scope(99), RiskLevel.LOW_IMPACT)
        for receipt, expected_status in (
            (single, "REVIEW_ONLY"),
            (batch, "REVIEW_ONLY"),
            (denied, "HOLD"),
        ):
            self.assertEqual(receipt.to_dict()["status"], expected_status)
            self.assertEqual(receipt.to_dict()["reason_code"], receipt.reason_code)
            self.assert_non_authorizing(receipt)

    def test_review_receipt_is_exact_immutable_tuple(self):
        receipt = inspect_direct_scope_risk(
            self.scope(RiskLevel.STANDARD), RiskLevel.LOW_IMPACT
        )
        self.assertIs(type(receipt), RiskReviewReceipt)
        self.assertIs(receipt.status, ReviewStatus.REVIEW_ONLY)
        self.assertEqual(len(receipt), 2)
        self.assertEqual(receipt._fields, ("status", "reason_code"))

    def test_reviewer_has_no_file_network_or_process_effects(self):
        """Real deny-tripwires around the pure in-memory inspection call."""
        import builtins
        import socket
        import subprocess
        from unittest.mock import patch

        allowed = self.scope(RiskLevel.STANDARD)
        corrupt = self.scope(99)

        def forbidden(*_args, **_kwargs):
            raise AssertionError("risk reviewer attempted external I/O")

        with (
            patch.object(builtins, "open", side_effect=forbidden),
            patch.object(os, "open", side_effect=forbidden),
            patch.object(os, "system", side_effect=forbidden),
            patch.object(socket, "socket", side_effect=forbidden),
            patch.object(socket, "create_connection", side_effect=forbidden),
            patch.object(subprocess, "Popen", side_effect=forbidden),
            patch.object(subprocess, "run", side_effect=forbidden),
        ):
            valid_receipt = inspect_direct_scope_risk(
                allowed, RiskLevel.LOW_IMPACT
            )
            denied_receipt = inspect_direct_scope_risk(
                corrupt, RiskLevel.LOW_IMPACT
            )
            batch_receipt = inspect_direct_scope_risk_batch((
                (allowed, RiskLevel.LOW_IMPACT),
                (corrupt, RiskLevel.LOW_IMPACT),
            ))
        self.assertIs(valid_receipt.status, ReviewStatus.REVIEW_ONLY)
        self.assertIs(denied_receipt.status, ReviewStatus.HOLD)
        self.assertIs(batch_receipt.status, ReviewStatus.HOLD)
        self.assert_non_authorizing(batch_receipt)
        self.assert_non_authorizing(valid_receipt)
        self.assert_non_authorizing(denied_receipt)

    def test_reviewer_module_static_import_boundary(self):
        """Freeze the opt-in module to enum/typing/model imports, no I/O SDKs."""
        import ast

        own_module = os.path.join(
            ROOT, "scripts", "review_scope_direct_risk_claim_773.py"
        )
        with open(own_module, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=own_module)
        allowed = {"__future__", "enum", "typing", "lightup.engagements"}
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.append(node.module)
            elif isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(
                    node.func.id,
                    {"open", "eval", "exec", "compile", "__import__", "input"},
                )
        self.assertEqual(set(imported), allowed)

    def test_atomic_batch_exact_limits_and_no_authority(self):
        for size in (1, 2, MAX_SYNTHETIC_REVIEW_ITEMS):
            claims = tuple(
                (self.scope(RiskLevel.ELEVATED), RiskLevel.PASSIVE)
                for _ in range(size)
            )
            receipt = inspect_direct_scope_risk_batch(claims)
            self.assertIs(receipt.status, ReviewStatus.REVIEW_ONLY)
            self.assertEqual(receipt.reason_code, "batch_risk_shape_only")
            self.assert_non_authorizing(receipt)
            serialized = receipt.to_dict()
            self.assertIs(serialized["may_dispatch"], False)
            self.assertIs(serialized["may_issue_grant"], False)
            self.assertEqual(
                set(serialized), {
                    "status", "reason_code", "authorized", "may_scan",
                    "may_dispatch", "may_issue_grant", "release_ready",
                    "may_deploy",
                },
            )

    def test_atomic_batch_malformed_inputs_are_opaque_hold(self):
        class PoisonTuple(tuple):
            def __iter__(self):
                raise AssertionError("subclass iteration invoked")
            def __len__(self):
                raise AssertionError("subclass length invoked")

        known_good = (self.scope(), RiskLevel.PASSIVE)
        malformed = (
            (),
            tuple(known_good for _ in range(MAX_SYNTHETIC_REVIEW_ITEMS + 1)),
            [known_good],
            PoisonTuple((known_good,)),
            (PoisonTuple(known_good),),
            (None,),
            ((),),
            ((self.scope(),),),
            ((self.scope(), RiskLevel.PASSIVE, "third"),),
            ((ExplodingScope(("fictional.invalid",), RiskLevel.STANDARD),
              RiskLevel.PASSIVE),),
            ((self.scope(), MisleadingRisk()),),
            ((self.scope(99), RiskLevel.STANDARD),),
            ((self.scope(RiskLevel.PASSIVE), RiskLevel.STANDARD),),
            ((self.scope(RiskLevel.DESTRUCTIVE_LAB_ONLY), RiskLevel.STANDARD),),
        )
        receipts = [inspect_direct_scope_risk_batch(value) for value in malformed]
        for receipt in receipts:
            self.assertIs(receipt.status, ReviewStatus.HOLD)
            self.assertEqual(receipt.reason_code, "batch_hold")
            self.assert_non_authorizing(receipt)
            self.assertEqual(
                receipt.to_dict(),
                receipts[0].to_dict(),
                "all malformed batch claim shapes must receive the same opaque HOLD",
            )

    def test_batch_detects_in_call_mutation_of_earlier_frozen_scope(self):
        """A later synthetic claim cannot conceal a changed prior risk ceiling."""
        import review_scope_direct_risk_claim_773 as module
        from unittest.mock import patch

        original_inspect = module.inspect_direct_scope_risk
        for mutation in ("object_setattr", "dict_write", "remove_field"):
            first = self.scope(RiskLevel.STANDARD)
            second = self.scope(RiskLevel.STANDARD)
            def mutate_during_second(scope, risk):
                if scope is second:
                    if mutation == "object_setattr":
                        object.__setattr__(first, "max_risk", RiskLevel.ELEVATED)
                    elif mutation == "dict_write":
                        first.__dict__["max_risk"] = 99
                    else:
                        first.__dict__.pop("max_risk", None)
                return original_inspect(scope, risk)

            with self.subTest(mutation=mutation):
                with patch.object(module, "inspect_direct_scope_risk",
                                  side_effect=mutate_during_second):
                    receipt = module.inspect_direct_scope_risk_batch((
                        (first, RiskLevel.LOW_IMPACT),
                        (second, RiskLevel.LOW_IMPACT),
                    ))
                self.assertEqual(receipt.to_dict()["status"], "HOLD")
                self.assertEqual(receipt.reason_code, "batch_hold")
                self.assert_non_authorizing(receipt)

    def test_batch_detects_deletion_during_inspection(self):
        """A later callback clearing a field never leaks a partial verdict."""
        import review_scope_direct_risk_claim_773 as module
        from unittest.mock import patch

        original = module.inspect_direct_scope_risk
        first = self.scope(RiskLevel.ELEVATED)
        second = self.scope(RiskLevel.ELEVATED)

        def drop_current(current, risk):
            if current is first:
                current.__dict__.pop("max_risk", None)
            return original(current, risk)

        with patch.object(module, "inspect_direct_scope_risk",
                          side_effect=drop_current):
            receipt = module.inspect_direct_scope_risk_batch((
                (first, RiskLevel.LOW_IMPACT),
                (second, RiskLevel.LOW_IMPACT),
            ))
        self.assertIs(receipt.status, ReviewStatus.HOLD)
        self.assertEqual(receipt.reason_code, "batch_hold")
        self.assert_non_authorizing(receipt)

    def test_batch_detects_mutation_during_own_inspection(self):
        """Even the current element is checked against its initial risk identity."""
        import review_scope_direct_risk_claim_773 as module
        from unittest.mock import patch

        original_inspect = module.inspect_direct_scope_risk
        scope = self.scope(RiskLevel.STANDARD)

        def mutate_before_return(current_scope, risk):
            receipt = original_inspect(current_scope, risk)
            object.__setattr__(current_scope, "max_risk", RiskLevel.PASSIVE)
            return receipt

        with patch.object(module, "inspect_direct_scope_risk",
                          side_effect=mutate_before_return):
            receipt = module.inspect_direct_scope_risk_batch((
                (scope, RiskLevel.LOW_IMPACT),
            ))
        self.assertIs(receipt.status, ReviewStatus.HOLD)
        self.assertEqual(receipt.reason_code, "batch_hold")
        self.assert_non_authorizing(receipt)

    def test_batch_stable_aliases_remain_review_only(self):
        """Repeated references are safe to review while unchanged in-call."""
        same = self.scope(RiskLevel.STANDARD)
        claims = tuple(
            (same, RiskLevel.LOW_IMPACT) for _ in range(MAX_SYNTHETIC_REVIEW_ITEMS)
        )
        receipt = inspect_direct_scope_risk_batch(claims)
        self.assertIs(receipt.status, ReviewStatus.REVIEW_ONLY)
        self.assert_non_authorizing(receipt)

    def test_batch_reference_risk_grid_all_sizes(self):
        """Independent numeric oracle for 5x5 canonical ceilings and bounded N."""
        levels = (
            RiskLevel.ANALYSIS_ONLY, RiskLevel.PASSIVE,
            RiskLevel.LOW_IMPACT, RiskLevel.STANDARD, RiskLevel.ELEVATED,
        )
        for n in (1, 2, 4, 16, MAX_SYNTHETIC_REVIEW_ITEMS):
            for ceiling in levels:
                for requested in levels:
                    with self.subTest(n=n, ceiling=ceiling, requested=requested):
                        claims = tuple(
                            (self.scope(ceiling), requested) for _ in range(n)
                        )
                        result = inspect_direct_scope_risk_batch(claims)
                        oracle = (
                            ReviewStatus.REVIEW_ONLY if requested.value <= ceiling.value
                            else ReviewStatus.HOLD
                        )
                        self.assertIs(result.status, oracle)
                        self.assert_non_authorizing(result)
                        self.assertIs(result.to_dict()["may_scan"], False)

    def test_batch_invalid_member_at_every_position_holds(self):
        """No prefix of good entries can turn later bad metadata into approval."""
        good = (self.scope(RiskLevel.STANDARD), RiskLevel.LOW_IMPACT)
        bad = (self.scope(RiskLevel.PASSIVE), RiskLevel.ELEVATED)
        for n in (1, 2, 7, MAX_SYNTHETIC_REVIEW_ITEMS):
            for pos in range(n):
                claims = tuple(bad if i == pos else good for i in range(n))
                receipt = inspect_direct_scope_risk_batch(claims)
                self.assertIs(receipt.status, ReviewStatus.HOLD)
                self.assertEqual(receipt.reason_code, "batch_hold")
                self.assert_non_authorizing(receipt)

    def test_batch_permutations_never_hide_a_single_bad_risk(self):
        import random

        good = (self.scope(RiskLevel.STANDARD), RiskLevel.LOW_IMPACT)
        invalid = (self.scope(ForeignRisk.SPOOFED), RiskLevel.STANDARD)
        rng = random.Random(773)
        for size in (1, 2, 3, 8, MAX_SYNTHETIC_REVIEW_ITEMS):
            claims = [good for _ in range(size)]
            for _ in range(60):
                # Every position receives an invalid entry in one permutation.
                position = rng.randrange(size)
                permuted = list(claims)
                permuted[position] = invalid
                rng.shuffle(permuted)
                receipt = inspect_direct_scope_risk_batch(tuple(permuted))
                self.assertIs(receipt.status, ReviewStatus.HOLD)
                self.assertEqual(receipt.reason_code, "batch_hold")
                self.assert_non_authorizing(receipt)
            self.assertIs(
                inspect_direct_scope_risk_batch(tuple(claims)).status,
                ReviewStatus.REVIEW_ONLY,
            )

    def test_atomic_batch_no_io_or_untrusted_repr(self):
        class HostileRisk:
            def __repr__(self):
                raise AssertionError("risk input was reflected")
            def __iter__(self):
                raise AssertionError("risk input was iterated")

        for size in (1, 16, MAX_SYNTHETIC_REVIEW_ITEMS):
            claims = tuple(
                (self.scope(), RiskLevel.PASSIVE)
                for _ in range(size - 1)
            ) + ((self.scope(), HostileRisk()),)
            receipt = inspect_direct_scope_risk_batch(claims)
            self.assertEqual(receipt.to_dict()["status"], "HOLD")
            self.assertNotIn("fictional.invalid", repr(receipt))
            self.assert_non_authorizing(receipt)

    def test_canonical_risk_request_order_only_narrows(self):
        levels = [RiskLevel.ANALYSIS_ONLY, RiskLevel.PASSIVE,
                  RiskLevel.LOW_IMPACT, RiskLevel.STANDARD, RiskLevel.ELEVATED]
        for ceiling in levels:
            reviews = [
                inspect_direct_scope_risk(self.scope(ceiling), requested).status
                for requested in levels
            ]
            first_hold = next((idx for idx, s in enumerate(reviews)
                               if s is ReviewStatus.HOLD), len(reviews))
            self.assertTrue(all(s is ReviewStatus.REVIEW_ONLY
                                for s in reviews[:first_hold]))
            self.assertTrue(all(s is ReviewStatus.HOLD
                                for s in reviews[first_hold:]))

    def installed_direct_decision(self, max_risk, requested_risk):
        """Only a local synthetic model fixture; never a target/scan."""
        grant = AuthorizationGrant(
            grant_id="synthetic-grant", client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            approved_by="synthetic-operator", reference="fictional-ref",
            scope=self.scope(max_risk),
            valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
            valid_until=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
        return ExecutionPolicy().decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="fictional.invalid",
            capability_id="fictional-capability",
            requested_risk=requested_risk,
            authorization=grant,
        ))

    def test_installed_policy_exact_canonical_risk_ceiling_matrix_control(self):
        """25 source-backed positive/negative controls: avoid vacuous REDs."""
        levels = (
            RiskLevel.ANALYSIS_ONLY, RiskLevel.PASSIVE,
            RiskLevel.LOW_IMPACT, RiskLevel.STANDARD, RiskLevel.ELEVATED,
        )
        for ceiling in levels:
            for requested in levels:
                with self.subTest(ceiling=ceiling, requested=requested):
                    actual = self.installed_direct_decision(ceiling, requested)
                    expected = requested.value <= ceiling.value
                    self.assertIs(
                        actual.allowed, expected,
                        "canonical installed policy semantics must not change",
                    )

    @unittest.expectedFailure
    def test_known_installed_raw_integer_alias_matrix_expected_red(self):
        """Production direct scope must reject *all* raw int risk ceilings."""
        noncanonical = (-1, 0, 1, 2, 3, 4, 5, 6, 99)
        admitted = tuple(
            value for value in noncanonical
            if self.installed_direct_decision(
                value, RiskLevel.ANALYSIS_ONLY
            ).allowed
        )
        self.assertEqual(
            admitted, (),
            "raw integer risk ceilings remain accepted by installed source",
        )

    @unittest.expectedFailure
    def test_known_installed_false_bool_alias_expected_red(self):
        """False is int zero and can incorrectly mean analysis-only scope."""
        decision = self.installed_direct_decision(
            False, RiskLevel.ANALYSIS_ONLY
        )
        self.assertIs(
            decision.allowed, False,
            "False is not a canonical RiskLevel ceiling",
        )

    @unittest.expectedFailure
    def test_known_installed_foreign_intenum_alias_matrix_expected_red(self):
        """Even equal foreign IntEnum members cannot stand in for RiskLevel."""
        admitted = tuple(
            member.name for member in ForeignRisk
            if self.installed_direct_decision(
                member, RiskLevel.ANALYSIS_ONLY
            ).allowed
        )
        self.assertEqual(
            admitted, (),
            "foreign IntEnum equivalents still widen installed active scope",
        )

    @unittest.expectedFailure
    def test_known_installed_float_and_nan_alias_matrix_expected_red(self):
        """Float and NaN comparisons must never become direct risk authority."""
        cases = (
            ("zero", 0.0), ("fraction", 2.5),
            ("infinity", float("inf")), ("nan", float("nan")),
        )
        admitted = tuple(
            name for name, ceiling in cases
            if self.installed_direct_decision(
                ceiling, RiskLevel.ANALYSIS_ONLY
            ).allowed
        )
        self.assertEqual(
            admitted, (),
            "unordered NaN and float risk ceilings are not canonical grants",
        )

    @unittest.expectedFailure
    def test_known_installed_custom_comparator_alias_expected_red(self):
        """An untrusted object can lie about risk comparison on direct grant."""
        class ForgedComparator:
            def __lt__(self, other):
                return False

            def __repr__(self):
                raise AssertionError("untrusted comparator was reflected")

        decision = self.installed_direct_decision(
            ForgedComparator(), RiskLevel.STANDARD
        )
        self.assertIs(
            decision.allowed, False,
            "untrusted right-hand comparison must never permit target-active",
        )

    @unittest.expectedFailure
    def test_known_installed_policy_bool_true_active_risk_expected_red(self):
        """bool is int-like; truthiness must not mint a risk ceiling."""
        decision = self.installed_direct_decision(True, RiskLevel.PASSIVE)
        self.assertFalse(
            decision.allowed,
            "boolean max_risk=True must never allow TARGET_ACTIVE",
        )

    @unittest.expectedFailure
    def test_known_installed_policy_foreign_intenum_99_expected_red(self):
        """A foreign IntEnum numerically equal to 99 is not RiskLevel."""
        decision = self.installed_direct_decision(
            ForeignRisk.SPOOFED, RiskLevel.STANDARD
        )
        self.assertFalse(
            decision.allowed,
            "foreign IntEnum max_risk=99 must never allow TARGET_ACTIVE",
        )

    @unittest.expectedFailure
    def test_known_installed_policy_direct_int_99_authority_gap_expected_red(self):
        """Source-owner #773 must eventually reject this, not this reviewer.

        Expected RED documents the installed code gap on main without asserting
        a false passing authorization fix. Remove decorator only after a real
        owner fix makes the negative test pass on the exact tested source head.
        """
        decision = self.installed_direct_decision(99, RiskLevel.STANDARD)
        self.assertFalse(
            decision.allowed,
            "direct noncanonical scope.max_risk=99 must never authorize TARGET_ACTIVE",
        )


if __name__ == "__main__":
    unittest.main()
