"""Offline security regression for opt-in legacy temporal review (#301).

Independent of installed Authorization.is_current, which remains a known RED.
All identities are synthetic and no target I/O is performed.
"""
import ast
import os
import sys
import unittest
import random
from pathlib import Path
from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization
from lightup.legacy_temporal_shape_review_301 import (
    LegacyTemporalReview, review_legacy_authorization_window,
    review_legacy_authorization_batch
)

START = datetime(2026, 10, 15, 12, tzinfo=timezone.utc)
END = START + timedelta(hours=1)
MID = START + timedelta(minutes=30)


def fixture(*, start=START, end=END):
    return Authorization(
        owner="FICTIONAL_DO_NOT_AUTHORIZE",
        reference="FAKE_APPROVAL_NOT_CONSENT",
        valid_from=start,
        valid_until=end,
    )


_DEFAULT_AUTH = object()


def review(auth=_DEFAULT_AUTH, now=MID):
    return review_legacy_authorization_window(
        fixture() if auth is _DEFAULT_AUTH else auth, observed_at=now
    )


def assert_non_authorizing(testcase, result, status, reason):
    testcase.assertIs(type(result), LegacyTemporalReview)
    testcase.assertEqual((result.status, result.reason), (status, reason))
    receipt = result.as_receipt()
    testcase.assertEqual((receipt["status"], receipt["reason"]), (status, reason))
    testcase.assertEqual(set(receipt), {
        "status", "reason", "authorization_verified", "permit_issued",
        "execution_enabled", "target_dispatch_allowed", "merge_approved",
        "release_approved"
    })
    for key in set(receipt) - {"status", "reason"}:
        testcase.assertIs(receipt[key], False)
    testcase.assertNotIn("FICTIONAL_DO_NOT_AUTHORIZE", str(receipt))
    testcase.assertNotIn("FAKE_APPROVAL_NOT_CONSENT", str(receipt))


class _DatetimeSpoof(datetime):
    def __lt__(self, other):
        return False

    def __gt__(self, other):
        return False

    def __le__(self, other):
        return True

    def __ge__(self, other):
        return True


class _MaliciousTZ(tzinfo):
    def utcoffset(self, value):
        raise AssertionError("custom tzinfo must never be consulted")

    def dst(self, value):
        raise AssertionError("custom tzinfo must never be consulted")


class _FakeAuthorization(Authorization):
    pass


class _TupleSubclass(tuple):
    pass



def _source_has_only_offline_effects(source):
    """Offline static tripwire, deliberately independent of runtime reviewer."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    approved_imports = {
        "__future__", "datetime", "typing", "lightup.models"
    }
    permitted_calls = {
        "type", "len", "range", "tuple", "list", "_stored_fields",
        "LegacyTemporalReview", "_canonical_datetime",
        "review_legacy_authorization_window"
    }
    # Bounded append mutates only the local, synthetic in-memory snapshot list.
    # It does not touch a client record, target, filesystem, or process.
    permitted_methods = {"astimezone", "append", "__getattribute__", "__getitem__"}
    for node in ast.walk(tree):
        # An attribute access on the untrusted Authorization instance itself
        # can dispatch a monkeypatched getter; use only _stored_fields().
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in {"authorization", "verdict", "self"}
        ):
            return False
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if not isinstance(node, ast.ImportFrom) or node.module not in approved_imports:
                return False
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id not in permitted_calls:
                    return False
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr not in permitted_methods:
                    return False
                if node.func.attr == "append" and not (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "snapshots"
                ):
                    return False
                if node.func.attr == "__getattribute__" and not (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "object"
                    and len(node.args) == 2
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id == "authorization"
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value == "__dict__"
                ):
                    return False
                if node.func.attr == "__getitem__" and not (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "tuple"
                    and len(node.args) == 2
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id in {"self", "verdict"}
                    and isinstance(node.args[1], ast.Constant)
                    and type(node.args[1].value) is int
                    and node.args[1].value in (0, 1)
                ):
                    return False
            else:
                return False
    return True


class LegacyTemporalShapeReviewTests(unittest.TestCase):
    def test_canonical_valid_window_is_only_review(self):
        assert_non_authorizing(self, review(), "REVIEW_ONLY", "temporal_shape_only")

    def test_exact_inclusive_endpoints_and_microsecond_expiry(self):
        for instant in (START, MID, END):
            with self.subTest(instant=instant):
                assert_non_authorizing(self, review(now=instant),
                                       "REVIEW_ONLY", "temporal_shape_only")
        for instant in (START - timedelta(microseconds=1),
                        END + timedelta(microseconds=1)):
            assert_non_authorizing(self, review(now=instant), "HOLD", "outside_window")

    def test_valid_fixed_offset_zone_equivalence(self):
        plus = timezone(timedelta(hours=5, minutes=30))
        minus = timezone(timedelta(hours=-7))
        claim = fixture(start=START.astimezone(plus), end=END.astimezone(minus))
        assert_non_authorizing(self, review(claim, MID.astimezone(plus)),
                               "REVIEW_ONLY", "temporal_shape_only")

    def test_inverted_and_open_windows(self):
        assert_non_authorizing(self, review(fixture(start=END, end=START)),
                               "HOLD", "inverted_window")
        assert_non_authorizing(self, review(fixture(start=None, end=None)),
                               "HOLD", "unbounded_window")
        for claim in (fixture(start=None), fixture(end=None)):
            assert_non_authorizing(self, review(claim),
                                   "REVIEW_ONLY", "temporal_shape_only")

    def test_falsy_and_polymorphic_bounds_fail_closed(self):
        bad = [False, 0, 0.0, "", (), [], {}, object(),
               START.replace(tzinfo=None),
               _DatetimeSpoof(2026, 10, 15, 12, tzinfo=timezone.utc),
               datetime(2026, 10, 15, 12, tzinfo=_MaliciousTZ())]
        for bad_bound in bad:
            for field in ("valid_from", "valid_until"):
                with self.subTest(field=field, cls=type(bad_bound).__name__):
                    claim = replace(fixture(), **{field: bad_bound})
                    assert_non_authorizing(self, review(claim), "HOLD", "invalid_shape")

    def test_polymorphic_or_implicit_evaluation_time_fails_closed(self):
        for instant in (None, False, 0, "", [], {},
                        MID.replace(tzinfo=None),
                        _DatetimeSpoof(2026, 10, 15, 12, 30, tzinfo=timezone.utc),
                        datetime(2026, 10, 15, 12, tzinfo=_MaliciousTZ())):
            with self.subTest(cls=type(instant).__name__):
                assert_non_authorizing(self, review(now=instant),
                                       "HOLD", "invalid_shape")

    def test_forged_authorization_type_is_denied(self):
        auth = fixture()
        assert_non_authorizing(self, review(_FakeAuthorization(**vars(auth))),
                               "HOLD", "invalid_shape")
        for invalid in (None, {}, [], "authorization"):
            assert_non_authorizing(self, review(invalid), "HOLD", "invalid_shape")

    def test_forged_receipt_cannot_assert_permission(self):
        for malicious in (
            LegacyTemporalReview("APPROVED", "grant"),
            LegacyTemporalReview("REVIEW_ONLY", "invalid_shape"),
            LegacyTemporalReview("HOLD", "temporal_shape_only"),
            LegacyTemporalReview(True, "outside_window"),
            LegacyTemporalReview("HOLD", object()),
        ):
            receipt = malicious.as_receipt()
            self.assertEqual((receipt["status"], receipt["reason"]),
                             ("HOLD", "invalid_shape"))
            for key in set(receipt) - {"status", "reason"}:
                self.assertIs(receipt[key], False)
        with self.assertRaises(TypeError):
            LegacyTemporalReview("REVIEW_ONLY", "temporal_shape_only",
                                 permit_issued=True)

    def test_receipt_uses_builtin_tuple_slots_not_patchable_getters(self):
        valid = LegacyTemporalReview("REVIEW_ONLY", "temporal_shape_only")
        invalid = LegacyTemporalReview("APPROVED", "pretend_grant")
        calls = []

        def hostile_getattribute(instance, name):
            calls.append(name)
            raise AssertionError("receipt getter executed")

        with patch.object(LegacyTemporalReview, "__getattribute__",
                          hostile_getattribute):
            # Canonical method lookup via class, as patched instance lookup
            # is untrusted. The method itself must never invoke the getter.
            accepted = LegacyTemporalReview.as_receipt(valid)
            denied = LegacyTemporalReview.as_receipt(invalid)
        self.assertEqual(calls, [])
        self.assertEqual((accepted["status"], accepted["reason"]),
                         ("REVIEW_ONLY", "temporal_shape_only"))
        self.assertEqual((denied["status"], denied["reason"]),
                         ("HOLD", "invalid_shape"))
        for receipt in (accepted, denied):
            for key in set(receipt) - {"status", "reason"}:
                self.assertIs(receipt[key], False)

    def test_batch_avoids_patchable_receipt_getter(self):
        auth = fixture()
        calls = []

        def hostile_getattribute(instance, name):
            calls.append(name)
            raise AssertionError("batch verdict getter executed")

        with patch.object(LegacyTemporalReview, "__getattribute__",
                          hostile_getattribute):
            valid = review_legacy_authorization_batch(
                (auth, auth), observed_at=MID
            )
            bad = review_legacy_authorization_batch(
                (auth, fixture(end=False)), observed_at=MID
            )
        self.assertEqual(calls, [])
        assert_non_authorizing(self, valid, "REVIEW_ONLY", "temporal_shape_only")
        assert_non_authorizing(self, bad, "HOLD", "invalid_batch")

    def test_forged_tuple_payload_never_runs_equality_hooks(self):
        import lightup.legacy_temporal_shape_review_301 as review_module

        class _EvilEquality:
            def __eq__(self, other):
                raise AssertionError("malicious comparator executed")

            def __repr__(self):
                raise AssertionError("malicious repr executed")

        forged = LegacyTemporalReview("REVIEW_ONLY", _EvilEquality())
        receipt = LegacyTemporalReview.as_receipt(forged)
        self.assertEqual((receipt["status"], receipt["reason"]),
                         ("HOLD", "invalid_shape"))
        for key in set(receipt) - {"status", "reason"}:
            self.assertIs(receipt[key], False)

        with patch.object(
            review_module, "review_legacy_authorization_window",
            return_value=forged
        ):
            decision = review_legacy_authorization_batch(
                (fixture(),), observed_at=MID
            )
        assert_non_authorizing(self, decision, "HOLD", "invalid_batch")

    def test_extreme_builtin_offsets_cannot_escape_as_overflow_exception(self):
        eastern = timezone(timedelta(hours=23))
        western = timezone(timedelta(hours=-23))
        near_floor = datetime.min.replace(tzinfo=eastern)
        near_ceiling = datetime.max.replace(tzinfo=western)
        for invalid in (near_floor, near_ceiling):
            with self.subTest(kind="observed", year=invalid.year):
                assert_non_authorizing(self, review(now=invalid),
                                       "HOLD", "invalid_shape")
            for field in ("valid_from", "valid_until"):
                with self.subTest(field=field, year=invalid.year):
                    auth = replace(fixture(), **{field: invalid})
                    assert_non_authorizing(self, review(auth),
                                           "HOLD", "invalid_shape")

    def test_missing_datetime_field_is_an_opaque_hold(self):
        incomplete = object.__new__(Authorization)
        assert_non_authorizing(self, review(incomplete), "HOLD", "invalid_shape")
        object.__setattr__(incomplete, "valid_from", START)
        assert_non_authorizing(self, review(incomplete), "HOLD", "invalid_shape")

    def test_getter_side_effect_cannot_execute_or_mutate_the_reviewed_window(self):
        auth = fixture()
        calls = []

        def forbidden_getter(instance, name):
            if instance is auth:
                calls.append(name)
                object.__setattr__(instance, "valid_until", False)
                raise AssertionError("untrusted getter invoked")
            return object.__getattribute__(instance, name)

        with patch.object(Authorization, "__getattribute__", forbidden_getter):
            assert_non_authorizing(self, review(auth),
                                   "REVIEW_ONLY", "temporal_shape_only")
            assert_non_authorizing(
                self, review_legacy_authorization_batch((auth,), observed_at=MID),
                "REVIEW_ONLY", "temporal_shape_only"
            )
        self.assertEqual(calls, [])
        self.assertIs(object.__getattribute__(auth, "__dict__")["valid_until"], END)

    def test_source_effect_guard_detects_offline_policy_regressions(self):
        path = Path(__file__).resolve().parent.parent / "src/lightup/legacy_temporal_shape_review_301.py"
        source = path.read_text(encoding="utf-8")
        self.assertTrue(_source_has_only_offline_effects(source))
        for mutant in (
            "open('/tmp/should-not-exist', 'w')",
            "__import__('socket')",
            "from socket import socket",
            "import subprocess",
            "datetime.now()",
            "os.system('echo forbidden')",
            "obj.astimezone().open()",
            "external.append(authorization)",
            "authorization.valid_from",
            "authorization.valid_until",
            "authorization.__dict__",
            "authorization.reference",
            "self.status",
            "self.reason",
            "verdict.status",
            "verdict.reason",
            "tuple.__getitem__(authorization, 0)",
            "tuple.__getitem__(verdict, 2)",
            "tuple.__getitem__(verdict, True)",
            "tuple.__getitem__(other, 0)",
            "vars(authorization)",
            "object.__getattribute__(authorization, 'reference')",
            "object.__getattribute__(other, '__dict__')",
            "getattr(obj, 'scope')",
        ):
            with self.subTest(mutant=mutant):
                self.assertFalse(_source_has_only_offline_effects(source + "\n" + mutant))

    def test_full_temporal_grid_matches_independent_inclusive_reference(self):
        # An independent arithmetic oracle avoids reusing the source's
        # comparison implementation. No customer, grant, or target exists.
        minutes = (-75, -45, -30, -15, 0, 15, 30, 45, 75)
        for offset in (-8, 0, 5.5):
            zone = timezone(timedelta(hours=offset))
            for start_offset in minutes:
                for end_offset in minutes:
                    first = (MID + timedelta(minutes=start_offset)).astimezone(zone)
                    last = (MID + timedelta(minutes=end_offset)).astimezone(zone)
                    auth = fixture(start=first, end=last)
                    if start_offset > end_offset:
                        expected = ("HOLD", "inverted_window")
                        batch_expected = ("HOLD", "invalid_batch")
                    elif start_offset <= 0 <= end_offset:
                        expected = ("REVIEW_ONLY", "temporal_shape_only")
                        batch_expected = expected
                    else:
                        expected = ("HOLD", "outside_window")
                        batch_expected = ("HOLD", "invalid_batch")
                    with self.subTest(zone=offset, start=start_offset, end=end_offset):
                        assert_non_authorizing(self, review(auth), *expected)
                        assert_non_authorizing(
                            self,
                            review_legacy_authorization_batch(
                                (auth,), observed_at=MID
                            ), *batch_expected
                        )

    def test_batch_fixed_offset_instant_and_inclusive_metaproperties(self):
        offsets = (-12, -8, -1, 0, 1, 5.5, 12, 14)
        for offset in offsets:
            zone = timezone(timedelta(hours=offset))
            claim = fixture(start=START.astimezone(zone),
                            end=END.astimezone(zone))
            for instant in (START, MID, END):
                with self.subTest(offset=offset, at=instant.isoformat()):
                    assert_non_authorizing(
                        self,
                        review_legacy_authorization_batch(
                            (claim, claim), observed_at=instant.astimezone(zone)
                        ), "REVIEW_ONLY", "temporal_shape_only"
                    )
            for instant in (START - timedelta(microseconds=1),
                            END + timedelta(microseconds=1)):
                assert_non_authorizing(
                    self,
                    review_legacy_authorization_batch(
                        (claim,), observed_at=instant.astimezone(zone)
                    ), "HOLD", "invalid_batch"
                )

    def test_deceptive_dual_getter_cannot_spoof_raw_storage_and_expiry(self):
        auth = fixture(end=False)
        original = Authorization.__getattribute__
        forged_fields = dict(vars(auth), valid_until=END)

        def deceptive_getter(instance, name):
            if instance is auth and name == "__dict__":
                return forged_fields
            if instance is auth and name == "valid_until":
                return END
            return original(instance, name)

        with patch.object(Authorization, "__getattribute__", deceptive_getter):
            assert_non_authorizing(
                self, review(auth), "HOLD", "invalid_shape"
            )
            assert_non_authorizing(
                self,
                review_legacy_authorization_batch((auth,), observed_at=MID),
                "HOLD", "invalid_batch"
            )

    def test_spoofed_dict_does_not_override_genuine_valid_storage(self):
        auth = fixture()
        original = Authorization.__getattribute__
        bogus = {"valid_from": False, "valid_until": False}

        def lying_storage(instance, name):
            if instance is auth and name == "__dict__":
                return bogus
            return original(instance, name)

        with patch.object(Authorization, "__getattribute__", lying_storage):
            assert_non_authorizing(
                self, review(auth), "REVIEW_ONLY", "temporal_shape_only"
            )
            assert_non_authorizing(
                self,
                review_legacy_authorization_batch((auth,), observed_at=MID),
                "REVIEW_ONLY", "temporal_shape_only"
            )

    def test_single_hidden_stored_falsy_window_cannot_appear_reviewable(self):
        auth = fixture(end=False)
        original = Authorization.__getattribute__

        def lying_getter(instance, name):
            if instance is auth and name == "valid_until":
                return END
            return original(instance, name)

        with patch.object(Authorization, "__getattribute__", lying_getter):
            verdict = review(auth)
        assert_non_authorizing(self, verdict, "HOLD", "invalid_shape")

    def test_late_getter_mutation_hook_is_not_invoked(self):
        auth = fixture()
        touched = []

        def late_mutator(instance, name):
            if instance is auth:
                touched.append(name)
                object.__setattr__(instance, "valid_until", False)
                raise AssertionError("late mutation hook invoked")
            return object.__getattribute__(instance, name)

        with patch.object(Authorization, "__getattribute__", late_mutator):
            assert_non_authorizing(
                self, review(auth), "REVIEW_ONLY", "temporal_shape_only"
            )
            assert_non_authorizing(
                self, review_legacy_authorization_batch((auth,), observed_at=MID),
                "REVIEW_ONLY", "temporal_shape_only"
            )
        self.assertEqual(touched, [])
        self.assertIs(object.__getattribute__(auth, "__dict__")["valid_until"], END)

    def test_single_late_stored_field_drift_is_a_hold(self):
        import lightup.legacy_temporal_shape_review_301 as review_module

        auth = fixture()
        original = review_module._stored_fields
        reads = [0]

        def change_at_last_read(subject):
            reads[0] += 1
            data = original(subject)
            if subject is auth and reads[0] == 2:
                object.__setattr__(subject, "valid_until", False)
            return data

        with patch.object(review_module, "_stored_fields",
                          side_effect=change_at_last_read):
            verdict = review(auth)
        self.assertEqual(reads[0], 2)
        assert_non_authorizing(self, verdict, "HOLD", "invalid_shape")

    def test_batch_final_storage_read_detects_late_rebinding(self):
        import lightup.legacy_temporal_shape_review_301 as review_module

        auth = fixture()
        original = review_module._stored_fields
        reads = [0]

        def change_at_final_batch_read(subject):
            reads[0] += 1
            data = original(subject)
            # Batch snapshot + single review initial + single review final,
            # followed by the batch-wide final consistency check.
            if subject is auth and reads[0] == 4:
                object.__setattr__(subject, "valid_from", False)
            return data

        with patch.object(review_module, "_stored_fields",
                          side_effect=change_at_final_batch_read):
            verdict = review_legacy_authorization_batch(
                (auth,), observed_at=MID
            )
        self.assertEqual(reads[0], 4)
        assert_non_authorizing(self, verdict, "HOLD", "invalid_batch")

    def test_batch_exact_tuple_size_bounds_and_no_authority(self):
        for size in (1, 2, 16, 32):
            claim = tuple(fixture() for _ in range(size))
            with self.subTest(size=size):
                assert_non_authorizing(
                    self,
                    review_legacy_authorization_batch(claim, observed_at=MID),
                    "REVIEW_ONLY", "temporal_shape_only"
                )
        for bad in ((), (fixture(),) * 33, [fixture()],
                    _TupleSubclass((fixture(),)), object(), None):
            with self.subTest(bad_type=type(bad).__name__):
                assert_non_authorizing(
                    self,
                    review_legacy_authorization_batch(bad, observed_at=MID),
                    "HOLD", "invalid_batch"
                )

    def test_batch_refuses_any_invalid_member_independent_of_position(self):
        for size in (1, 2, 8, 32):
            for invalid_index in range(size):
                claims = [fixture() for _ in range(size)]
                claims[invalid_index] = fixture(end=False)
                with self.subTest(size=size, invalid_index=invalid_index):
                    assert_non_authorizing(
                        self,
                        review_legacy_authorization_batch(
                            tuple(claims), observed_at=MID
                        ), "HOLD", "invalid_batch"
                    )

    def test_batch_denies_invalid_member_types_and_evaluation_time(self):
        for invalid in (None, object(), {}, _FakeAuthorization(**vars(fixture())),
                        fixture(start=END, end=START), fixture(start=None, end=None),
                        fixture(start=END + timedelta(seconds=1)),
                        fixture(end=START - timedelta(seconds=1))):
            with self.subTest(kind=type(invalid).__name__):
                assert_non_authorizing(
                    self,
                    review_legacy_authorization_batch(
                        (fixture(), invalid, fixture()), observed_at=MID
                    ), "HOLD", "invalid_batch"
                )
        for bad_now in (None, False, "", MID.replace(tzinfo=None),
                        _DatetimeSpoof(2026, 10, 15, 12, 30, tzinfo=timezone.utc)):
            assert_non_authorizing(
                self,
                review_legacy_authorization_batch(
                    (fixture(),), observed_at=bad_now
                ), "HOLD", "invalid_batch"
            )

    def test_batch_is_permutation_invariant_and_no_partial_leaks(self):
        rng = random.Random(301)
        claims = [fixture() for _ in range(9)] + [fixture(end=0)]
        for _ in range(150):
            rng.shuffle(claims)
            verdict = review_legacy_authorization_batch(
                tuple(claims), observed_at=MID
            )
            assert_non_authorizing(self, verdict, "HOLD", "invalid_batch")
            self.assertNotIn("10", str(verdict.as_receipt()))
            self.assertEqual(
                verdict.as_receipt(),
                review_legacy_authorization_batch(
                    (fixture(end=False),), observed_at=MID
                ).as_receipt()
            )

    def test_batch_detects_earlier_claim_rebinding_during_later_review(self):
        import lightup.legacy_temporal_shape_review_301 as review_module

        first = fixture()
        second = fixture()
        original = review_module.review_legacy_authorization_window
        seen = {"count": 0}

        def mutating_review(auth, *, observed_at):
            result = original(auth, observed_at=observed_at)
            seen["count"] += 1
            if seen["count"] == 2:
                object.__setattr__(first, "valid_until", START)
            return result

        with patch.object(
            review_module, "review_legacy_authorization_window",
            side_effect=mutating_review
        ):
            result = review_legacy_authorization_batch(
                (first, second), observed_at=MID
            )
        self.assertEqual(seen["count"], 2)
        assert_non_authorizing(self, result, "HOLD", "invalid_batch")

    def test_batch_preserves_external_effect_denial(self):
        with (
            patch("builtins.open", side_effect=AssertionError("file access")),
            patch("socket.socket", side_effect=AssertionError("network access")),
            patch("subprocess.Popen", side_effect=AssertionError("process access")),
        ):
            assert_non_authorizing(
                self,
                review_legacy_authorization_batch(
                    (fixture(), fixture()), observed_at=MID
                ), "REVIEW_ONLY", "temporal_shape_only"
            )

    def test_no_external_effects_or_clock_lookup(self):
        # Imports already complete: actual reviewer must not open files, spawn
        # processes, resolve hosts, or read current time for synthetic review.
        with (
            patch("builtins.open", side_effect=AssertionError("file access")),
            patch("socket.socket", side_effect=AssertionError("network access")),
            patch("subprocess.Popen", side_effect=AssertionError("process access")),
        ):
            assert_non_authorizing(self, review(), "REVIEW_ONLY", "temporal_shape_only")
            assert_non_authorizing(self, review(fixture(end=False)),
                                   "HOLD", "invalid_shape")

    def test_receipt_snapshot_is_fresh_and_non_authorizing(self):
        verdict = review()
        first = verdict.as_receipt()
        first["permit_issued"] = True
        self.assertIs(verdict.as_receipt()["permit_issued"], False)


if __name__ == "__main__":
    unittest.main()
