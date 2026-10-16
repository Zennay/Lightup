"""Ordinary offline tests for the unwired #1507 fictional review helper."""
import socket
import sqlite3
import subprocess
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from lightup.fictional_dual_party_review_1507 import (
    FictionalAcknowledgement,
    ReviewResult,
    review_fictional_acknowledgements,
)


NOW = datetime(2030, 4, 15, 12, 0, 0, tzinfo=timezone.utc)
START = NOW - timedelta(hours=1)
END = NOW + timedelta(hours=1)


def client(**changes):
    return replace(
        FictionalAcknowledgement(
            case_id="case-sample42",
            role="client",
            actor_id="fictional-client-demo1",
            asset="sandbox.example.test",
            capabilities=("inventory", "observe"),
            risk=2,
            issued_at=START,
            expires_at=END,
            decision="acknowledge",
            revoked=False,
        ),
        **changes,
    )


def operator(**changes):
    fields = {"role": "operator", "actor_id": "fictional-operator-demo2"}
    fields.update(changes)
    return replace(client(), **fields)


def verdict(c= None, o=None, at=NOW):
    return review_fictional_acknowledgements(
        (client() if c is None else c, operator() if o is None else o), at
    )


class FictionalDualPartyReviewTests(unittest.TestCase):
    def assert_no_authority(self, outcome):
        self.assertIs(type(outcome), ReviewResult)
        self.assertIs(outcome.authorized, False)
        self.assertIs(outcome.consent_verified, False)
        self.assertIs(outcome.dispatch_allowed, False)
        self.assertIs(outcome.release_allowed, False)
        self.assertIn(outcome.status, ("HOLD", "REVIEW_ONLY"))

    def assert_hold(self, c=None, o=None, at=NOW):
        result = verdict(c, o, at)
        self.assertEqual(result.status, "HOLD")
        self.assert_no_authority(result)
        self.assertEqual(repr(result).count("sandbox"), 0)

    def test_exact_matching_fictional_claims_are_only_review_only(self):
        self.assertEqual(verdict().status, "REVIEW_ONLY")
        self.assert_no_authority(verdict())

    def test_swapped_role_order_is_consistent_but_never_permission(self):
        result = review_fictional_acknowledgements((operator(), client()), NOW)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assert_no_authority(result)

    def test_no_claims_one_claim_extra_claim_list_tuple_subclass(self):
        class FakeTuple(tuple):
            pass
        for claims in (None, (), (client(),), (client(), operator(), client()),
                       [client(), operator()], FakeTuple((client(), operator()))):
            with self.subTest(claims=type(claims)):
                result = review_fictional_acknowledgements(claims, NOW)
                self.assertEqual(result.status, "HOLD")
                self.assert_no_authority(result)

    def test_no_duplicate_role_or_same_actor(self):
        self.assert_hold(o=client())
        self.assert_hold(o=operator(actor_id="fictional-client-demo1"))
        self.assert_hold(o=operator(role="client", actor_id="fictional-client-other"))

    def test_each_cross_party_proposal_dimension_must_be_equal(self):
        modifications = (
            {"case_id": "case-other"},
            {"asset": "second.example.test"},
            {"capabilities": ("observe",)},
            {"risk": 3},
            {"issued_at": START - timedelta(seconds=1)},
            {"expires_at": END + timedelta(seconds=1)},
        )
        for change in modifications:
            with self.subTest(change=change):
                self.assert_hold(o=operator(**change))

    def test_both_fictional_parties_can_agree_without_true_consent(self):
        first = client(risk=5, capabilities=("report",))
        second = operator(risk=5, capabilities=("report",))
        result = verdict(first, second)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assert_no_authority(result)

    def test_denial_or_revocation_wins_even_when_both_claims_agree(self):
        for change in ({"decision": "deny"}, {"decision": "pending"},
                       {"revoked": True}):
            with self.subTest(change=change):
                self.assert_hold(c=client(**change), o=operator(**change))

    def test_true_boolean_identity_mandatory(self):
        for bad in (0, 1, "", None, [], "false"):
            with self.subTest(bad=bad):
                self.assert_hold(c=client(revoked=bad))
        self.assert_hold(c=client(risk=True))
        self.assert_hold(c=client(risk=False))

    def test_trusted_roles_and_actor_prefixes_cannot_be_self_declared(self):
        for role, actor in (("client", "fictional-operator-demo2"),
                            ("operator", "fictional-client-demo1"),
                            ("admin", "fictional-operator-demo2"),
                            ("CLIENT", "fictional-client-demo1"),
                            ("clіent", "fictional-client-demo1"),
                            (1, "fictional-client-demo1")):
            with self.subTest(role=role, actor=actor):
                self.assert_hold(c=client(role=role, actor_id=actor))

    def test_fictional_actor_and_case_ids_are_exact_ascii(self):
        invalid = ("", "client-demo", "fictional-client-", "fictional-client-UP",
                   "fictional-client-a/b", "fictional-client-" + "x"*30,
                   "fictional-client-demo\x00", "fictional-client-démo")
        for actor in invalid:
            with self.subTest(actor=repr(actor)):
                self.assert_hold(c=client(actor_id=actor))
        for case in ("CASE-sample42", "case-", "case-hello/world", "case-é", "case-"+"z"*30):
            with self.subTest(case=case):
                self.assert_hold(c=client(case_id=case))

    def test_fictional_asset_only_and_no_punycode_or_domain_confusion(self):
        bad = ("example.com", "127.0.0.1", "sandbox.example.test.",
               "https://sandbox.example.test", "sandbox.example.test/path",
               "evil-example.test", "xn--evil.example.test", "a--b.example.test",
               "SANDBOX.example.test", "ä.example.test", "bad..example.test",
               "x"*35+".example.test", "sandbox.example.test\u202e")
        for asset in bad:
            with self.subTest(asset=repr(asset)):
                self.assert_hold(c=client(asset=asset))
        for valid in ("a.example.test", "lab-01.example.test"):
            first = client(asset=valid)
            second = operator(asset=valid)
            self.assertEqual(verdict(first, second).status, "REVIEW_ONLY")

    def test_capability_tuple_exact_sorted_unique_allowlist(self):
        invalid = ((), [], ["inventory"], ("observe", "inventory"),
                   ("report", "report"), ("execute",), ("obѕerve",),
                   ("observe", 1), ("inventory", "observe", "report", "extra"),
                   ("REPORT",))
        for caps in invalid:
            with self.subTest(caps=repr(caps)):
                self.assert_hold(c=client(capabilities=caps))
        class SubTuple(tuple):
            pass
        self.assert_hold(c=client(capabilities=SubTuple(("inventory",))))

    def test_risk_is_exact_bounded_integer(self):
        for bad in (-1, 0, 6, 100, 2.0, "2", None, True):
            with self.subTest(risk=bad):
                self.assert_hold(c=client(risk=bad))
        class SubInt(int):
            pass
        self.assert_hold(c=client(risk=SubInt(2)))

    def test_expired_future_and_window_bounds(self):
        for at in (START - timedelta(seconds=1), END,
                   END + timedelta(seconds=1)):
            with self.subTest(at=at):
                self.assert_hold(at=at)
        self.assert_hold(c=client(expires_at=START))
        self.assert_hold(c=client(expires_at=START - timedelta(seconds=1)))
        self.assert_hold(c=client(expires_at=START + timedelta(hours=25)))
        self.assert_hold(c=client(issued_at=END))
        self.assert_hold(c=client(issued_at=NOW + timedelta(seconds=1)))

    def test_utc_exact_second_required_on_all_instants(self):
        for at in (NOW.replace(tzinfo=None),
                   NOW.replace(tzinfo=timezone(timedelta(hours=1))),
                   NOW.replace(microsecond=1), NOW.replace(fold=1)):
            with self.subTest(at=at):
                self.assert_hold(at=at)
        for when in (START.replace(tzinfo=None),
                     START.replace(microsecond=4), START.replace(fold=1),
                     START.replace(tzinfo=timezone(timedelta(hours=1)))):
            with self.subTest(when=when):
                self.assert_hold(c=client(issued_at=when))

    def test_record_datetime_and_string_subclasses_are_not_trusted(self):
        class ForgedAck(FictionalAcknowledgement):
            pass
        class ForgedText(str):
            pass
        class ForgedTime(datetime):
            pass
        self.assert_hold(c=ForgedAck(**{name: getattr(client(), name)
                     for name in client().__dataclass_fields__}))
        self.assert_hold(c=client(case_id=ForgedText("case-sample42")))
        self.assert_hold(c=client(issued_at=ForgedTime.fromtimestamp(START.timestamp(), timezone.utc)))
        self.assert_hold(at=ForgedTime.fromtimestamp(NOW.timestamp(), timezone.utc))

    def test_no_original_object_or_datetime_mutation(self):
        before = client()
        other = operator()
        pair = (before, other)
        self.assertEqual(review_fictional_acknowledgements(pair, NOW).status, "REVIEW_ONLY")
        self.assertIs(pair[0], before)
        self.assertIs(pair[1], other)
        self.assertEqual(pair, (client(), operator()))

    def test_repeated_bad_inputs_are_generic_no_echo(self):
        secret = "REAL_CUSTOMER_SECRET_abc"
        for bad in (secret, secret+".example.test", "\u202e"+secret):
            res = verdict(client(asset=bad), operator(asset=bad))
            self.assertEqual(res.status, "HOLD")
            self.assertNotIn(secret, repr(res))
            self.assert_no_authority(res)

    def test_no_io_or_process_is_needed_by_review(self):
        with patch("builtins.open", side_effect=AssertionError("file")), \
             patch("socket.socket", side_effect=AssertionError("socket")), \
             patch("sqlite3.connect", side_effect=AssertionError("db")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            self.assertEqual(verdict().status, "REVIEW_ONLY")
            self.assert_hold(c=client(asset="private.host"))

    def test_plain_input_strings_never_claim_real_permission(self):
        for x in ("authorized", "APPROVED", "granted", "true", "release"):
            with self.subTest(status=x):
                self.assert_hold(c=client(decision=x))
                self.assert_no_authority(verdict())


if __name__ == "__main__":
    unittest.main()
