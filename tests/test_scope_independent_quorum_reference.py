"""Offline review reference: multiple independent reviewers never create authority.

Synthetic fixtures only. No network, production grant issuance, or dispatch.
"""
from dataclasses import dataclass
import re
import unittest


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z", re.ASCII)


@dataclass(frozen=True)
class Review:
    reviewer: str
    tenant: str
    request: str
    revision: int
    purpose: str
    approved: bool
    revoked: bool = False


@dataclass(frozen=True)
class ApprovalRequest:
    operator: str
    tenant: str
    request: str
    revision: int
    purpose: str


def reference_quorum(request, reviews, trusted_reviewers, minimum=2):
    """Consistency predicate only, NEVER a production authorization decision."""
    if type(request) is not ApprovalRequest or type(reviews) is not tuple:
        return False
    if type(trusted_reviewers) is not frozenset or type(minimum) is not int or minimum < 2:
        return False
    fields = (request.operator, request.tenant, request.request, request.purpose)
    if any(type(s) is not str or not _ID.fullmatch(s) for s in fields):
        return False
    if type(request.revision) is not int or request.revision < 1:
        return False
    if any(type(s) is not str or not _ID.fullmatch(s) for s in trusted_reviewers):
        return False
    if len(trusted_reviewers) < minimum or len(reviews) < minimum:
        return False
    seen = set()
    for review in reviews:
        if type(review) is not Review:
            return False
        if type(review.reviewer) is not str or not _ID.fullmatch(review.reviewer):
            return False
        if review.reviewer == request.operator or review.reviewer not in trusted_reviewers:
            return False
        if review.reviewer in seen:
            return False  # duplicate decisions are ambiguous; no vote multiplication
        seen.add(review.reviewer)
        if any(type(v) is not str or not _ID.fullmatch(v) for v in
               (review.tenant, review.request, review.purpose)):
            return False
        if (review.tenant, review.request, review.purpose) != (
                request.tenant, request.request, request.purpose):
            return False
        if type(review.revision) is not int or review.revision != request.revision:
            return False
        if review.approved is not True or review.revoked is not False:
            return False
    return len(seen) >= minimum


class IndependentReviewerQuorumReference(unittest.TestCase):
    def setUp(self):
        self.request = ApprovalRequest("operator", "tenant", "req", 4, "current")
        self.reviewers = frozenset({"alice", "bob", "carol"})
        self.votes = (Review("alice", "tenant", "req", 4, "current", True),
                      Review("bob", "tenant", "req", 4, "current", True))

    def check(self, votes=None, request=None, roster=None, minimum=2):
        return reference_quorum(self.request if request is None else request,
                                self.votes if votes is None else votes,
                                self.reviewers if roster is None else roster,
                                minimum)

    def test_matching_only_conditional(self):
        self.assertTrue(self.check())

    def test_single_vote_denied(self):
        self.assertFalse(self.check(votes=self.votes[:1]))

    def test_duplicate_vote_denied(self):
        self.assertFalse(self.check(votes=(self.votes[0], self.votes[0])))

    def test_self_approval_denied(self):
        self.assertFalse(self.check(votes=(self.votes[0],
                            Review("operator", "tenant", "req", 4, "current", True))))

    def test_untrusted_review_denied(self):
        self.assertFalse(self.check(votes=(self.votes[0],
                            Review("unknown", "tenant", "req", 4, "current", True))))

    def test_cross_boundary_denied(self):
        for field, value in (("tenant", "other"), ("request", "other"),
                             ("purpose", "future"), ("revision", 5)):
            with self.subTest(field=field):
                changed = {**self.votes[1].__dict__, field: value}
                self.assertFalse(self.check(votes=(self.votes[0], Review(**changed))))

    def test_withdrawn_or_negative_vote_denied(self):
        for values in ({"revoked": True}, {"approved": False},
                       {"approved": 1}, {"revoked": 0}, {"approved": "true"}):
            with self.subTest(values=values):
                self.assertFalse(self.check(votes=(self.votes[0],
                    Review(**{**self.votes[1].__dict__, **values}))))

    def test_malformed_identity_denied(self):
        for bad in ("", "alice\n", "alice\x00", "аlice", " alice", "alice\u200b"):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(self.check(votes=(
                    Review(bad, "tenant", "req", 4, "current", True), self.votes[1])))

    def test_bool_revision_and_minimum_denied(self):
        self.assertFalse(self.check(request=ApprovalRequest("operator", "tenant", "req", True, "current")))
        self.assertFalse(self.check(minimum=True))
        self.assertFalse(self.check(minimum=1))
        self.assertFalse(self.check(minimum=4))

    def test_forged_envelopes_denied(self):
        class ForgedReview(Review):
            pass
        class ForgedRequest(ApprovalRequest):
            pass
        self.assertFalse(self.check(votes=(ForgedReview(**self.votes[0].__dict__), self.votes[1])))
        self.assertFalse(self.check(request=ForgedRequest(**self.request.__dict__)))
        self.assertFalse(reference_quorum(self.request, list(self.votes), self.reviewers))
        self.assertFalse(reference_quorum(self.request, self.votes, {"alice", "bob"}))

    def test_higher_quorum_requires_three_distinct(self):
        self.assertFalse(self.check(minimum=3))
        self.assertTrue(self.check(votes=self.votes + (
            Review("carol", "tenant", "req", 4, "current", True),), minimum=3))

    def test_every_vote_must_be_valid_even_above_quorum(self):
        third = Review("carol", "tenant", "req", 4, "current", False)
        self.assertFalse(self.check(votes=self.votes + (third,)))
        self.assertFalse(self.check(votes=self.votes + (
            Review("alice", "tenant", "req", 4, "current", True),)))

    def test_request_identity_is_strict(self):
        for field, value in (("operator", "operator\n"), ("tenant", "tenant\x00"),
                             ("request", "req\u200b"), ("purpose", "future\r")):
            with self.subTest(field=field):
                self.assertFalse(self.check(request=ApprovalRequest(
                    **{**self.request.__dict__, field: value})))

    def test_malformed_roster_and_revision(self):
        for roster in (frozenset({"alice", "bob\n"}), frozenset({"alice", 2}),
                       frozenset({"alice"})):
            with self.subTest(roster=repr(roster)):
                self.assertFalse(self.check(roster=roster))
        for revision in (0, -1, 4.0, "4"):
            with self.subTest(revision=revision):
                self.assertFalse(self.check(request=ApprovalRequest(
                    "operator", "tenant", "req", revision, "current")))


if __name__ == "__main__":
    unittest.main()
