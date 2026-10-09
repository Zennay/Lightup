"""Offline reference for binding scope authorization to one dispatch attempt.

Not an executable production permission or a substitute for issuer verification.
"""
import dataclasses
import unittest


@dataclasses.dataclass(frozen=True)
class AttemptGrant:
    tenant: str
    request: str
    scope_revision: int
    attempt: str
    grant_id: str
    active: bool


def canonical_token(value):
    return type(value) is str and 0 < len(value) <= 128 and value.isascii() and all(
        char.isalnum() or char in "-_" for char in value
    )


def reference_attempt_bound(grant, *, tenant, request, revision, attempt, grant_id):
    """Reference equality predicate only; caller must authenticate grant provenance."""
    if type(grant) is not AttemptGrant or type(grant.active) is not bool or grant.active is not True:
        return False
    if type(grant.scope_revision) is not int or type(revision) is not int or revision < 0:
        return False
    for value in (grant.tenant, grant.request, grant.attempt, grant.grant_id,
                  tenant, request, attempt, grant_id):
        if not canonical_token(value):
            return False
    return (
        grant.tenant == tenant
        and grant.request == request
        and grant.scope_revision == revision
        and grant.attempt == attempt
        and grant.grant_id == grant_id
    )


class AttemptBindingReferenceTests(unittest.TestCase):
    def setUp(self):
        self.grant = AttemptGrant("tenant-A", "request-1", 3, "attempt-1", "grant-1", True)
        self.claim = dict(tenant="tenant-A", request="request-1", revision=3,
                          attempt="attempt-1", grant_id="grant-1")

    def check(self, grant=None, **overrides):
        claim = dict(self.claim)
        claim.update(overrides)
        return reference_attempt_bound(self.grant if grant is None else grant, **claim)

    def test_matching_reference_only(self):
        self.assertTrue(self.check())

    def test_replay_into_new_attempt_denied(self):
        self.assertFalse(self.check(attempt="attempt-2"))

    def test_request_or_tenant_swap_denied(self):
        self.assertFalse(self.check(request="request-2"))
        self.assertFalse(self.check(tenant="tenant-B"))

    def test_revision_or_grant_swap_denied(self):
        self.assertFalse(self.check(revision=4))
        self.assertFalse(self.check(grant_id="grant-2"))

    def test_inactive_and_truthy_active_denied(self):
        self.assertFalse(self.check(grant=dataclasses.replace(self.grant, active=False)))
        self.assertFalse(self.check(grant=dataclasses.replace(self.grant, active=1)))

    def test_type_confusion_denied(self):
        self.assertFalse(self.check(revision=True))
        self.assertFalse(self.check(attempt=1))
        self.assertFalse(self.check(tenant=b"tenant-A"))
        self.assertFalse(self.check(grant=dataclasses.replace(self.grant, scope_revision=True)))

    def test_ambiguous_tokens_denied(self):
        for token in ("", " attempt-1", "attempt-1 ", "attempt\n1", "attempt/1",
                      "attémpt", "x" * 129):
            with self.subTest(token=token):
                self.assertFalse(self.check(attempt=token))

    def test_subclass_envelope_denied(self):
        class ForgedGrant(AttemptGrant):
            pass
        self.assertFalse(self.check(grant=ForgedGrant(**dataclasses.asdict(self.grant))))

    def test_reference_does_not_mutate_inputs(self):
        original = dataclasses.asdict(self.grant), dict(self.claim)
        self.check()
        self.assertEqual(original, (dataclasses.asdict(self.grant), self.claim))

    def test_negative_revision_is_never_authority(self):
        self.assertFalse(self.check(grant=dataclasses.replace(self.grant, scope_revision=-1), revision=-1))

    def test_all_grant_identity_fields_are_validated(self):
        for field in ("tenant", "request", "attempt", "grant_id"):
            with self.subTest(field=field):
                self.assertFalse(self.check(grant=dataclasses.replace(self.grant, **{field: "bad token"})))

    def test_all_claim_identity_fields_are_validated(self):
        for field in ("tenant", "request", "attempt", "grant_id"):
            with self.subTest(field=field):
                self.assertFalse(self.check(**{field: "bad\\tvalue"}))

    def test_invalid_grant_envelopes_are_denied(self):
        self.assertFalse(self.check(grant=None))
        self.assertFalse(self.check(grant=dataclasses.asdict(self.grant)))


if __name__ == "__main__":
    unittest.main()
