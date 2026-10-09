"""Offline reference: HTTP cache metadata is never authorization authority.

Synthetic objects only. Does not grant rights or contact targets.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class LiveGrant:
    tenant: str
    request: str
    revision: int
    capability: str
    active: bool
    revoked: bool


@dataclass(frozen=True)
class Dispatch:
    tenant: str
    request: str
    revision: int
    capability: str


def reference_eligible(grant, dispatch, cache_metadata):
    """Necessary consistency predicate, never sufficient for production dispatch.

    Cache metadata deliberately cannot supply missing or stale grant authority.
    """
    if type(grant) is not LiveGrant or type(dispatch) is not Dispatch:
        return False
    if type(grant.active) is not bool or grant.active is not True:
        return False
    if type(grant.revoked) is not bool or grant.revoked is not False:
        return False
    for value in (grant.tenant, grant.request, grant.capability,
                  dispatch.tenant, dispatch.request, dispatch.capability):
        if type(value) is not str or not value or len(value) > 128:
            return False
        if not value.isascii() or not all(c.isalnum() or c in "_-" for c in value):
            return False
    if type(grant.revision) is not int or type(dispatch.revision) is not int:
        return False
    if grant.revision < 1:
        return False
    # No decisions are taken from HTTP ETag, Age, Cache-Control, 304,
    # cached policy documents or intermediaries. It is untrusted metadata.
    _ = cache_metadata
    return (grant.tenant == dispatch.tenant and
            grant.request == dispatch.request and
            grant.revision == dispatch.revision and
            grant.capability == dispatch.capability)


class HttpCacheNonAuthorityReferenceTests(unittest.TestCase):
    def setUp(self):
        self.grant = LiveGrant("tenant_a", "req_a", 2, "headers", True, False)
        self.dispatch = Dispatch("tenant_a", "req_a", 2, "headers")

    def test_matching_live_reference_is_only_conditional(self):
        self.assertTrue(reference_eligible(self.grant, self.dispatch, None))

    def test_304_does_not_revive_revoked_grant(self):
        revoked = LiveGrant("tenant_a", "req_a", 2, "headers", True, True)
        self.assertFalse(reference_eligible(revoked, self.dispatch, {"status": 304}))

    def test_fresh_etag_does_not_activate_inactive_grant(self):
        inactive = LiveGrant("tenant_a", "req_a", 2, "headers", False, False)
        self.assertFalse(reference_eligible(inactive, self.dispatch, {"etag": '"approved"'}))

    def test_max_age_does_not_resurrect_stale_revision(self):
        stale = LiveGrant("tenant_a", "req_a", 1, "headers", True, False)
        self.assertFalse(reference_eligible(stale, self.dispatch, {"cache_control": "max-age=86400"}))

    def test_cached_success_does_not_change_tenant(self):
        altered = Dispatch("tenant_b", "req_a", 2, "headers")
        self.assertFalse(reference_eligible(self.grant, altered, {"status": 200, "approved": True}))

    def test_cached_success_does_not_change_request(self):
        altered = Dispatch("tenant_a", "req_b", 2, "headers")
        self.assertFalse(reference_eligible(self.grant, altered, {"status": 200}))

    def test_cached_success_does_not_expand_capability(self):
        altered = Dispatch("tenant_a", "req_a", 2, "tls")
        self.assertFalse(reference_eligible(self.grant, altered, {"etag": "current"}))

    def test_truthy_active_or_revoked_is_denied(self):
        self.assertFalse(reference_eligible(
            LiveGrant("tenant_a", "req_a", 2, "headers", 1, False),
            self.dispatch, {"age": 0}))
        self.assertFalse(reference_eligible(
            LiveGrant("tenant_a", "req_a", 2, "headers", True, 0),
            self.dispatch, {"age": 0}))

    def test_revision_bool_is_denied(self):
        self.assertFalse(reference_eligible(
            LiveGrant("tenant_a", "req_a", True, "headers", True, False),
            self.dispatch, {"status": 304}))

    def test_ambiguous_identifiers_denied_even_when_equal(self):
        for value in (" tenant_a", "tenant/a", "t\\ntenant", "ténant", ""):
            with self.subTest(value=value):
                grant = LiveGrant(value, "req_a", 2, "headers", True, False)
                dispatch = Dispatch(value, "req_a", 2, "headers")
                self.assertFalse(reference_eligible(grant, dispatch, {}))

    def test_forged_envelopes_denied(self):
        class ForgedGrant(LiveGrant):
            pass
        self.assertFalse(reference_eligible(ForgedGrant(
            "tenant_a", "req_a", 2, "headers", True, False), self.dispatch, {}))
        self.assertFalse(reference_eligible(self.grant, vars(self.dispatch), {}))

    def test_hostile_cache_object_not_inspected(self):
        class HostileCache:
            def __getattribute__(self, name):
                raise AssertionError("cache metadata must not be inspected")
        self.assertTrue(reference_eligible(self.grant, self.dispatch, HostileCache()))


if __name__ == "__main__":
    unittest.main()
