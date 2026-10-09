"""Offline reference for non-transferable scope consent; never authorizes execution."""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class Consent:
    tenant_id: str
    engagement_id: str
    owner_id: str
    asset_id: str
    capability_id: str
    revision: int
    approved: bool


def matches_consent(consent: Consent, *, tenant_id: str, engagement_id: str,
                    owner_id: str, asset_id: str, capability_id: str,
                    revision: int, revoked: bool) -> bool:
    """Illustrative all-field exact binding; not a trusted grant issuer."""
    fields = (consent.tenant_id, consent.engagement_id, consent.owner_id,
              consent.asset_id, consent.capability_id)
    requested = (tenant_id, engagement_id, owner_id, asset_id, capability_id)
    if any(type(value) is not str or not value.strip() for value in fields + requested):
        return False
    if type(consent.revision) is not int or type(revision) is not int:
        return False
    if type(consent.approved) is not bool or type(revoked) is not bool:
        return False
    return (consent.approved is True and revoked is False
            and consent.revision == revision and fields == requested)


class ScopeConsentNontransferabilityReferenceTests(unittest.TestCase):
    def setUp(self):
        self.consent = Consent("tenant-A", "engagement-A", "owner-A",
                               "asset-A", "web-baseline", 3, True)
        self.request = dict(tenant_id="tenant-A", engagement_id="engagement-A",
                            owner_id="owner-A", asset_id="asset-A",
                            capability_id="web-baseline", revision=3, revoked=False)

    def test_exact_match_reference_only(self):
        self.assertTrue(matches_consent(self.consent, **self.request))

    def test_reject_cross_tenant_transfer(self):
        self.assertFalse(matches_consent(self.consent, **(self.request | {"tenant_id": "tenant-B"})))

    def test_reject_engagement_reuse(self):
        self.assertFalse(matches_consent(self.consent, **(self.request | {"engagement_id": "engagement-B"})))

    def test_reject_owner_change_even_same_asset(self):
        self.assertFalse(matches_consent(self.consent, **(self.request | {"owner_id": "owner-B"})))

    def test_reject_asset_or_capability_reassignment(self):
        for field, value in (("asset_id", "asset-B"), ("capability_id", "tls-baseline")):
            with self.subTest(field=field):
                self.assertFalse(matches_consent(self.consent, **(self.request | {field: value})))

    def test_reject_stale_revision_or_revocation(self):
        for changes in ({"revision": 4}, {"revoked": True}):
            with self.subTest(changes=changes):
                self.assertFalse(matches_consent(self.consent, **(self.request | changes)))

    def test_reject_truthy_nonboolean_approval(self):
        self.assertFalse(matches_consent(Consent("tenant-A", "engagement-A", "owner-A",
                                                "asset-A", "web-baseline", 3, "true"),
                                         **self.request))

    def test_reject_bool_revision_and_polymorphic_identity(self):
        self.assertFalse(matches_consent(self.consent, **(self.request | {"revision": True})))
        class Forged(str):
            pass
        self.assertFalse(matches_consent(self.consent, **(self.request | {"owner_id": Forged("owner-A")})))

    def test_reject_empty_identity_or_malformed_revocation(self):
        self.assertFalse(matches_consent(self.consent, **(self.request | {"tenant_id": "  "})))
        self.assertFalse(matches_consent(self.consent, **(self.request | {"revoked": 0})))


if __name__ == "__main__":
    unittest.main()
