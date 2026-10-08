"""Offline reference only: delegation eligibility is not execution permission."""
import dataclasses
import unittest


@dataclasses.dataclass(frozen=True)
class Grant:
    tenant: str
    engagement: str
    principal: str
    asset: str
    capability: str
    max_risk: int
    revision: int
    active: bool


@dataclasses.dataclass(frozen=True)
class Child:
    tenant: str
    engagement: str
    principal: str
    asset: str
    capability: str
    risk: int
    revision: int


def eligible(child, issuer_grant, *, trusted_lookup, audit_available):
    """Pure, intentionally restrictive fixture; NOT production authorization."""
    if type(child) is not Child or type(issuer_grant) is not Grant:
        return False
    if trusted_lookup is not True or audit_available is not True:
        return False
    if type(issuer_grant.active) is not bool or issuer_grant.active is not True:
        return False
    if type(child.risk) is not int or type(issuer_grant.max_risk) is not int:
        return False
    if type(child.revision) is not int or type(issuer_grant.revision) is not int:
        return False
    if not all(type(v) is str and bool(v) for v in (
        child.tenant, child.engagement, child.principal, child.asset, child.capability,
        issuer_grant.tenant, issuer_grant.engagement, issuer_grant.principal,
        issuer_grant.asset, issuer_grant.capability
    )):
        return False
    return (
        child.tenant == issuer_grant.tenant
        and child.engagement == issuer_grant.engagement
        and child.principal == issuer_grant.principal
        and child.asset == issuer_grant.asset
        and child.capability == issuer_grant.capability
        and child.risk >= 0
        and 0 <= issuer_grant.max_risk <= 5
        and child.risk <= issuer_grant.max_risk
        and child.revision == issuer_grant.revision
    )


class NoTransitiveDelegationReferenceTests(unittest.TestCase):
    def setUp(self):
        self.grant = Grant("tenant-a", "eng-a", "worker-b", "asset-a",
                           "headers", 2, 7, True)
        self.child = Child("tenant-a", "eng-a", "worker-b", "asset-a",
                           "headers", 1, 7)

    def evaluate(self, child=None, grant=None, **overrides):
        args = {"trusted_lookup": True, "audit_available": True}
        args.update(overrides)
        return eligible(self.child if child is None else child,
                        self.grant if grant is None else grant, **args)

    def test_positive_reference_is_only_eligible(self):
        self.assertTrue(self.evaluate())

    def test_missing_trusted_lookup_denies(self):
        self.assertFalse(self.evaluate(trusted_lookup=False))

    def test_parent_principal_does_not_authorize_child(self):
        self.assertFalse(self.evaluate(child=dataclasses.replace(self.child, principal="worker-c")))

    def test_cross_tenant_denies(self):
        self.assertFalse(self.evaluate(child=dataclasses.replace(self.child, tenant="tenant-b")))

    def test_cross_engagement_denies(self):
        self.assertFalse(self.evaluate(child=dataclasses.replace(self.child, engagement="eng-b")))

    def test_widened_asset_denies(self):
        self.assertFalse(self.evaluate(child=dataclasses.replace(self.child, asset="asset-b")))

    def test_widened_capability_denies(self):
        self.assertFalse(self.evaluate(child=dataclasses.replace(self.child, capability="tls")))

    def test_risk_escalation_denies(self):
        self.assertFalse(self.evaluate(child=dataclasses.replace(self.child, risk=3)))

    def test_revoked_parent_denies(self):
        self.assertFalse(self.evaluate(grant=dataclasses.replace(self.grant, active=False)))

    def test_stale_revision_denies(self):
        self.assertFalse(self.evaluate(child=dataclasses.replace(self.child, revision=6)))

    def test_audit_outage_denies(self):
        self.assertFalse(self.evaluate(audit_available=False))

    def test_truthy_flags_do_not_count_as_trust(self):
        self.assertFalse(self.evaluate(trusted_lookup=1))
        self.assertFalse(self.evaluate(grant=dataclasses.replace(self.grant, active=1)))

    def test_type_confusion_denies(self):
        self.assertFalse(self.evaluate(child=dataclasses.replace(self.child, risk=True)))
        self.assertFalse(self.evaluate(child=dataclasses.replace(self.child, revision="7")))

    def test_original_inputs_unchanged(self):
        before = (self.grant, self.child)
        self.evaluate()
        self.assertEqual(before, (self.grant, self.child))


if __name__ == "__main__":
    unittest.main()
