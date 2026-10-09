"""Offline negative-only reference: audit receipts cannot authorize execution.

This is deliberately NOT a production authorization implementation.
"""
import dataclasses
import unittest


@dataclasses.dataclass(frozen=True)
class Receipt:
    tenant: str
    request: str
    outcome: str
    correlation: str


@dataclasses.dataclass(frozen=True)
class LiveGrant:
    tenant: str
    request: str
    capability: str
    active: bool
    revision: int


def reference_admit(*, receipt, grant, tenant, request, capability, revision):
    """A receipt is audit-only; live grant checks remain mandatory."""
    if type(receipt) is not Receipt or type(grant) is not LiveGrant:
        return False
    if type(tenant) is not str or type(request) is not str:
        return False
    if type(capability) is not str or type(revision) is not int:
        return False
    if not tenant or not request or not capability or revision < 1:
        return False
    if type(grant.active) is not bool or grant.active is not True:
        return False
    if type(grant.revision) is not int or grant.revision < 1:
        return False
    if any(type(value) is not str or not value for value in (
        grant.tenant, grant.request, grant.capability
    )):
        return False
    return (
        grant.tenant == tenant
        and grant.request == request
        and grant.capability == capability
        and grant.revision == revision
    )


class ReceiptNonAuthorityReference(unittest.TestCase):
    def setUp(self):
        self.receipt = Receipt("tenant-a", "request-a", "allowed", "trace-1")
        self.grant = LiveGrant("tenant-a", "request-a", "http_baseline", True, 3)
        self.args = dict(tenant="tenant-a", request="request-a",
                         capability="http_baseline", revision=3)

    def test_positive_is_conditional_on_live_grant(self):
        self.assertTrue(reference_admit(receipt=self.receipt, grant=self.grant, **self.args))

    def test_success_receipt_cannot_replace_absent_or_revoked_grant(self):
        for grant in (None, dataclasses.replace(self.grant, active=False)):
            with self.subTest(grant=grant):
                self.assertFalse(reference_admit(receipt=self.receipt, grant=grant, **self.args))

    def test_receipt_correlation_does_not_grant_authority(self):
        for correlation in ("trace-1", "admin-approved", "grant:all", ""):
            receipt = dataclasses.replace(self.receipt, correlation=correlation)
            self.assertFalse(reference_admit(
                receipt=receipt, grant=dataclasses.replace(self.grant, active=False),
                **self.args))

    def test_current_grant_binding_is_required(self):
        for key, value in (("tenant", "tenant-b"), ("request", "request-b"),
                           ("capability", "service_inventory"), ("revision", 4)):
            with self.subTest(key=key):
                self.assertFalse(reference_admit(
                    receipt=self.receipt, grant=self.grant, **(self.args | {key: value})))

    def test_malformed_grant_status_and_revision_fail_closed(self):
        for grant in (dataclasses.replace(self.grant, active=1),
                      dataclasses.replace(self.grant, active="yes"),
                      dataclasses.replace(self.grant, revision=True)):
            with self.subTest(grant=grant):
                self.assertFalse(reference_admit(receipt=self.receipt, grant=grant, **self.args))

    def test_receipt_outcome_is_non_authoritative(self):
        for outcome in ("allowed", "denied", "revoked", "approved", ""):
            with self.subTest(outcome=outcome):
                receipt = dataclasses.replace(self.receipt, outcome=outcome)
                self.assertTrue(reference_admit(
                    receipt=receipt, grant=self.grant, **self.args))
                self.assertFalse(reference_admit(
                    receipt=receipt, grant=dataclasses.replace(self.grant, active=False),
                    **self.args))

    def test_polymorphic_grant_fields_cannot_cross_boundary(self):
        class Identity(str):
            pass
        for field in ("tenant", "request", "capability"):
            with self.subTest(field=field):
                grant = dataclasses.replace(
                    self.grant, **{field: Identity(getattr(self.grant, field))})
                self.assertFalse(reference_admit(
                    receipt=self.receipt, grant=grant, **self.args))

    def test_invalid_grant_revision_cannot_authorize(self):
        for revision in (0, -1, 3.0, "3"):
            with self.subTest(revision=revision):
                grant = dataclasses.replace(self.grant, revision=revision)
                self.assertFalse(reference_admit(
                    receipt=self.receipt, grant=grant, **self.args))

    def test_receipt_subclass_is_not_a_trusted_envelope(self):
        class ForgedReceipt(Receipt):
            pass
        self.assertFalse(reference_admit(
            receipt=ForgedReceipt("tenant-a", "request-a", "allowed", "trace-1"),
            grant=self.grant, **self.args))


if __name__ == "__main__":
    unittest.main()
