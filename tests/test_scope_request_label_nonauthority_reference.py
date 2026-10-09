"""Offline reference: human-readable request labels must never mint scope authority.

This is not a production authorization engine. No network, target, or I/O.
"""
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Request:
    tenant_id: str
    request_id: str
    asset_id: str
    capability_id: str
    purpose: str
    label: str = ""


@dataclass(frozen=True)
class Grant:
    tenant_id: str
    request_id: str
    assets: tuple[str, ...]
    capabilities: tuple[str, ...]
    purpose: str
    approved: bool


def reference_permit(request: Request, grant: Grant) -> bool:
    """Narrow, in-memory identity comparison; label is deliberately ignored."""
    if type(request) is not Request or type(grant) is not Grant:
        return False
    if type(grant.approved) is not bool or not grant.approved:
        return False
    identities = (request.tenant_id, request.request_id, request.asset_id,
                  request.capability_id, request.purpose, grant.tenant_id,
                  grant.request_id, grant.purpose)
    if any(type(value) is not str or not value or len(value) > 128
           or not value.isascii() or not all(ch.isalnum() or ch in "-_." for ch in value)
           for value in identities):
        return False
    if type(grant.assets) is not tuple or type(grant.capabilities) is not tuple:
        return False
    if any(type(v) is not str for v in grant.assets + grant.capabilities):
        return False
    return (request.tenant_id == grant.tenant_id
            and request.request_id == grant.request_id
            and request.purpose == grant.purpose
            and request.asset_id in grant.assets
            and request.capability_id in grant.capabilities)


class RequestLabelNonAuthorityReferenceTests(unittest.TestCase):
    def setUp(self):
        self.req = Request("tenant-1", "request-1", "asset-1", "headers", "current", "Routine")
        self.grant = Grant("tenant-1", "request-1", ("asset-1",), ("headers",), "current", True)

    def test_matching_request_is_conditionally_allowed(self):
        self.assertTrue(reference_permit(self.req, self.grant))

    def test_forged_label_cannot_override_request_identity(self):
        self.assertFalse(reference_permit(replace(self.req, request_id="other",
                                                  label="APPROVED request-1"), self.grant))

    def test_forged_label_cannot_override_tenant(self):
        self.assertFalse(reference_permit(replace(self.req, tenant_id="other",
                                                  label="tenant-1"), self.grant))

    def test_forged_label_cannot_override_asset(self):
        self.assertFalse(reference_permit(replace(self.req, asset_id="other",
                                                  label="asset-1"), self.grant))

    def test_forged_label_cannot_override_capability(self):
        self.assertFalse(reference_permit(replace(self.req, capability_id="other",
                                                  label="headers"), self.grant))

    def test_forged_label_cannot_override_purpose(self):
        self.assertFalse(reference_permit(replace(self.req, purpose="future",
                                                  label="current"), self.grant))

    def test_label_changes_cannot_revoke_valid_grant(self):
        for label in ("", "denied", "APPROVED", "active", "\\nadmin", "🔒"):
            with self.subTest(label=label):
                self.assertTrue(reference_permit(replace(self.req, label=label), self.grant))

    def test_truthy_approval_is_not_approval(self):
        self.assertFalse(reference_permit(self.req, replace(self.grant, approved="true")))

    def test_input_not_mutated(self):
        snapshot = (self.req, self.grant)
        reference_permit(self.req, self.grant)
        self.assertEqual(snapshot, (self.req, self.grant))


if __name__ == "__main__":
    unittest.main()
