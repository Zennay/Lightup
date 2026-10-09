"""Offline contract: WebSocket subprotocol negotiation conveys no authorization.

Reference-only: does not represent production ToolExecutor enforcement.
Run: python -m unittest discover -s tests -p 'test_scope_ws_subprotocol_nonauthority_reference.py'
"""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class Grant:
    tenant: str
    asset: str
    capability: str
    revision: int
    approved: bool
    revoked: bool


def reference_decide(grant, requested, headers):
    """Fail closed using trusted grant fields only; ignore caller presentation headers."""
    del headers
    if type(grant) is not Grant or type(requested) is not Grant:
        return False
    for item in (grant, requested):
        if any(type(getattr(item, field)) is not str or not getattr(item, field)
               for field in ("tenant", "asset", "capability")):
            return False
        if type(item.revision) is not int or item.revision < 1:
            return False
        if type(item.approved) is not bool or type(item.revoked) is not bool:
            return False
    return (grant == requested and grant.approved is True and grant.revoked is False)


class WebSocketSubprotocolNonauthorityReference(unittest.TestCase):
    def setUp(self):
        self.valid = Grant("tenant-a", "lab-asset", "read-only", 3, True, False)

    def test_header_cannot_approve_unapproved_grant(self):
        unapproved = Grant("tenant-a", "lab-asset", "read-only", 3, False, False)
        for value in ("approved", "admin", "scope:all", "Bearer token", "", None,
                      ["approved"], {"approval": True}):
            with self.subTest(value=value):
                self.assertFalse(reference_decide(unapproved, unapproved,
                    {"Sec-WebSocket-Protocol": value}))

    def test_header_cannot_bypass_revocation(self):
        revoked = Grant("tenant-a", "lab-asset", "read-only", 3, True, True)
        for value in ("authorized", "revocation=false", "3", "read-only"):
            with self.subTest(value=value):
                self.assertFalse(reference_decide(revoked, revoked,
                    {"sec-websocket-protocol": value}))

    def test_header_cannot_widen_identity_or_capability(self):
        variants = [
            Grant("tenant-b", "lab-asset", "read-only", 3, True, False),
            Grant("tenant-a", "other-asset", "read-only", 3, True, False),
            Grant("tenant-a", "lab-asset", "active-scan", 3, True, False),
            Grant("tenant-a", "lab-asset", "read-only", 4, True, False),
        ]
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertFalse(reference_decide(self.valid, variant,
                    {"Sec-WebSocket-Protocol": "tenant-a, lab-asset, active-scan, approved"}))

    def test_valid_grant_not_blocked_by_presentation_header(self):
        for headers in ({}, {"Sec-WebSocket-Protocol": "json"},
                        {"sec-websocket-protocol": "some-other-format"}):
            with self.subTest(headers=headers):
                self.assertTrue(reference_decide(self.valid, self.valid, headers))

    def test_denial_never_calls_handler(self):
        revoked = Grant("tenant-a", "lab-asset", "read-only", 3, True, True)
        calls = []
        def mock_handler():
            calls.append(True)
        for header in ("admin", "approved", "read-only", ""):
            if reference_decide(revoked, revoked, {"Sec-WebSocket-Protocol": header}):
                mock_handler()
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
