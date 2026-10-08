"""Offline reference-model checks for queue/retry revocation races.

This model is deliberately NOT wired into LightUp's production executor.
"""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class Grant:
    tenant: str
    grant_id: str
    revision: int
    active: bool


class OfflineQueueGate:
    """Reference model: dispatch never inherits enqueue-time permission."""

    def __init__(self):
        self.live = {}
        self.handler_calls = []

    def publish(self, grant):
        self.live[(grant.tenant, grant.grant_id)] = grant

    def dispatch(self, snapshot, requested_tenant, action):
        live = self.live.get((snapshot.tenant, snapshot.grant_id))
        # Tenant, exact grant version and active status are required at use time.
        if (type(requested_tenant) is not str
                or requested_tenant != snapshot.tenant
                or live is None
                or not live.active
                or live != snapshot):
            return "denied"
        self.handler_calls.append((requested_tenant, action))
        return "executed"


class QueueRevocationReferenceTest(unittest.TestCase):
    def setUp(self):
        self.gate = OfflineQueueGate()
        self.grant = Grant("tenant-a", "same-id", 1, True)
        self.gate.publish(self.grant)

    def test_enqueue_then_revoke_before_dispatch_never_calls_handler(self):
        self.gate.publish(Grant("tenant-a", "same-id", 2, False))
        self.assertEqual(self.gate.dispatch(self.grant, "tenant-a", "inert"), "denied")
        self.assertEqual(self.gate.handler_calls, [])

    def test_retry_after_revocation_cannot_reuse_cached_allow(self):
        self.assertEqual(self.gate.dispatch(self.grant, "tenant-a", "first"), "executed")
        self.gate.publish(Grant("tenant-a", "same-id", 2, False))
        for _ in range(3):
            self.assertEqual(self.gate.dispatch(self.grant, "tenant-a", "retry"), "denied")
        self.assertEqual(self.gate.handler_calls, [("tenant-a", "first")])

    def test_reapproval_same_identifier_does_not_revive_old_snapshot(self):
        self.gate.publish(Grant("tenant-a", "same-id", 3, True))
        self.assertEqual(self.gate.dispatch(self.grant, "tenant-a", "stale"), "denied")
        self.assertEqual(self.gate.handler_calls, [])

    def test_cross_tenant_identifier_reuse_never_authorizes(self):
        self.gate.publish(Grant("tenant-b", "same-id", 1, True))
        self.assertEqual(self.gate.dispatch(self.grant, "tenant-b", "wrong-tenant"), "denied")
        self.assertEqual(self.gate.handler_calls, [])

    def test_missing_live_grant_denies(self):
        self.gate.live.clear()
        self.assertEqual(self.gate.dispatch(self.grant, "tenant-a", "missing"), "denied")
        self.assertEqual(self.gate.handler_calls, [])

    def test_valid_unchanged_grant_allows_only_inert_model_step(self):
        self.assertEqual(self.gate.dispatch(self.grant, "tenant-a", "inert"), "executed")
        self.assertEqual(self.gate.handler_calls, [("tenant-a", "inert")])


if __name__ == "__main__":
    unittest.main()
