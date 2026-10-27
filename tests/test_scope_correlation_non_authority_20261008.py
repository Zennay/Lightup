"""Offline acceptance reference: correlation identifiers never grant authority."""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class SyntheticDecision:
    correlation_id: str
    authorized: bool
    tenant: str
    scope: str


def eligible(decision: SyntheticDecision, *, trusted_tenant: str, trusted_scope: str) -> bool:
    """Illustrative pure reference, NOT LightUp's runtime authorization gate."""
    return (
        type(decision) is SyntheticDecision
        and type(decision.authorized) is bool
        and decision.authorized is True
        and type(decision.tenant) is str
        and decision.tenant == trusted_tenant
        and type(decision.scope) is str
        and decision.scope == trusted_scope
    )


class CorrelationNonAuthority(unittest.TestCase):
    def setUp(self):
        self.allowed = SyntheticDecision("trace-1", True, "tenant-a", "asset-a")

    def test_trace_mutation_cannot_grant_authority(self):
        for token in ("", "trace-1", "trace-other", "tenant-a:asset-a", "admin"):
            with self.subTest(token=token):
                denied = SyntheticDecision(token, False, "tenant-a", "asset-a")
                self.assertFalse(eligible(denied, trusted_tenant="tenant-a", trusted_scope="asset-a"))

    def test_matching_trace_does_not_bypass_tenant(self):
        denied = SyntheticDecision("trace-1", True, "tenant-b", "asset-a")
        self.assertFalse(eligible(denied, trusted_tenant="tenant-a", trusted_scope="asset-a"))

    def test_matching_trace_does_not_bypass_scope(self):
        denied = SyntheticDecision("trace-1", True, "tenant-a", "asset-b")
        self.assertFalse(eligible(denied, trusted_tenant="tenant-a", trusted_scope="asset-a"))

    def test_trace_is_not_required_for_positive_reference(self):
        self.assertTrue(eligible(SyntheticDecision("", True, "tenant-a", "asset-a"), trusted_tenant="tenant-a", trusted_scope="asset-a"))

    def test_truthy_authorized_is_denied(self):
        self.assertFalse(eligible(SyntheticDecision("trace-1", 1, "tenant-a", "asset-a"), trusted_tenant="tenant-a", trusted_scope="asset-a"))

    def test_subclass_cannot_supply_authority(self):
        class Forged(SyntheticDecision):
            pass
        self.assertFalse(eligible(Forged("trace-1", True, "tenant-a", "asset-a"), trusted_tenant="tenant-a", trusted_scope="asset-a"))


if __name__ == "__main__":
    unittest.main()
