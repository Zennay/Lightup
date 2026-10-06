import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy


class ActivationTests(unittest.TestCase):
    def test_plan_only_never_issues_execution_permit(self):
        gate = ActivationGate(ScopePolicy(), ActivationPolicy())
        with self.assertRaises(PermissionError):
            gate.issue(Target("127.0.0.1"), "web-baseline")

    def test_lab_only_can_issue_private_permit(self):
        gate = ActivationGate(
            ScopePolicy(allow_private_lab=True),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY, activation_reference="LAB-TEST"),
        )
        permit = gate.issue(Target("10.10.0.5"), "web-baseline")
        self.assertEqual(permit.mode, ActivationMode.LAB_ONLY)
        self.assertIsNone(permit.authorization_reference)

    def test_authorized_public_permit_requires_bound_asset(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset(
                {"authorized.example.test", "other.example.test"}
            )
        )
        gate = ActivationGate(
            policy,
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference="ACTIVE-TEST",
            ),
        )
        auth = Authorization(
            owner="owner",
            reference="AUTH-1",
            assets=("authorized.example.test",),
            capabilities=("web-baseline",),
        )
        permit = gate.issue(
            Target("authorized.example.test", authorization=auth),
            "web-baseline",
        )
        self.assertEqual(permit.mode, ActivationMode.AUTHORIZED)
        self.assertEqual(permit.activation_reference, "ACTIVE-TEST")
        self.assertEqual(permit.authorization_reference, "AUTH-1")
        with self.assertRaises(PermissionError):
            gate.issue(
                Target("other.example.test", authorization=auth),
                "web-baseline",
            )

    def test_authorized_loopback_requires_exact_asset_binding(self):
        gate = ActivationGate(
            ScopePolicy(),
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference="ACTIVE-TEST",
            ),
        )
        wrong_asset = Authorization(
            owner="owner",
            reference="AUTH-WRONG",
            assets=("authorized.example.test",),
            capabilities=("web-baseline",),
        )
        with self.assertRaises(PermissionError) as caught:
            gate.issue(
                Target("127.0.0.1", authorization=wrong_asset),
                "web-baseline",
            )
        self.assertIn("exact target asset", str(caught.exception))

        bound = Authorization(
            owner="owner",
            reference="AUTH-LOOPBACK",
            assets=("127.0.0.1",),
            capabilities=("web-baseline",),
        )
        permit = gate.issue(
            Target("http://127.0.0.1:8080/path", authorization=bound),
            "web-baseline",
        )
        self.assertEqual(permit.target, "127.0.0.1")
        self.assertEqual(permit.authorization_reference, "AUTH-LOOPBACK")

    def test_authorized_private_lab_requires_exact_asset_binding(self):
        gate = ActivationGate(
            ScopePolicy(allow_private_lab=True),
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference="ACTIVE-TEST",
            ),
        )
        wrong_asset = Authorization(
            owner="owner",
            reference="AUTH-WRONG",
            assets=("10.10.0.6",),
            capabilities=("web-baseline",),
        )
        with self.assertRaises(PermissionError) as caught:
            gate.issue(
                Target("10.10.0.5", authorization=wrong_asset),
                "web-baseline",
            )
        self.assertIn("exact target asset", str(caught.exception))

        bound = Authorization(
            owner="owner",
            reference="AUTH-PRIVATE",
            assets=("10.10.0.5",),
            capabilities=("web-baseline",),
        )
        permit = gate.issue(
            Target("https://10.10.0.5:8443/", authorization=bound),
            "web-baseline",
        )
        self.assertEqual(permit.target, "10.10.0.5")
        self.assertEqual(permit.authorization_reference, "AUTH-PRIVATE")

    def test_authorized_permit_requires_explicit_capability_binding(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"authorized.example.test"}))
        gate = ActivationGate(
            policy,
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference="ACTIVE-TEST",
            ),
        )
        unscoped = Authorization(
            owner="owner",
            reference="AUTH-EMPTY",
            assets=("authorized.example.test",),
        )
        with self.assertRaises(PermissionError) as caught:
            gate.issue(
                Target("authorized.example.test", authorization=unscoped),
                "web-baseline",
            )
        self.assertIn("explicitly authorized capability", str(caught.exception))

        wrong_capability = Authorization(
            owner="owner",
            reference="AUTH-WRONG-CAP",
            assets=("authorized.example.test",),
            capabilities=("network-services",),
        )
        with self.assertRaises(PermissionError) as caught:
            gate.issue(
                Target("authorized.example.test", authorization=wrong_capability),
                "web-baseline",
            )
        self.assertIn("explicitly authorized capability", str(caught.exception))

        bound = Authorization(
            owner="owner",
            reference="AUTH-CAP",
            assets=("authorized.example.test",),
            capabilities=("web-baseline",),
        )
        permit = gate.issue(
            Target("authorized.example.test", authorization=bound),
            "web-baseline",
        )
        self.assertEqual(permit.capability_id, "web-baseline")
        self.assertEqual(permit.authorization_reference, "AUTH-CAP")

    def test_revoked_public_authorization_never_issues_permit(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"authorized.example.test"}))
        gate = ActivationGate(
            policy,
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference="ACTIVE-TEST",
            ),
        )
        target = Target(
            "authorized.example.test",
            authorization=Authorization(
                owner="owner",
                reference="AUTH-1",
                assets=("authorized.example.test",),
                revoked_at=datetime.now(timezone.utc),
                revoked_by="op-1",
                revocation_reason="scope withdrawn",
            ),
        )
        with self.assertRaises(PermissionError):
            gate.issue(target, "web-baseline")

    def test_lab_only_default_scope_rejects_private_target(self):
        gate = ActivationGate(
            ScopePolicy(),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY, activation_reference="LAB-TEST"),
        )
        with self.assertRaises(PermissionError):
            gate.issue(Target("10.10.0.5"), "web-baseline")

    def test_lab_only_rejects_explicit_public_target(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"authorized.example.test"}))
        gate = ActivationGate(
            policy,
            ActivationPolicy(mode=ActivationMode.LAB_ONLY, activation_reference="LAB-TEST"),
        )
        target = Target(
            "authorized.example.test",
            authorization=Authorization(
                owner="owner",
                reference="AUTH-1",
                assets=("authorized.example.test",),
            ),
        )
        with self.assertRaises(PermissionError):
            gate.issue(target, "web-baseline")


if __name__ == "__main__":
    unittest.main()
