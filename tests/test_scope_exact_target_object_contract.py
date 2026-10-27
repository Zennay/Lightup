import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class _DuckTarget:
    value = "127.0.0.1"
    authorization = None


class _IdentitySpoofingTarget(Target):
    def __getattribute__(self, name):
        if name == "value":
            return "127.0.0.1"
        return super().__getattribute__(name)


def _canonical_spoofed_authorization() -> Authorization:
    kwargs = {
        "owner": "spoofed-owner",
        "reference": "SPOOFED-AUTH",
    }
    if "assets" in Authorization.__dataclass_fields__:
        kwargs["assets"] = ("security.example.test",)
    return Authorization(**kwargs)


class _AuthorizationSpoofingTarget(Target):
    def __getattribute__(self, name):
        if name == "authorization":
            return _canonical_spoofed_authorization()
        return super().__getattribute__(name)


class ScopeExactTargetObjectContractTests(unittest.TestCase):
    def test_non_target_objects_fail_closed_as_invalid_target(self):
        policy = ScopePolicy()
        malformed_targets = (
            None,
            "127.0.0.1",
            {"value": "127.0.0.1"},
            _DuckTarget(),
        )

        for target in malformed_targets:
            with self.subTest(target_type=type(target).__name__):
                decision = policy.decide(target)  # type: ignore[arg-type]

                self.assertFalse(decision.allowed)
                self.assertIsNone(decision.normalized_host)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_target_subclass_cannot_override_scope_identity(self):
        policy = ScopePolicy()
        target = _IdentitySpoofingTarget("8.8.8.8")

        self.assertEqual(object.__getattribute__(target, "__dict__")["value"], "8.8.8.8")

        decision = policy.decide(target)

        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.normalized_host)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_target_subclass_cannot_inject_authorization(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"security.example.test"}))
        target = _AuthorizationSpoofingTarget("security.example.test", authorization=None)

        self.assertIsNone(object.__getattribute__(target, "__dict__")["authorization"])

        decision = policy.decide(target)

        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.normalized_host)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_exact_target_behavior_is_unchanged(self):
        loopback = ScopePolicy().decide(Target("127.0.0.1"))
        private_lab = ScopePolicy(allow_private_lab=True).decide(Target("10.20.30.40"))
        public = ScopePolicy().decide(Target("8.8.8.8"))

        self.assertTrue(loopback.allowed)
        self.assertEqual(loopback.reason, ScopeReason.LOOPBACK)
        self.assertTrue(private_lab.allowed)
        self.assertEqual(private_lab.reason, ScopeReason.PRIVATE_LAB)
        self.assertFalse(public.allowed)
        self.assertEqual(public.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
