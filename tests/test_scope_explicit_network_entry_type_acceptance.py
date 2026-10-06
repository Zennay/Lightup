from __future__ import annotations

import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy


class ScopeExplicitNetworkEntryTypeAcceptanceTest(unittest.TestCase):
    def _assert_non_string_entry_rejected(self, entry: object, target_value: str) -> None:
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=(entry,),  # type: ignore[arg-type]
            require_authorization_for_public=True,
        )
        target = Target(
            target_value,
            authorization=Authorization(
                owner="scope-type-regression",
                reference="scope-type-regression-ref",
            ),
        )

        with self.assertRaises((TypeError, ValueError)):
            policy.decide(target)

    def test_integer_network_entry_cannot_mint_public_scope(self):
        self._assert_non_string_entry_rejected(134744072, "8.8.8.8")

    def test_raw_bytes_network_entry_cannot_mint_public_scope(self):
        self._assert_non_string_entry_rejected(b"\x08\x08\x08\x08", "8.8.8.8")

    def test_boolean_network_entries_cannot_mint_scope(self):
        for entry, target in ((True, "0.0.0.1"), (False, "0.0.0.0")):
            with self.subTest(entry=entry):
                self._assert_non_string_entry_rejected(entry, target)

    def test_bytearray_network_entry_is_rejected_before_ip_network_coercion(self):
        self._assert_non_string_entry_rejected(
            bytearray(b"\x08\x08\x08\x08"),
            "8.8.8.8",
        )

    def test_canonical_string_network_keeps_existing_behavior(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.8/32",),
            require_authorization_for_public=True,
        )
        decision = policy.decide(
            Target(
                "8.8.8.8",
                authorization=Authorization(
                    owner="scope-type-regression",
                    reference="scope-type-regression-ref",
                ),
            )
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_host, "8.8.8.8")
        self.assertEqual(decision.reason.value, "explicit_network")


if __name__ == "__main__":
    unittest.main()
