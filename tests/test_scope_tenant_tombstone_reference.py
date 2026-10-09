"""Offline tenant-deletion tombstone reference; never grants production authority."""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class TenantGrant:
    tenant_id: str
    grant_id: str
    generation: int
    active: bool


@dataclass(frozen=True)
class TenantState:
    tenant_id: str
    generation: int
    deleted: bool


def eligible(grant: TenantGrant, state: TenantState) -> bool:
    """Necessary identity/lifecycle condition, NOT sufficient authorization."""
    if type(grant) is not TenantGrant or type(state) is not TenantState:
        return False
    if any(type(value) is not str or not value or len(value) > 128
           or not value.isascii() or not all(c.isalnum() or c in "_-" for c in value)
           for value in (grant.tenant_id, grant.grant_id, state.tenant_id)):
        return False
    if type(grant.generation) is not int or type(state.generation) is not int:
        return False
    if not (1 <= grant.generation <= 2**63 - 1\n            and 1 <= state.generation <= 2**63 - 1):
        return False
    return (type(grant.active) is bool and grant.active is True
            and type(state.deleted) is bool and state.deleted is False
            and grant.tenant_id == state.tenant_id
            and grant.generation == state.generation)


class TenantTombstoneTests(unittest.TestCase):
    def setUp(self):
        self.grant = TenantGrant("tenant_a", "grant_1", 7, True)
        self.state = TenantState("tenant_a", 7, False)

    def test_live_matching_generation_is_only_conditionally_eligible(self):
        self.assertTrue(eligible(self.grant, self.state))

    def test_deleted_tenant_denied_even_if_grant_still_active(self):
        self.assertFalse(eligible(self.grant, TenantState("tenant_a", 7, True)))

    def test_recreated_tenant_cannot_reuse_old_grant(self):
        self.assertFalse(eligible(self.grant, TenantState("tenant_a", 8, False)))

    def test_older_tenant_snapshot_denied(self):
        self.assertFalse(eligible(self.grant, TenantState("tenant_a", 6, False)))

    def test_cross_tenant_state_denied(self):
        self.assertFalse(eligible(self.grant, TenantState("tenant_b", 7, False)))

    def test_inactive_grant_denied(self):
        self.assertFalse(eligible(TenantGrant("tenant_a", "grant_1", 7, False), self.state))

    def test_truthy_non_boolean_grant_denied(self):
        self.assertFalse(eligible(TenantGrant("tenant_a", "grant_1", 7, 1), self.state))

    def test_truthy_non_boolean_deletion_flag_denied(self):
        self.assertFalse(eligible(self.grant, TenantState("tenant_a", 7, 0)))

    def test_boolean_generation_denied(self):
        self.assertFalse(eligible(TenantGrant("tenant_a", "grant_1", True, True), self.state))

    def test_invalid_identity_denied(self):
        for identity in ("", " tenant_a", "tenant/a", "tenant\nA", "ténant"):
            with self.subTest(identity=identity):
                self.assertFalse(eligible(TenantGrant(identity, "grant_1", 7, True), self.state))

    def test_wrong_envelope_and_subclass_denied(self):
        @dataclass(frozen=True)
        class DerivedGrant(TenantGrant):
            pass
        self.assertFalse(eligible(DerivedGrant("tenant_a", "grant_1", 7, True), self.state))
        self.assertFalse(eligible({"tenant_id": "tenant_a"}, self.state))


    def test_state_boolean_generation_denied(self):
        self.assertFalse(eligible(self.grant, TenantState("tenant_a", True, False)))

    def test_zero_and_negative_generations_denied(self):
        for generation in (0, -1):
            with self.subTest(generation=generation):
                self.assertFalse(eligible(TenantGrant("tenant_a", "grant_1", generation, True), self.state))
                self.assertFalse(eligible(self.grant, TenantState("tenant_a", generation, False)))

    def test_malformed_state_and_grant_identifiers_denied(self):
        for value in ("tenant/a", "grant\\n1", "a" * 129, "x.y", "id\\x00suffix"):
            with self.subTest(value=value):
                self.assertFalse(eligible(TenantGrant("tenant_a", value, 7, True), self.state))
                self.assertFalse(eligible(self.grant, TenantState(value, 7, False)))

    def test_tenant_state_subclass_and_non_boolean_deletion_denied(self):
        @dataclass(frozen=True)
        class DerivedState(TenantState):
            pass
        self.assertFalse(eligible(self.grant, DerivedState("tenant_a", 7, False)))
        self.assertFalse(eligible(self.grant, TenantState("tenant_a", 7, "false")))

    def test_generation_overflow_denied(self):
        for huge in (2**63, 10**100):
            with self.subTest(huge=huge):
                self.assertFalse(eligible(TenantGrant("tenant_a", "grant_1", huge, True), self.state))
                self.assertFalse(eligible(self.grant, TenantState("tenant_a", huge, False)))

    def test_max_generation_boundary_is_conditionally_eligible(self):
        maximum = 2**63 - 1
        self.assertTrue(eligible(
            TenantGrant("tenant_a", "grant_1", maximum, True),
            TenantState("tenant_a", maximum, False)))

    def test_non_integer_generation_types_denied(self):
        for bad in (7.0, "7", None):
            with self.subTest(value=bad):
                self.assertFalse(eligible(TenantGrant("tenant_a", "grant_1", bad, True), self.state))
                self.assertFalse(eligible(self.grant, TenantState("tenant_a", bad, False)))

    def test_non_string_grant_and_tenant_ids_denied(self):
        for bad in (None, 1, b"tenant_a"):
            with self.subTest(value=bad):
                self.assertFalse(eligible(TenantGrant("tenant_a", bad, 7, True), self.state))
                self.assertFalse(eligible(self.grant, TenantState(bad, 7, False)))

    def test_inputs_unchanged(self):
        before = (repr(self.grant), repr(self.state))
        eligible(self.grant, self.state)
        self.assertEqual(before, (repr(self.grant), repr(self.state)))


if __name__ == "__main__":
    unittest.main()
