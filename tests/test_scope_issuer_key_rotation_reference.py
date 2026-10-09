"""Offline issuer signing-key rotation reference: not a production authorization gate.

No crypto, network, external targets or capability dispatch. A positive result only
means internally consistent *synthetic* issuer metadata, not authenticated provenance.
"""
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Key:
    issuer: str
    tenant: str
    key_id: str
    algorithm: str
    generation: int
    active: bool


@dataclass(frozen=True)
class Claim:
    issuer: str
    tenant: str
    key_id: str
    algorithm: str
    generation: int
    authorization_revision: int


def eligible(key, claim, *, required_revision, minimum_generation):
    """Necessary consistency conditions only; NEVER sufficient for dispatch."""
    if type(key) is not Key or type(claim) is not Claim:
        return False
    strings = (key.issuer, key.tenant, key.key_id, key.algorithm,
               claim.issuer, claim.tenant, claim.key_id, claim.algorithm)
    if not all(type(s) is str and s and s.isascii() and s.isprintable()
               and s == s.strip() for s in strings):
        return False
    if type(key.active) is not bool or key.active is not True:
        return False
    ints = (key.generation, claim.generation, claim.authorization_revision,
            required_revision, minimum_generation)
    if not all(type(n) is int and 0 < n < 2**63 for n in ints):
        return False
    if key.algorithm != "Ed25519" or claim.algorithm != "Ed25519":
        return False
    return (key.issuer == claim.issuer and key.tenant == claim.tenant
            and key.key_id == claim.key_id
            and key.generation == claim.generation
            and key.generation >= minimum_generation
            and claim.authorization_revision == required_revision)


class IssuerKeyRotationReferenceTests(unittest.TestCase):
    def setUp(self):
        self.key = Key("issuer-A", "tenant-A", "key-2", "Ed25519", 2, True)
        self.claim = Claim("issuer-A", "tenant-A", "key-2", "Ed25519", 2, 5)

    def check(self, key=None, claim=None, **overrides):
        defaults = {"required_revision": 5, "minimum_generation": 2}
        defaults.update(overrides)
        return eligible(self.key if key is None else key,
                        self.claim if claim is None else claim, **defaults)

    def test_matching_synthetic_claim_is_conditional_only(self):
        self.assertTrue(self.check())

    def test_retired_key_denied(self):
        self.assertFalse(self.check(key=replace(self.key, active=False)))

    def test_older_key_epoch_denied(self):
        self.assertFalse(self.check(key=replace(self.key, generation=1),
                                    claim=replace(self.claim, generation=1)))

    def test_future_claim_generation_denied(self):
        self.assertFalse(self.check(claim=replace(self.claim, generation=3)))

    def test_claim_key_substitution_denied(self):
        self.assertFalse(self.check(claim=replace(self.claim, key_id="key-1")))

    def test_cross_tenant_claim_denied(self):
        self.assertFalse(self.check(claim=replace(self.claim, tenant="tenant-B")))

    def test_cross_issuer_claim_denied(self):
        self.assertFalse(self.check(claim=replace(self.claim, issuer="issuer-B")))

    def test_algorithm_confusion_denied(self):
        for alg in ("none", "HS256", "ed25519", "RSA", ""):
            with self.subTest(alg=alg):
                self.assertFalse(self.check(claim=replace(self.claim, algorithm=alg)))
                self.assertFalse(self.check(key=replace(self.key, algorithm=alg)))

    def test_revision_swap_denied(self):
        self.assertFalse(self.check(claim=replace(self.claim, authorization_revision=4)))

    def test_invalid_types_denied(self):
        for value in (True, "2", 0, -1, 2**63, 2.0):
            with self.subTest(value=value):
                self.assertFalse(self.check(key=replace(self.key, generation=value)))
                self.assertFalse(self.check(claim=replace(self.claim, generation=value)))

    def test_truthy_active_flag_denied(self):
        for value in (1, "yes", None):
            with self.subTest(value=value):
                self.assertFalse(self.check(key=replace(self.key, active=value)))

    def test_polymorphic_claim_denied(self):
        class ForgedClaim(Claim):
            pass
        self.assertFalse(self.check(claim=ForgedClaim(**vars(self.claim))))

    def test_polymorphic_key_denied(self):
        class ForgedKey(Key):
            pass
        self.assertFalse(self.check(key=ForgedKey(**vars(self.key))))

    def test_malformed_identity_denied(self):
        for value in (" tenant-A", "tenant-A\n", "tenant-\x00A", "ténant-A", ""):
            with self.subTest(value=repr(value)):
                self.assertFalse(self.check(claim=replace(self.claim, tenant=value)))

    def test_revision_or_floor_invalid_denied(self):
        self.assertFalse(self.check(required_revision=True))
        self.assertFalse(self.check(minimum_generation="2"))
        self.assertFalse(self.check(minimum_generation=2**63))

    def test_reference_is_input_pure(self):
        key, claim = self.key, self.claim
        self.check()
        self.assertEqual(key, self.key)
        self.assertEqual(claim, self.claim)


if __name__ == "__main__":
    unittest.main()
