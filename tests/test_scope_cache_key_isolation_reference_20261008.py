"""Offline cache-key isolation contract; never grants real authorization.

The fixtures model cached verdict lookup only. A cache hit is not consent,
does not bypass revocation, and cannot replace execution-time verification.
"""
import unittest


FIELDS = ("tenant_id", "engagement_id", "grant_id", "asset_id",
          "capability", "risk_level", "policy_version", "revocation_epoch")


def strict_cache_key(context):
    """Return immutable, fully-bound key or refuse caching."""
    if type(context) is not dict or set(context) != set(FIELDS):
        return None
    values = []
    for field in FIELDS:
        value = context[field]
        if type(value) is not str or not value or value.strip() != value:
            return None
        values.append(value)
    return tuple(values)


class CacheIsolationContract(unittest.TestCase):
    def setUp(self):
        self.base = dict(tenant_id="tenant-A", engagement_id="engagement-1",
                         grant_id="grant-1", asset_id="asset.example",
                         capability="passive-read", risk_level="low",
                         policy_version="policy-1", revocation_epoch="rev-0")

    def test_every_bound_dimension_changes_key(self):
        original = strict_cache_key(self.base)
        self.assertIsNotNone(original)
        for field in FIELDS:
            with self.subTest(field=field):
                changed = dict(self.base, **{field: self.base[field] + "-other"})
                self.assertNotEqual(original, strict_cache_key(changed))

    def test_cache_hits_only_on_exact_binding(self):
        verdict_cache = {strict_cache_key(self.base): "historical-eligible"}
        self.assertEqual(verdict_cache.get(strict_cache_key(dict(self.base))),
                         "historical-eligible")
        for field in FIELDS:
            with self.subTest(field=field):
                mismatched = dict(self.base)
                mismatched[field] += "-different"
                self.assertIsNone(verdict_cache.get(strict_cache_key(mismatched)))

    def test_missing_extra_and_badly_typed_fields_disable_cache(self):
        variants = [None, [], {}, dict(self.base, unexpected="value")]
        for field in FIELDS:
            missing = dict(self.base)
            missing.pop(field)
            variants.append(missing)
            for value in ("", " space", "space ", None, True, 1, ["x"]):
                malformed = dict(self.base)
                malformed[field] = value
                variants.append(malformed)
        for value in variants:
            with self.subTest(value=repr(value)[:100]):
                self.assertIsNone(strict_cache_key(value))

    def test_shared_asset_across_tenants_must_not_share_verdict(self):
        second = dict(self.base, tenant_id="tenant-B")
        self.assertEqual(self.base["asset_id"], second["asset_id"])
        self.assertNotEqual(strict_cache_key(self.base), strict_cache_key(second))

    def test_revocation_epoch_invalidates_previous_key(self):
        next_epoch = dict(self.base, revocation_epoch="rev-1")
        cache = {strict_cache_key(self.base): "historical-eligible"}
        self.assertIsNone(cache.get(strict_cache_key(next_epoch)))

    def test_unsafe_asset_only_key_has_cross_tenant_collision(self):
        second = dict(self.base, tenant_id="tenant-B")
        # Counterexample: using only asset identity is unacceptable.
        self.assertEqual(self.base["asset_id"], second["asset_id"])
        self.assertNotEqual(strict_cache_key(self.base), strict_cache_key(second))


if __name__ == "__main__":
    unittest.main()
