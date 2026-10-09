"""Offline reference for environment-bound scope decisions; never a production grant."""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class EnvironmentGrant:
    tenant: str
    request: str
    environment: str
    issuer: str
    revision: int
    active: bool


def eligible_for_environment(grant: object, *, tenant: object, request: object,
                             environment: object, issuer: object, revision: object) -> bool:
    """Fail closed on environment substitution, including string lookalikes."""
    if type(grant) is not EnvironmentGrant:
        return False
    if type(grant.active) is not bool or grant.active is not True:
        return False
    if type(grant.revision) is not int or grant.revision < 1:
        return False
    if type(revision) is not int or revision < 1 or revision != grant.revision:
        return False
    fields = (grant.tenant, grant.request, grant.environment, grant.issuer,
              tenant, request, environment, issuer)
    if any(type(value) is not str or not value or len(value) > 128 or
           value != value.strip() or any(ord(ch) < 33 or ord(ch) == 127 for ch in value)
           for value in fields):
        return False
    if grant.environment not in ("test", "staging", "production"):
        return False
    return (grant.tenant == tenant and grant.request == request and
            grant.environment == environment and grant.issuer == issuer)


class EnvironmentBindingReferenceTests(unittest.TestCase):
    def setUp(self):
        self.grant = EnvironmentGrant("tenant-a", "request-1", "staging", "issuer-a", 4, True)
        self.kwargs = dict(tenant="tenant-a", request="request-1",
                           environment="staging", issuer="issuer-a", revision=4)

    def test_matching_context_is_only_conditionally_eligible(self):
        self.assertTrue(eligible_for_environment(self.grant, **self.kwargs))

    def test_staging_grant_cannot_authorize_production(self):
        self.assertFalse(eligible_for_environment(self.grant, **{**self.kwargs, "environment": "production"}))

    def test_production_grant_cannot_authorize_staging(self):
        prod = EnvironmentGrant("tenant-a", "request-1", "production", "issuer-a", 4, True)
        self.assertFalse(eligible_for_environment(prod, **self.kwargs))

    def test_tenant_request_issuer_and_revision_swaps_denied(self):
        for key, value in (("tenant", "tenant-b"), ("request", "request-2"),
                           ("issuer", "issuer-b"), ("revision", 5)):
            with self.subTest(key=key):
                self.assertFalse(eligible_for_environment(self.grant, **{**self.kwargs, key: value}))

    def test_untrusted_aliases_denied(self):
        for env in ("prod", "PRODUCTION", " staging", "staging ", "staging\n", "staging\x00", ""):
            with self.subTest(env=env):
                self.assertFalse(eligible_for_environment(self.grant, **{**self.kwargs, "environment": env}))

    def test_malformed_flags_and_revision_denied(self):
        for active in (1, "true", None, False):
            self.assertFalse(eligible_for_environment(
                EnvironmentGrant("tenant-a", "request-1", "staging", "issuer-a", 4, active), **self.kwargs))
        for revision in (True, "4", 0, -1, 4.0):
            self.assertFalse(eligible_for_environment(self.grant, **{**self.kwargs, "revision": revision}))

    def test_polymorphic_and_malformed_grants_denied(self):
        class Derived(EnvironmentGrant):
            pass
        self.assertFalse(eligible_for_environment(Derived(**vars(self.grant)), **self.kwargs))
        self.assertFalse(eligible_for_environment({"environment": "staging"}, **self.kwargs))
        self.assertFalse(eligible_for_environment(None, **self.kwargs))

    def test_reference_does_not_mutate_input(self):
        before = vars(self.grant).copy()
        self.assertFalse(eligible_for_environment(self.grant, **{**self.kwargs, "environment": "production"}))
        self.assertEqual(vars(self.grant), before)


    def test_grant_environment_identity_is_strict(self):
        for environment in ("prod", "STAGING", "staging ", "staging\\n", "", None, 1, True):
            with self.subTest(environment=environment):
                candidate = EnvironmentGrant("tenant-a", "request-1", environment, "issuer-a", 4, True)
                self.assertFalse(eligible_for_environment(candidate, **self.kwargs))

    def test_other_canonical_environment_requires_matching_grant(self):
        for environment in ("test", "staging", "production"):
            candidate = EnvironmentGrant("tenant-a", "request-1", environment, "issuer-a", 4, True)
            actual = eligible_for_environment(candidate, **{**self.kwargs, "environment": environment})
            self.assertTrue(actual)

    def test_identity_fields_reject_control_alias_and_wrong_type(self):
        for field in ("tenant", "request", "issuer"):
            for variant in (None, True, 42, "tenant-a\\n" if field == "tenant" else "bad\\n",
                            " " + self.kwargs[field], self.kwargs[field] + " ",
                            self.kwargs[field] + "\\x00", "x" * 129):
                with self.subTest(field=field, variant=variant):
                    self.assertFalse(eligible_for_environment(
                        self.grant, **{**self.kwargs, field: variant}))

    def test_grant_metadata_rejects_invalid_identity_and_revision(self):
        for key, values in {
            "tenant": (None, "tenant-a ", True),
            "request": (None, "request-1\\n", 7),
            "issuer": (None, " issuer-a", False),
            "revision": (True, 0, "4", -1, 4.0),
        }.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    candidate = EnvironmentGrant(**{**vars(self.grant), key: value})
                    self.assertFalse(eligible_for_environment(candidate, **self.kwargs))

if __name__ == "__main__":
    unittest.main()
