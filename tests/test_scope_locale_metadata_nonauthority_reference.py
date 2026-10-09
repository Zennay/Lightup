"""Offline reference: presentation locale/timezone hints never confer scope authority.

Synthetic predicate only; production gate remains separately owned.
"""
from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Grant:
    tenant: str
    request: str
    revision: int
    capability: str
    active: bool


@dataclass(frozen=True)
class Dispatch:
    tenant: str
    request: str
    revision: int
    capability: str
    presentation_locale: object = "en-US"
    display_timezone: object = "UTC"


def conditionally_eligible(grant: Grant, request: Dispatch) -> bool:
    """Necessary consistency only; NOT proof of authenticated permission."""
    if type(grant) is not Grant or type(request) is not Dispatch:
        return False
    for value in (grant.tenant, grant.request, grant.capability,
                  request.tenant, request.request, request.capability):
        if (type(value) is not str or not value or value != value.strip()
                or any(ord(char) < 33 or ord(char) > 126 for char in value)):
            return False
    if type(grant.revision) is not int or type(request.revision) is not int:
        return False
    if grant.revision < 1 or request.revision < 1 or grant.active is not True:
        return False
    return (
        grant.tenant == request.tenant
        and grant.request == request.request
        and grant.revision == request.revision
        and grant.capability == request.capability
    )


class LocaleMetadataNonAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.grant = Grant("tenant-a", "request-a", 3, "lab-plan", True)
        self.dispatch = Dispatch("tenant-a", "request-a", 3, "lab-plan")

    def test_matching_synthetic_fields_are_only_conditional(self):
        self.assertTrue(conditionally_eligible(self.grant, self.dispatch))

    def test_locale_and_timezone_never_change_matching_consistency(self):
        for locale in ("en-US", "tr-TR", "nl-NL", "ar-EG", "", None, 1, object()):
            for timezone in ("UTC", "Pacific/Kiritimati", "Etc/GMT+12", "", None, [], object()):
                with self.subTest(locale=locale, timezone=timezone):
                    request = replace(self.dispatch, presentation_locale=locale, display_timezone=timezone)
                    self.assertTrue(conditionally_eligible(self.grant, request))

    def test_metadata_cannot_revive_inactive_grant(self):
        self.assertFalse(conditionally_eligible(replace(self.grant, active=False),
                                               replace(self.dispatch, display_timezone="Pacific/Kiritimati")))

    def test_metadata_cannot_revive_revoked_like_grant(self):
        self.assertFalse(conditionally_eligible(replace(self.grant, active=None),
                                               replace(self.dispatch, presentation_locale="tr-TR")))

    def test_metadata_cannot_override_tenant(self):
        self.assertFalse(conditionally_eligible(self.grant, replace(self.dispatch, tenant="tenant-b",
                                                  presentation_locale="nl-NL")))

    def test_metadata_cannot_override_request(self):
        self.assertFalse(conditionally_eligible(self.grant, replace(self.dispatch, request="request-b",
                                                  display_timezone="UTC")))

    def test_metadata_cannot_override_revision(self):
        self.assertFalse(conditionally_eligible(self.grant, replace(self.dispatch, revision=4)))

    def test_metadata_cannot_override_capability(self):
        self.assertFalse(conditionally_eligible(self.grant, replace(self.dispatch, capability="active-scan")))

    def test_truthy_active_is_rejected(self):
        for value in (1, "true", [], object()):
            with self.subTest(value=value):
                self.assertFalse(conditionally_eligible(replace(self.grant, active=value), self.dispatch))

    def test_forged_subclass_request_rejected(self):
        class ForgedDispatch(Dispatch):
            pass
        self.assertFalse(conditionally_eligible(self.grant, ForgedDispatch("tenant-a", "request-a", 3, "lab-plan")))

    def test_forged_subclass_grant_rejected(self):
        class ForgedGrant(Grant):
            pass
        self.assertFalse(conditionally_eligible(ForgedGrant("tenant-a", "request-a", 3, "lab-plan", True), self.dispatch))

    def test_boolean_revision_rejected(self):
        self.assertFalse(conditionally_eligible(replace(self.grant, revision=True),
                                               replace(self.dispatch, revision=True)))

    def test_invalid_identity_denied_even_when_equal(self):
        for identity in (" tenant-a", "tenant-a ", "", "\n"):
            with self.subTest(identity=identity):
                self.assertFalse(conditionally_eligible(replace(self.grant, tenant=identity),
                                                       replace(self.dispatch, tenant=identity)))


if __name__ == "__main__":
    unittest.main()
