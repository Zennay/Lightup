"""Offline reference for non-transferable scope consent; never authorizes execution."""
from dataclasses import dataclass
import unittest
import unicodedata


@dataclass(frozen=True)
class Consent:
    tenant_id: str
    engagement_id: str
    owner_id: str
    asset_id: str
    capability_id: str
    revision: int
    approved: bool


def matches_consent(consent: Consent, *, tenant_id: str, engagement_id: str,
                    owner_id: str, asset_id: str, capability_id: str,
                    revision: int, revoked: bool) -> bool:
    """Illustrative all-field exact binding; not a trusted grant issuer."""
    if type(consent) is not Consent:
        return False
    fields = (consent.tenant_id, consent.engagement_id, consent.owner_id,
              consent.asset_id, consent.capability_id)
    requested = (tenant_id, engagement_id, owner_id, asset_id, capability_id)
    if any(type(value) is not str or not value.strip() or
           any(ord(char) < 32 or ord(char) == 127 or
               0xD800 <= ord(char) <= 0xDFFF or
               unicodedata.category(char) in ("Cc", "Cf", "Cs", "Zl", "Zp") for char in value)
           for value in fields + requested):
        return False
    if type(consent.revision) is not int or type(revision) is not int:
        return False
    if consent.revision < 1 or revision < 1:
        return False
    if type(consent.approved) is not bool or type(revoked) is not bool:
        return False
    return (consent.approved is True and revoked is False
            and consent.revision == revision and fields == requested)


class ScopeConsentNontransferabilityReferenceTests(unittest.TestCase):
    def setUp(self):
        self.consent = Consent("tenant-A", "engagement-A", "owner-A",
                               "asset-A", "web-baseline", 3, True)
        self.request = dict(tenant_id="tenant-A", engagement_id="engagement-A",
                            owner_id="owner-A", asset_id="asset-A",
                            capability_id="web-baseline", revision=3, revoked=False)

    def test_exact_match_reference_only(self):
        self.assertTrue(matches_consent(self.consent, **self.request))

    def test_reject_cross_tenant_transfer(self):
        self.assertFalse(matches_consent(self.consent, **(self.request | {"tenant_id": "tenant-B"})))

    def test_reject_engagement_reuse(self):
        self.assertFalse(matches_consent(self.consent, **(self.request | {"engagement_id": "engagement-B"})))

    def test_reject_owner_change_even_same_asset(self):
        self.assertFalse(matches_consent(self.consent, **(self.request | {"owner_id": "owner-B"})))

    def test_reject_asset_or_capability_reassignment(self):
        for field, value in (("asset_id", "asset-B"), ("capability_id", "tls-baseline")):
            with self.subTest(field=field):
                self.assertFalse(matches_consent(self.consent, **(self.request | {field: value})))

    def test_reject_stale_revision_or_revocation(self):
        for changes in ({"revision": 4}, {"revoked": True}):
            with self.subTest(changes=changes):
                self.assertFalse(matches_consent(self.consent, **(self.request | changes)))

    def test_reject_truthy_nonboolean_approval(self):
        self.assertFalse(matches_consent(Consent("tenant-A", "engagement-A", "owner-A",
                                                "asset-A", "web-baseline", 3, "true"),
                                         **self.request))

    def test_reject_bool_revision_and_polymorphic_identity(self):
        self.assertFalse(matches_consent(self.consent, **(self.request | {"revision": True})))
        class Forged(str):
            pass
        self.assertFalse(matches_consent(self.consent, **(self.request | {"owner_id": Forged("owner-A")})))

    def test_reject_empty_identity_or_malformed_revocation(self):
        self.assertFalse(matches_consent(self.consent, **(self.request | {"tenant_id": "  "})))
        self.assertFalse(matches_consent(self.consent, **(self.request | {"revoked": 0})))

    def test_transfer_back_requires_new_authorization_revision(self):
        # Returning an asset to the original owner must not resurrect old consent.
        request_after_transfer_back = self.request | {"revision": 4}
        self.assertFalse(matches_consent(self.consent, **request_after_transfer_back))
        renewed = Consent("tenant-A", "engagement-A", "owner-A",
                          "asset-A", "web-baseline", 4, True)
        self.assertTrue(matches_consent(renewed, **request_after_transfer_back))

    def test_revocation_cannot_be_undone_by_revision_match(self):
        for revision in (3, 4):
            with self.subTest(revision=revision):
                approval = Consent("tenant-A", "engagement-A", "owner-A",
                                   "asset-A", "web-baseline", revision, True)
                request = self.request | {"revision": revision, "revoked": True}
                self.assertFalse(matches_consent(approval, **request))

    def test_reject_nonboolean_revocation_even_if_falsy(self):
        for forged in (None, "", [], {}, 0):
            with self.subTest(value=repr(forged)):
                self.assertFalse(matches_consent(self.consent, **(self.request | {"revoked": forged})))

    def test_reject_unapproved_consent_even_if_identifiers_match(self):
        unapproved = Consent("tenant-A", "engagement-A", "owner-A",
                             "asset-A", "web-baseline", 3, False)
        self.assertFalse(matches_consent(unapproved, **self.request))

    def test_reject_missing_or_forged_stored_identity(self):
        class Forged(str):
            pass
        for replacement in ("", "  ", Forged("owner-A")):
            with self.subTest(replacement=repr(replacement)):
                changed = Consent("tenant-A", "engagement-A", replacement,
                                  "asset-A", "web-baseline", 3, True)
                self.assertFalse(matches_consent(changed, **self.request))

    def test_reject_lookalike_identifiers_without_normalizing_authority(self):
        for field, replacement in (("tenant_id", "tenant-a"),
                                   ("owner_id", "owner-A "),
                                   ("asset_id", "asset-Α")):
            with self.subTest(field=field):
                self.assertFalse(matches_consent(
                    self.consent, **(self.request | {field: replacement})))

    def test_reject_hostile_consent_container_without_attribute_access(self):
        class Hostile:
            def __getattribute__(self, name):
                raise AssertionError("untrusted attribute access")
        self.assertFalse(matches_consent(Hostile(), **self.request))

    def test_reject_consent_subclass_override_without_attribute_access(self):
        class HostileConsent(Consent):
            def __getattribute__(self, name):
                raise AssertionError("subclass intercept")
        forged = object.__new__(HostileConsent)
        self.assertFalse(matches_consent(forged, **self.request))

    def test_no_implicit_string_conversion_of_requested_identity(self):
        class Hostile:
            def __str__(self):
                raise AssertionError("implicit conversion")
            def __eq__(self, other):
                raise AssertionError("untrusted equality")
        self.assertFalse(matches_consent(self.consent,
                                         **(self.request | {"asset_id": Hostile()})))

    def test_reject_zero_or_negative_revision(self):
        for invalid in (0, -1, -999):
            with self.subTest(revision=invalid):
                self.assertFalse(matches_consent(
                    self.consent, **(self.request | {"revision": invalid})))
                invalid_record = Consent("tenant-A", "engagement-A", "owner-A",
                                         "asset-A", "web-baseline", invalid, True)
                self.assertFalse(matches_consent(
                    invalid_record, **(self.request | {"revision": invalid})))

    def test_reject_stored_boolean_revision(self):
        invalid_record = Consent("tenant-A", "engagement-A", "owner-A",
                                 "asset-A", "web-baseline", True, True)
        self.assertFalse(matches_consent(invalid_record,
                                         **(self.request | {"revision": True})))

    def test_reject_control_characters_in_stored_and_requested_identities(self):
        for field in ("tenant_id", "engagement_id", "owner_id", "asset_id", "capability_id"):
            for suffix in map(chr, (0, 9, 10, 13, 127)):
                with self.subTest(field=field, suffix=repr(suffix)):
                    self.assertFalse(matches_consent(
                        self.consent, **(self.request | {field: self.request[field] + suffix})))
                    data = dict(tenant_id=self.consent.tenant_id,
                                engagement_id=self.consent.engagement_id,
                                owner_id=self.consent.owner_id,
                                asset_id=self.consent.asset_id,
                                capability_id=self.consent.capability_id,
                                revision=3, approved=True)
                    data[field] += suffix
                    self.assertFalse(matches_consent(
                        Consent(**data), **(self.request | {field: data[field]})))

    def test_control_character_fixture_is_real_codepoint(self):
        for value in map(chr, (0, 9, 10, 13, 127)):
            with self.subTest(codepoint=ord(value)):
                self.assertEqual(len(value), 1)
                self.assertTrue(ord(value) < 32 or ord(value) == 127)

    def test_stored_binding_mutation_denied_even_when_request_unchanged(self):
        original = dict(tenant_id=self.consent.tenant_id,
                        engagement_id=self.consent.engagement_id,
                        owner_id=self.consent.owner_id,
                        asset_id=self.consent.asset_id,
                        capability_id=self.consent.capability_id,
                        revision=self.consent.revision, approved=True)
        for field in ("tenant_id", "engagement_id", "owner_id", "asset_id", "capability_id"):
            with self.subTest(field=field):
                mutated = original | {field: original[field] + "-changed"}
                self.assertFalse(matches_consent(Consent(**mutated), **self.request))

    def test_all_binding_fields_must_match_not_just_owner_and_asset(self):
        # This catches accidental omission of tenant, engagement or capability checks.
        for field in ("tenant_id", "engagement_id", "owner_id", "asset_id", "capability_id"):
            with self.subTest(field=field):
                swapped = self.request | {field: "alternate-" + self.request[field]}
                self.assertFalse(matches_consent(self.consent, **swapped))

    def test_reject_unicode_format_and_surrogate_identifiers(self):
        for suffix in ("\u200b", "\u202e", "\ud800"):
            for field in ("tenant_id", "engagement_id", "owner_id",
                          "asset_id", "capability_id"):
                with self.subTest(field=field, codepoint=hex(ord(suffix))):
                    self.assertFalse(matches_consent(
                        self.consent,
                        **(self.request | {field: self.request[field] + suffix})))

    def test_reject_unicode_bidi_controls_and_joiners_across_all_bindings(self):
        # Identity strings must not carry invisible formatting that changes display.
        for codepoint in (0x200C, 0x200D, 0x2060, 0x202A, 0x202B,
                          0x202C, 0x202D, 0x2066, 0x2067, 0x2068, 0x2069):
            for field in ("tenant_id", "engagement_id", "owner_id",
                          "asset_id", "capability_id"):
                with self.subTest(codepoint=hex(codepoint), field=field):
                    contaminated = self.request[field] + chr(codepoint)
                    self.assertFalse(matches_consent(
                        self.consent, **(self.request | {field: contaminated})))

    def test_reject_unicode_format_controls_in_stored_consent_too(self):
        for codepoint in (0x200B, 0x200D, 0x202E, 0x2066):
            for field in ("tenant_id", "engagement_id", "owner_id",
                          "asset_id", "capability_id"):
                with self.subTest(codepoint=hex(codepoint), field=field):
                    data = dict(tenant_id=self.consent.tenant_id,
                                engagement_id=self.consent.engagement_id,
                                owner_id=self.consent.owner_id,
                                asset_id=self.consent.asset_id,
                                capability_id=self.consent.capability_id,
                                revision=3, approved=True)
                    data[field] += chr(codepoint)
                    self.assertFalse(matches_consent(
                        Consent(**data), **(self.request | {field: data[field]})))

    def test_benign_unicode_letters_remain_exactly_bound(self):
        # Reference screening must not broadly ban legitimate Unicode identities.
        for replacement in ("e\u0301", "\u00e9", "\u03b1", "\u6771"):
            with self.subTest(value=ascii(replacement)):
                approved = Consent("tenant-A", "engagement-A", replacement,
                                   "asset-A", "web-baseline", 3, True)
                self.assertTrue(matches_consent(
                    approved, **(self.request | {"owner_id": replacement})))
                self.assertFalse(matches_consent(
                    approved, **(self.request | {"owner_id": "owner-A"})))

    def test_canonical_equivalent_unicode_is_not_implicit_authority(self):
        stored = Consent("tenant-A", "engagement-A", "\u00e9",
                         "asset-A", "web-baseline", 3, True)
        self.assertFalse(matches_consent(
            stored, **(self.request | {"owner_id": "e\u0301"})))

    def test_reject_all_unicode_surrogate_range_without_coercion(self):
        for codepoint in (0xD800, 0xDBFF, 0xDC00, 0xDFFF):
            with self.subTest(codepoint=hex(codepoint)):
                forged = self.request | {"asset_id": self.request["asset_id"] + chr(codepoint)}
                self.assertFalse(matches_consent(self.consent, **forged))

    def test_combining_marks_do_not_normalize_other_binding_fields(self):
        for field in ("tenant_id", "engagement_id", "asset_id", "capability_id"):
            with self.subTest(field=field):
                original = self.request[field]
                forged = self.request | {field: original + "\u0301"}
                self.assertFalse(matches_consent(self.consent, **forged))

    def test_only_requested_revision_must_match_exactly(self):
        # Independently mutate the persisted grant revision and request revision.
        for stored, requested in ((4, 3), (3, 4), (10, 9)):
            with self.subTest(stored=stored, requested=requested):
                changed = Consent("tenant-A", "engagement-A", "owner-A",
                                  "asset-A", "web-baseline", stored, True)
                self.assertFalse(matches_consent(
                    changed, **(self.request | {"revision": requested})))

    def test_nonboolean_approved_values_fail_closed_even_when_falsey(self):
        for approval in (None, 0, 1, "", "false", [], {}):
            with self.subTest(value=repr(approval)):
                changed = Consent("tenant-A", "engagement-A", "owner-A",
                                  "asset-A", "web-baseline", 3, approval)
                self.assertFalse(matches_consent(changed, **self.request))

    def test_reject_unicode_line_and_paragraph_separators(self):
        for separator in map(chr, (0x2028, 0x2029)):
            for field in ("tenant_id", "engagement_id", "owner_id", "asset_id", "capability_id"):
                with self.subTest(field=field, codepoint=ascii(separator)):
                    self.assertFalse(matches_consent(
                        self.consent, **(self.request | {field: self.request[field] + separator})))

    def test_reject_unicode_separator_in_stored_and_requested_binding(self):
        for codepoint in (0x2028, 0x2029):
            for field in ("tenant_id", "engagement_id", "owner_id", "asset_id", "capability_id"):
                with self.subTest(field=field, codepoint=hex(codepoint)):
                    record = dict(tenant_id=self.consent.tenant_id,
                                  engagement_id=self.consent.engagement_id,
                                  owner_id=self.consent.owner_id,
                                  asset_id=self.consent.asset_id,
                                  capability_id=self.consent.capability_id,
                                  revision=3, approved=True)
                    record[field] += chr(codepoint)
                    self.assertFalse(matches_consent(
                        Consent(**record), **(self.request | {field: record[field]})))

    def test_all_ascii_control_codepoints_rejected_for_request_and_storage(self):
        for codepoint in (*range(32), 127):
            for field in ("tenant_id", "engagement_id", "owner_id", "asset_id", "capability_id"):
                with self.subTest(codepoint=codepoint, field=field):
                    altered = self.request[field] + chr(codepoint)
                    self.assertFalse(matches_consent(
                        self.consent, **(self.request | {field: altered})))
                    record = dict(tenant_id=self.consent.tenant_id,
                                  engagement_id=self.consent.engagement_id,
                                  owner_id=self.consent.owner_id,
                                  asset_id=self.consent.asset_id,
                                  capability_id=self.consent.capability_id,
                                  revision=3, approved=True)
                    record[field] = altered
                    self.assertFalse(matches_consent(
                        Consent(**record), **(self.request | {field: altered})))

    def test_approval_revision_is_not_float_or_numeric_string(self):
        for forged in (3.0, "3", "+3", 3.5):
            with self.subTest(value=repr(forged)):
                self.assertFalse(matches_consent(
                    self.consent, **(self.request | {"revision": forged})))
                record = Consent("tenant-A", "engagement-A", "owner-A",
                                 "asset-A", "web-baseline", forged, True)
                self.assertFalse(matches_consent(record, **self.request))

    def test_valid_revision_still_requires_live_unrevoked_consent(self):
        for revocation in (False, True):
            with self.subTest(revoked=revocation):
                decision = matches_consent(
                    self.consent, **(self.request | {"revoked": revocation}))
                self.assertEqual(decision, not revocation)


if __name__ == "__main__":
    unittest.main()
