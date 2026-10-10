"""Offline real-FindingRecord regressions for advisory remediation triage."""
from __future__ import annotations

from dataclasses import replace
import json
import unittest

from lightup.domain import FindingRecord
from lightup.models import RetestStatus, Severity
from lightup.remediation_review_queue import (
    MAX_EVIDENCE_IDS,
    MAX_FINDINGS,
    RemediationReviewItem,
    RemediationReviewQueue,
    build_remediation_review_queue,
)


def finding(**changes: object) -> FindingRecord:
    fields = dict(
        finding_id="finding-1",
        client_id="client-A",
        engagement_id="engagement-A",
        title="A private finding title",
        severity=Severity.HIGH,
        asset="internal://sensitive-customer-host",
        impact="internal impact with password=private",
        remediation="Replace unsafe configuration. Authorization: Bearer SECRET",
        retest_status=RetestStatus.FIX_PENDING,
        evidence_ids=("evidence-1",),
        created_at="2026-10-10T00:00:00+00:00",
    )
    fields.update(changes)
    return FindingRecord(**fields)


def queue(*rows: FindingRecord, **kwargs: str):
    return build_remediation_review_queue(
        tuple(rows),
        client_id=kwargs.get("client_id", "client-A"),
        engagement_id=kwargs.get("engagement_id", "engagement-A"),
    )


class RemediationQueueTests(unittest.TestCase):
    def test_empty_queue_is_non_authorizing_and_stable(self):
        a = queue()
        self.assertEqual(a.items, ())
        self.assertEqual(len(a.digest_sha256), 64)
        self.assertEqual(a, queue())
        body = json.loads(a.to_json())
        self.assertFalse(body["authorization_verified"])
        self.assertFalse(body["evidence_verified"])
        self.assertFalse(body["remediation_authorized"])
        self.assertFalse(body["retest_authorized"])
        self.assertFalse(body["release_authorized"])

    def test_historical_fixed_status_requires_independent_retest(self):
        result = queue(finding(retest_status=RetestStatus.FIXED))
        self.assertEqual(result.items[0].next_review_step, "independent_retest")
        self.assertEqual(result.items[0].claimed_retest_status, RetestStatus.FIXED)
        self.assertFalse(result.items[0].fix_verified)
        self.assertFalse(result.items[0].remediation_authorized)

    def test_missing_evidence_never_promotes_fixed_to_verified(self):
        result = queue(finding(evidence_ids=(), retest_status=RetestStatus.FIXED))
        self.assertEqual(result.items[0].next_review_step, "collect_evidence")
        self.assertEqual(result.items[0].referenced_evidence_count, 0)
        self.assertFalse(result.items[0].evidence_verified)

    def test_missing_remediation_requires_human_authoring(self):
        row = finding(remediation="   ", retest_status=RetestStatus.NOT_TESTED)
        self.assertEqual(queue(row).items[0].next_review_step, "author_remediation")

    def test_invisible_or_nonsemantic_remediation_requires_authoring(self):
        empty_in_practice = (
            chr(0x200D), chr(0x202E), chr(0x200B), chr(0x2060),
            chr(0x0301), " ⚠️ ", " ✨ ", " -- ",
            "  " + chr(0x200D) + "  ",
        )
        for value in empty_in_practice:
            with self.subTest(value=ascii(value)):
                result = queue(finding(remediation=value))
                self.assertEqual(result.items[0].next_review_step,
                                 "author_remediation")
                self.assertFalse(result.items[0].fix_verified)
                self.assertFalse(result.evidence_verified)

    def test_non_latin_remediation_counts_as_present_but_not_verified(self):
        for value in ("修复配置", "Исправить настройку", "إصلاح الخلل",
                      "確認して修正", "chmod 600", "✅ 修复"):
            with self.subTest(value=value):
                result = queue(finding(remediation=value))
                self.assertEqual(result.items[0].next_review_step,
                                 "review_remediation")
                self.assertFalse(result.items[0].fix_verified)
                self.assertFalse(result.remediation_authorized)

    def test_regression_is_investigation_not_automatic_reexecution(self):
        row = finding(retest_status=RetestStatus.REGRESSION)
        result = queue(row)
        self.assertEqual(result.items[0].next_review_step, "investigate_regression")
        self.assertFalse(result.retest_authorized)

    def test_normal_pending_remediation_is_review_only(self):
        result = queue(finding())
        self.assertEqual(result.items[0].next_review_step, "review_remediation")

    def test_severity_priority_independent_of_input_order(self):
        high = finding(finding_id="high", severity=Severity.HIGH)
        low = finding(finding_id="low", severity=Severity.LOW)
        critical = finding(finding_id="critical", severity=Severity.CRITICAL)
        first = queue(low, high, critical)
        second = queue(critical, low, high)
        self.assertEqual(first, second)
        self.assertEqual(
            [item.severity for item in first.items],
            [Severity.CRITICAL, Severity.HIGH, Severity.LOW],
        )
        self.assertEqual(first.to_json(), second.to_json())

    def test_digest_changes_when_review_step_changes(self):
        a = queue(finding(evidence_ids=()))
        b = queue(finding(evidence_ids=("evidence-1",)))
        self.assertNotEqual(a.digest_sha256, b.digest_sha256)

    def test_output_has_no_raw_evidence_text_or_tenant_identifiers(self):
        row = finding()
        result = queue(row)
        exported = result.to_json()
        for secret in (
            row.finding_id, row.client_id, row.engagement_id, row.asset,
            row.title, row.impact, row.remediation, row.evidence_ids[0],
            "SECRET", "internal://",
        ):
            self.assertNotIn(secret, exported)

    def test_input_record_remains_unchanged(self):
        row = finding()
        before = replace(row)
        queue(row)
        self.assertEqual(row, before)

    def test_cross_tenant_finding_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "scope mismatch"):
            queue(finding(client_id="other-tenant"))

    def test_cross_engagement_finding_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "scope mismatch"):
            queue(finding(engagement_id="other-engagement"))

    def test_duplicate_finding_identity_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            queue(finding(), finding())

    def test_exact_tuple_and_record_types_required(self):
        with self.assertRaises(ValueError):
            build_remediation_review_queue([finding()], client_id="client-A", engagement_id="engagement-A")
        class FakeFinding(FindingRecord):
            pass
        with self.assertRaises(ValueError):
            queue(FakeFinding(**finding().__dict__))

    def test_exact_enum_types_are_required(self):
        with self.assertRaisesRegex(ValueError, "status"):
            queue(finding(severity="high"))
        with self.assertRaisesRegex(ValueError, "status"):
            queue(finding(retest_status="fixed"))

    def test_rejects_malformed_and_repeated_evidence_ids(self):
        for evidence_ids in (
            ["evidence-1"],
            ("evidence-1", "evidence-1"),
            ("",),
            (" ",),
            (42,),
            ("id",) * (MAX_EVIDENCE_IDS + 1),
        ):
            with self.subTest(case=str(evidence_ids)[:20]):
                with self.assertRaises(ValueError):
                    queue(finding(evidence_ids=evidence_ids))

    def test_rejects_polymorphic_ids_and_secret_like_error_is_generic(self):
        class StrChild(str):
            pass
        for field in ("finding_id", "client_id", "engagement_id"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError) as caught:
                    queue(finding(**{field: StrChild("PRIVATE-SOURCE")}))
                self.assertNotIn("PRIVATE-SOURCE", str(caught.exception))

    def test_rejects_unbounded_findings_before_allocation(self):
        rows = tuple(finding(finding_id=f"finding-{i}") for i in range(MAX_FINDINGS + 1))
        with self.assertRaisesRegex(ValueError, "findings"):
            queue(*rows)

    def test_rejects_mutable_or_polymorphic_source_text(self):
        class StrChild(str):
            pass
        for value in (None, [], StrChild("looks like text"), "x" * 8193):
            with self.subTest(value=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "source field"):
                    queue(finding(remediation=value))


    def test_equal_count_evidence_substitution_changes_snapshot_digest(self):
        original = queue(finding(evidence_ids=("evidence-1", "evidence-2")))
        replaced = queue(finding(evidence_ids=("evidence-1", "evidence-OTHER")))
        self.assertEqual(original.items, replaced.items)
        self.assertNotEqual(original.digest_sha256, replaced.digest_sha256)
        self.assertNotIn("evidence-OTHER", replaced.to_json())

    def test_evidence_reference_order_changes_snapshot_digest(self):
        before = queue(finding(evidence_ids=("evidence-1", "evidence-2")))
        after = queue(finding(evidence_ids=("evidence-2", "evidence-1")))
        self.assertNotEqual(before.digest_sha256, after.digest_sha256)
        self.assertEqual(before.items, after.items)

    def test_equal_stage_remediation_revision_changes_snapshot_digest(self):
        first = queue(finding(remediation="Rotate secrets safely"))
        second = queue(finding(remediation="Replace the exposed key"))
        self.assertEqual(first.items, second.items)
        self.assertNotEqual(first.digest_sha256, second.digest_sha256)
        self.assertNotIn("Rotate secrets safely", first.to_json())
        self.assertNotIn("Replace the exposed key", second.to_json())

    def test_evidence_review_digest_not_reusable_across_empty_scopes(self):
        first = queue(client_id="client-A", engagement_id="engagement-A")
        different_client = queue(client_id="client-B", engagement_id="engagement-A")
        different_engagement = queue(client_id="client-A", engagement_id="engagement-B")
        self.assertNotEqual(first.digest_sha256, different_client.digest_sha256)
        self.assertNotEqual(first.digest_sha256, different_engagement.digest_sha256)
        for result in (first, different_client, different_engagement):
            self.assertEqual(result.items, ())
            self.assertNotIn("client-", result.to_json())
            self.assertNotIn("engagement-", result.to_json())

    def test_non_display_source_revision_invalidates_digest(self):
        first = queue(finding(asset="lab://one", impact="first claim",
                              title="old", created_at="2026-10-09T00:00:00Z"))
        revisions = (
            {"asset": "lab://two", "impact": "first claim", "title": "old",
             "created_at": "2026-10-09T00:00:00Z"},
            {"asset": "lab://one", "impact": "different claim", "title": "old",
             "created_at": "2026-10-09T00:00:00Z"},
            {"asset": "lab://one", "impact": "first claim", "title": "new",
             "created_at": "2026-10-09T00:00:00Z"},
            {"asset": "lab://one", "impact": "first claim", "title": "old",
             "created_at": "2026-10-10T00:00:00Z"},
        )
        for changes in revisions:
            with self.subTest(changes=changes):
                later = queue(finding(**changes))
                self.assertEqual(first.items, later.items)
                self.assertNotEqual(first.digest_sha256, later.digest_sha256)

    def test_queue_json_schema_v3_and_pseudonymous_fingerprint_only(self):
        original = queue(finding(remediation="sensitive-text-cannot-escape"))
        payload = json.loads(original.to_json())
        self.assertEqual(payload["schema_version"], "lightup.remediation_review_queue.v3")
        self.assertEqual(len(payload["digest_sha256"]), 64)
        self.assertNotIn("sensitive-text-cannot-escape", original.to_json())
        self.assertFalse(payload["release_authorized"])



    def test_printable_delimiter_cannot_alias_cross_scope_finding_keys(self):
        # Printable backslash + zero is a valid identifier substring, and
        # historically was also the field separator in the hash input.
        first = queue(
            finding(client_id=r"tenant\0sub", engagement_id="alpha",
                    finding_id="same-finding"),
            client_id=r"tenant\0sub", engagement_id="alpha",
        )
        second = queue(
            finding(client_id="tenant", engagement_id=r"sub\0alpha",
                    finding_id="same-finding"),
            client_id="tenant", engagement_id=r"sub\0alpha",
        )
        self.assertEqual(len(first.items), 1)
        self.assertEqual(len(second.items), 1)
        self.assertNotEqual(
            first.items[0].finding_key_sha256,
            second.items[0].finding_key_sha256,
        )
        self.assertNotEqual(first.digest_sha256, second.digest_sha256)
        self.assertNotIn("tenant", first.to_json())
        self.assertNotIn("tenant", second.to_json())

    def test_key_identity_changes_for_distinct_engagement_or_finding_ids(self):
        first = queue(finding(finding_id="same"))
        changed_id = queue(finding(finding_id="different"))
        changed_engagement = queue(
            finding(finding_id="same", engagement_id="another"),
            engagement_id="another",
        )
        self.assertNotEqual(first.items[0].finding_key_sha256,
                            changed_id.items[0].finding_key_sha256)
        self.assertNotEqual(first.items[0].finding_key_sha256,
                            changed_engagement.items[0].finding_key_sha256)


    def test_item_direct_constructor_rejects_positive_verification_flags(self):
        item = queue(finding()).items[0]
        for name in ("evidence_verified", "fix_verified", "remediation_authorized"):
            with self.subTest(flag=name):
                with self.assertRaisesRegex(ValueError, "cannot certify"):
                    replace(item, **{name: True})
                with self.assertRaisesRegex(ValueError, "cannot certify"):
                    replace(item, **{name: 0})

    def test_queue_direct_constructor_rejects_positive_authority_flags(self):
        advisory = queue(finding())
        for name in (
            "authorization_verified", "evidence_verified",
            "remediation_authorized", "retest_authorized", "release_authorized",
        ):
            with self.subTest(flag=name):
                with self.assertRaisesRegex(ValueError, "cannot certify"):
                    replace(advisory, **{name: True})
                with self.assertRaisesRegex(ValueError, "cannot certify"):
                    replace(advisory, **{name: 0})

    def test_direct_constructor_rejects_invalid_stage_digest_and_count(self):
        item = queue(finding()).items[0]
        for kwargs in (
            {"next_review_step": "execute_fix"},
            {"next_review_step": ""},
            {"referenced_evidence_count": -1},
            {"referenced_evidence_count": 65},
            {"referenced_evidence_count": True},
            {"finding_key_sha256": "A" * 64},
            {"severity": "high"},
            {"claimed_retest_status": "fixed"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(ValueError, "invalid remediation"):
                    replace(item, **kwargs)
        review = queue(finding())
        for kwargs in (
            {"digest_sha256": "bad"},
            {"items": [item]},
            {"items": (item, item)},
            {"items": tuple([item] * 129)},
        ):
            with self.subTest(kwargs=str(kwargs)[:80]):
                with self.assertRaisesRegex(ValueError, "invalid remediation"):
                    replace(review, **kwargs)

    def test_queue_direct_constructor_rejects_item_subclass(self):
        class SubItem(RemediationReviewItem):
            pass
        item = queue(finding()).items[0]
        forged = SubItem(**item.__dict__)
        with self.assertRaisesRegex(ValueError, "invalid remediation"):
            RemediationReviewQueue(
                items=(forged,),
                digest_sha256=queue(finding()).digest_sha256,
            )


if __name__ == "__main__":
    unittest.main()
