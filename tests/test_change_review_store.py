"""Change reviews: inferred-only persistence, tenant isolation, web rendering."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from lightup.change_review import review_change
from lightup.domain import AccessContext, Role, RoleError, TenantIsolationError
import test_webapp


def _report(path="app/run.py", line="subprocess.run(cmd, shell=True)"):
    return review_change(
        client_id="any", repository="acme/app", base_revision="a" * 40,
        head_revision="b" * 40,
        files=[{"filename": path, "status": "modified", "additions": 1,
                "deletions": 0, "patch": f"@@ -1,0 +1,1 @@\n+{line}"}],
    ).to_dict()


class ChangeReviewStoreTest(unittest.TestCase):
    # Reuse the web shell fixture without re-running its own tests.
    setUp = test_webapp.WebAppTest.setUp
    tearDown = test_webapp.WebAppTest.tearDown
    request = test_webapp.WebAppTest.request

    def test_operator_records_and_tenants_are_isolated(self):
        record = self.store.record_change_review(
            self.operator, self.client_a.client_id, _report())
        self.assertEqual(record.verdict, "REVIEW_REQUIRED")
        client_ctx = self.store.context_for_user(self.user_a.user_id)
        self.assertEqual([r.review_id for r in self.store.list_change_reviews(client_ctx)],
                         [record.review_id])
        with self.assertRaises(TenantIsolationError):
            self.store.list_change_reviews(client_ctx, self.client_b.client_id)
        self.assertEqual(self.store.list_change_reviews(
            self.operator, self.client_b.client_id), [])
        with self.assertRaises(RoleError):
            self.store.record_change_review(client_ctx, self.client_a.client_id, _report())

    def test_non_inferred_or_authorizing_reports_rejected(self):
        for mutate in (lambda r: r.update(basis="verified"),
                       lambda r: r.update(not_authorization=False),
                       lambda r: r.update(verdict="APPROVED"),
                       lambda r: r.update(schema="other")):
            report = _report()
            mutate(report)
            with self.subTest(report=report.get("basis")), self.assertRaises(ValueError):
                self.store.record_change_review(self.operator, self.client_a.client_id, report)
        with self.assertRaises(KeyError):
            self.store.record_change_review(self.operator, "no-such-client", _report())

    def test_web_shell_renders_reviews_for_operator_and_client_only(self):
        self.store.record_change_review(self.operator, self.client_a.client_id, _report())
        status, _, body = self.request("GET", f"/clients/{self.client_a.client_id}",
                                       token=self.op_token)
        self.assertEqual(status, "200 OK")
        self.assertIn("Review required", body)
        self.assertIn("acme/app @ bbbbbbbbbbbb", body)
        status, _, body = self.request("GET", f"/portal/{self.client_a.client_id}",
                                       token=self.a_token)
        self.assertEqual(status, "200 OK")
        self.assertIn("Subprocess invoked through a shell", body)
        self.assertIn("never authorization to deploy", body)
        status, _, body = self.request("GET", f"/portal/{self.client_b.client_id}",
                                       token=self.op_token)
        self.assertIn("No change reviews yet", body)

    def test_review_content_is_html_escaped(self):
        report = _report()
        report["change"]["repository"] = "<script>alert(1)</script>/x"
        self.store.record_change_review(self.operator, self.client_a.client_id, report)
        _, _, body = self.request("GET", f"/portal/{self.client_a.client_id}",
                                  token=self.a_token)
        self.assertNotIn("<script>alert(1)</script>", body)


if __name__ == "__main__":
    unittest.main()
