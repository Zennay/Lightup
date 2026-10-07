import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lightup.domain import DomainStore, Role
from lightup.finding_export_cli import main
from lightup.models import Severity


class FindingExportCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "domain.db"
        self.store = DomainStore(self.db)
        self.user = self.store.bootstrap_operator("op@example.test", "Operator", "operator-password")
        self.op = self.store.context_for_user(self.user.user_id)
        self.a = self.store.create_client(self.op, "A")
        self.b = self.store.create_client(self.op, "B")
        self.client = self.store.create_user(self.op, "client@example.test", "Member",
                                             Role.CLIENT_MEMBER, self.a.client_id)
        self.store.set_password(self.op, self.client.user_id, "client-password")
        self.eng = self.store.create_engagement(self.op, self.a.client_id, "First")
        self.finding = self.store.record_finding(
            self.op, self.eng.engagement_id, "Private finding", Severity.LOW,
            "private.invalid", "Impact", "Fix the setting")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, email="op@example.test", password="operator-password",
                client_id=None, engagement_id=None, terminal=True, db=None):
        argv = ["--db", str(db or self.db), "--email", email,
                "--client-id", client_id or self.a.client_id]
        if engagement_id:
            argv += ["--engagement-id", engagement_id]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
             patch("lightup.finding_export_cli.getpass", return_value=password) as prompt, \
             patch("sys.stdin.isatty", return_value=terminal):
            code = main(argv)
        return code, out.getvalue(), err.getvalue(), prompt

    def test_operator_sign_in_and_csv_output(self):
        code, output, error, prompt = self.run_cli()
        self.assertEqual(code, 0)
        self.assertIn(self.finding.finding_id, output)
        self.assertEqual(error, "")
        prompt.assert_called_once()
        self.assertNotIn("operator-password", output)

    def test_client_own_tenant_export(self):
        code, output, error, _ = self.run_cli(
            email="client@example.test", password="client-password")
        self.assertEqual(code, 0)
        self.assertIn("Private finding", output)
        self.assertEqual(error, "")

    def test_bad_password_never_outputs_csv(self):
        code, output, error, _ = self.run_cli(password="wrong-password")
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("Sign-in failed", error)
        self.assertNotIn("wrong-password", error)

    def test_unknown_email_uses_same_error(self):
        known = self.run_cli(password="wrong-password")
        unknown = self.run_cli(email="missing@example.test", password="wrong-password")
        self.assertEqual(known[:3], unknown[:3])

    def test_foreign_tenant_denied_without_partial_csv(self):
        code, output, error, _ = self.run_cli(
            email="client@example.test", password="client-password", client_id=self.b.client_id)
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("Export denied", error)
        self.assertNotIn(self.b.client_id, error)

    def test_operator_mismatched_engagement_denied(self):
        code, output, _, _ = self.run_cli(client_id=self.b.client_id,
                                          engagement_id=self.eng.engagement_id)
        self.assertEqual(code, 2)
        self.assertEqual(output, "")

    def test_noninteractive_password_prompt_is_refused(self):
        code, output, error, prompt = self.run_cli(terminal=False)
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("Interactive terminal required", error)
        prompt.assert_not_called()

    def test_missing_database_does_not_create_file(self):
        missing = Path(self.tmp.name) / "missing.db"
        code, output, error, prompt = self.run_cli(db=missing)
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("existing domain database", error)
        self.assertFalse(missing.exists())
        prompt.assert_not_called()

    def test_locked_account_denied_without_data(self):
        for _ in range(DomainStore.LOGIN_MAX_FAILURES):
            self.store.authenticate("op@example.test", "wrong-password")
        code, output, error, _ = self.run_cli()
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("temporarily locked", error)

    def test_cli_has_no_password_or_role_override_argument(self):
        with redirect_stderr(io.StringIO()):
            for flag in ("--password", "--role"):
                with self.subTest(flag=flag), self.assertRaises(SystemExit):
                    main(["--db", str(self.db), "--email", "op@example.test",
                          "--client-id", self.a.client_id, flag, "value"])


if __name__ == "__main__":
    unittest.main()
