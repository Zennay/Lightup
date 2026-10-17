"""End-to-end and unit tests for the offline pre-merge change review."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup import cli
from lightup.change_review import (
    ChangeReviewPolicy, render_markdown, render_sarif, review_change,
)
from lightup.change_rules import LineSide, evaluate_patch, iter_patch_lines
from lightup.changes import ChangeObjectKind
from lightup.future_security_ci_verdict import SecurityCIVerdict
from lightup.git_changes import GitChangeError, collect_git_range
from lightup.models import Severity

# Built at runtime so no secret-shaped literal lives in the repository.
FAKE_AWS_KEY = "AKIA" + "Z" * 16
FAKE_PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"


def _patch(*added, removed=()):
    lines = [f"@@ -1,{len(removed)} +1,{len(added)} @@"]
    lines += [f"-{line}" for line in removed]
    lines += [f"+{line}" for line in added]
    return "\n".join(lines)


def _rules(path, kind, *added, removed=()):
    return {h.rule_id for h in evaluate_patch(
        path=path, kind=kind, patch=_patch(*added, removed=removed))}


class PatchLineTests(unittest.TestCase):
    def test_line_numbers_follow_hunk_headers(self):
        patch = "@@ -10,3 +20,4 @@\n ctx\n-old\n+new\n+newer\n ctx"
        self.assertEqual(
            list(iter_patch_lines(patch)),
            [(LineSide.REMOVED, 11, "old"), (LineSide.ADDED, 21, "new"),
             (LineSide.ADDED, 22, "newer")],
        )


class RuleTests(unittest.TestCase):
    SRC = ChangeObjectKind.SOURCE

    def test_secrets_detected(self):
        self.assertIn("secret.aws-access-key",
                      _rules("app/settings.py", self.SRC, f"KEY = '{FAKE_AWS_KEY}'"))
        self.assertIn("secret.private-key",
                      _rules("deploy/key.pem", ChangeObjectKind.OTHER, FAKE_PEM))
        self.assertIn("secret.generic-assignment",
                      _rules("app/db.py", self.SRC, 'password = "hunter2hunter2"'))

    def test_secret_placeholders_and_env_lookups_ignored(self):
        self.assertEqual(set(), _rules("app/db.py", self.SRC,
                                       'password = os.environ["DB_PASSWORD"]',
                                       'api_key = "<your-api-key-here>"',
                                       'secret = "changeme-please"'))

    def test_secrets_in_tests_and_docs_ignored(self):
        self.assertEqual(set(), _rules("tests/test_x.py", ChangeObjectKind.TEST,
                                       f"KEY = '{FAKE_AWS_KEY}'"))
        self.assertEqual(set(), _rules("docs/x.md", ChangeObjectKind.DOC, FAKE_PEM))

    def test_injection_rules(self):
        found = _rules(
            "app/run.py", self.SRC,
            "subprocess.run(cmd, shell=True)",
            "data = pickle.loads(body)",
            "cfg = yaml.load(text)",
            'cur.execute(f"SELECT * FROM users WHERE id = {uid}")',
            "result = eval(expr)",
        )
        self.assertTrue({"code.python-shell-true", "code.unsafe-deserialization",
                         "code.sql-string-build", "code.dynamic-eval"} <= found)

    def test_safe_variants_not_flagged(self):
        self.assertEqual(set(), _rules(
            "app/run.py", self.SRC,
            "subprocess.run(['ls', path])",
            "cfg = yaml.load(text, Loader=yaml.SafeLoader)",
            'cur.execute("SELECT * FROM users WHERE id = ?", (uid,))',
            "value = ast.literal_eval(expr)",
        ))

    def test_removed_auth_guard_is_flagged_only_on_removal(self):
        self.assertIn("auth.guard-removed", _rules(
            "app/views.py", self.SRC, "def admin():", removed=("@login_required",)))
        self.assertNotIn("auth.guard-removed", _rules(
            "app/views.py", self.SRC, "@login_required"))

    def test_infrastructure_rules(self):
        found = _rules(
            "infra/main.tf", ChangeObjectKind.IAC,
            'cidr_blocks = ["0.0.0.0/0"]',
            'acl = "public-read"',
            "storage_encrypted = false",
        )
        self.assertTrue({"iac.open-ingress", "iac.public-storage",
                         "iac.encryption-disabled"} <= found)
        self.assertEqual(set(), _rules("infra/main.tf", ChangeObjectKind.IAC,
                                       'egress_cidr = "0.0.0.0/0"  # egress'))

    def test_iam_wildcards(self):
        found = _rules("iam/policy.json", ChangeObjectKind.IAM,
                       '"Action": "*",', '"Principal": {"AWS": "*"}')
        self.assertTrue({"iam.wildcard-action", "iam.wildcard-principal"} <= found)

    def test_ci_rules(self):
        found = _rules(
            ".github/workflows/ci.yml", ChangeObjectKind.CI,
            "on: pull_request_target",
            "  run: echo ${{ github.event.pull_request.title }}",
            "  uses: someone/deploy-action@v2",
            "  uses: actions/checkout@v4",
        )
        self.assertTrue({"ci.pull-request-target", "ci.script-injection",
                         "ci.unpinned-action"} <= found)

    def test_inline_suppression(self):
        self.assertEqual(set(), _rules(
            "app/run.py", self.SRC, "subprocess.run(cmd, shell=True)  # lightup: ignore"))

    def test_hypotheses_never_retain_matched_content(self):
        hypotheses = evaluate_patch(path="app/settings.py", kind=self.SRC,
                                    patch=_patch(f"KEY = '{FAKE_AWS_KEY}'"))
        self.assertTrue(hypotheses)
        blob = json.dumps([h.to_dict() for h in hypotheses])
        self.assertNotIn(FAKE_AWS_KEY, blob)
        self.assertTrue(all(h.provenance.value == "inferred" for h in hypotheses))


def _files(**patches):
    return [{"filename": path, "status": "modified", "additions": 1,
             "deletions": 0, "patch": patch} for path, patch in patches.items()]


class VerdictTests(unittest.TestCase):
    def _review(self, files, policy=None):
        return review_change(client_id="client-1", repository="acme/app",
                             base_revision="a" * 40, head_revision="b" * 40,
                             files=files, policy=policy)

    def test_clean_change_passes_but_says_it_is_not_a_clean_bill(self):
        review = self._review(_files(**{"app/x.py": _patch("x = 1")}))
        self.assertIs(review.verdict, SecurityCIVerdict.PASS)
        self.assertIn("not a clean bill of health", review.reasons[0].reason)

    def test_critical_blocks_high_requires_review(self):
        blocked = self._review(_files(**{"app/x.py": _patch(f"K='{FAKE_AWS_KEY}'")}))
        self.assertIs(blocked.verdict, SecurityCIVerdict.BLOCK)
        self.assertEqual(blocked.conclusion, "failure")
        review = self._review(_files(**{"app/x.py": _patch("subprocess.call(c, shell=True)")}))
        self.assertIs(review.verdict, SecurityCIVerdict.REVIEW_REQUIRED)

    def test_unanalyzed_file_is_not_silently_passed(self):
        files = [{"filename": "assets/logo.png", "status": "added",
                  "additions": None, "deletions": None, "patch": None}]
        review = self._review(files)
        self.assertIs(review.verdict, SecurityCIVerdict.PASS_WITH_WARNING)
        self.assertEqual(review.unanalyzed_paths, ("assets/logo.png",))

    def test_policy_suppression_and_override(self):
        files = _files(**{"app/x.py": _patch(f"K='{FAKE_AWS_KEY}'")})
        policy = ChangeReviewPolicy.from_mapping({"ignore_paths": ["app/*"]})
        review = self._review(files, policy)
        self.assertIs(review.verdict, SecurityCIVerdict.PASS)
        self.assertEqual(len(review.suppressed), 1)
        policy = ChangeReviewPolicy.from_mapping(
            {"severity_verdicts": {"critical": "REVIEW_REQUIRED"}})
        self.assertIs(self._review(files, policy).verdict,
                      SecurityCIVerdict.REVIEW_REQUIRED)
        with self.assertRaises(ValueError):
            ChangeReviewPolicy.from_mapping({"block_everything": True})

    def test_report_is_labelled_inferred_and_not_authorization(self):
        review = self._review(_files(**{"app/x.py": _patch("subprocess.call(c, shell=True)")}))
        data = review.to_dict()
        self.assertEqual(data["basis"], "inferred")
        self.assertTrue(data["not_authorization"])
        self.assertEqual(data["future_twin"]["future_semantics"], "unresolved")
        self.assertIn("**inferred**", render_markdown(review))
        sarif = render_sarif(review)
        self.assertEqual(sarif["version"], "2.1.0")
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "code.python-shell-true")
        self.assertEqual(
            result["locations"][0]["physicalLocation"]["region"]["startLine"], 1)


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x"})


class GitRangeEndToEndTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-review-")
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        _git(self.repo, "init", "-q", "-b", "main")
        (self.repo / "app").mkdir()
        (self.repo / "app" / "views.py").write_text(
            "@login_required\ndef admin():\n    return 'ok'\n")
        (self.repo / "openapi.json").write_text(json.dumps(
            {"openapi": "3.0.0", "paths": {"/health": {"get": {}}}}))
        (self.repo / "README.md").write_text("hello\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "base")
        _git(self.repo, "checkout", "-qb", "feature")
        (self.repo / "app" / "views.py").write_text(
            "def admin():\n    return 'ok'\n")
        (self.repo / "app" / "run.py").write_text(
            "import subprocess\n"
            "def go(cmd):\n"
            "    return subprocess.run(cmd, shell=True)\n"
            f"AWS = '{FAKE_AWS_KEY}'\n")
        (self.repo / "infra").mkdir()
        (self.repo / "infra" / "main.tf").write_text(
            'resource "aws_security_group" "web" {\n'
            '  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
        (self.repo / "openapi.json").write_text(json.dumps(
            {"openapi": "3.0.0", "paths": {"/health": {"get": {}},
                                           "/admin/export": {"post": {}}}}))
        (self.repo / "README.md").write_text("hello world\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "feature")

    def test_collect_git_range(self):
        git_range = collect_git_range(self.repo, "main", "feature",
                                      repository="acme/app")
        paths = {item["filename"]: item for item in git_range.files}
        self.assertEqual(set(paths), {"app/views.py", "app/run.py", "infra/main.tf",
                                      "openapi.json", "README.md"})
        self.assertEqual(paths["app/run.py"]["status"], "added")
        self.assertTrue(paths["app/run.py"]["patch"].startswith("@@"))
        self.assertIn("openapi.json", git_range.structured_deltas)
        self.assertIn("infra/main.tf", git_range.structured_deltas)

    def test_unsafe_revisions_rejected(self):
        for ref in ("--output=/tmp/x", "main..feature", "a b"):
            with self.subTest(ref=ref), self.assertRaises(GitChangeError):
                collect_git_range(self.repo, ref, "feature")

    def test_full_review_blocks_planted_change(self):
        git_range = collect_git_range(self.repo, "main", "feature",
                                      repository="acme/app")
        review = review_change(
            client_id="client-1", repository=git_range.repository,
            base_revision=git_range.base_revision,
            head_revision=git_range.head_revision, files=git_range.files,
            structured_deltas=git_range.structured_deltas,
        )
        rules = {h.rule_id for h in review.hypotheses}
        self.assertTrue({"secret.aws-access-key", "code.python-shell-true",
                         "auth.guard-removed", "iac.open-ingress"} <= rules)
        self.assertIs(review.verdict, SecurityCIVerdict.BLOCK)
        signals = {s.kind.value for s in review.changeset.semantic_signals}
        self.assertIn("api_surface", signals)
        self.assertGreater(review.to_dict()["future_twin"]["change_nodes"], 0)
        top = review.hypotheses[0]
        self.assertIs(top.severity, Severity.CRITICAL)
        self.assertEqual((top.path, top.line), ("app/run.py", 4))

    def test_cli_exit_codes_and_outputs(self):
        sarif_path = self.repo / "out.sarif"
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(["review-change", "--repo", str(self.repo), "--base", "main",
                             "--head", "feature", "--repository", "acme/app",
                             "--sarif-output", str(sarif_path)])
        self.assertEqual(code, 1)
        self.assertIn("**BLOCK**", out.getvalue())
        self.assertTrue(json.loads(sarif_path.read_text())["runs"][0]["results"])
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(["review-change", "--repo", str(self.repo), "--base", "main",
                             "--head", "feature", "--format", "json",
                             "--fail-on", "never"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["verdict"], "BLOCK")

    def test_cli_stores_review_for_existing_client_only(self):
        from lightup.domain import AccessContext, DomainStore, Role

        db = self.repo / "lightup.db"
        operator = AccessContext("t", Role.OPERATOR)
        client = DomainStore(db).create_client(operator, "Acme")
        argv = ["review-change", "--repo", str(self.repo), "--base", "main",
                "--head", "feature", "--fail-on", "never", "--db", str(db)]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(argv + ["--client-id", client.client_id]), 0)
            self.assertEqual(cli.main(argv + ["--client-id", "missing"]), 2)
        stored = DomainStore(db).list_change_reviews(operator, client.client_id)
        self.assertEqual([r.verdict for r in stored], ["BLOCK"])

    def test_cli_policy_file_in_repo_is_honoured(self):
        (self.repo / ".lightup-review.json").write_text(json.dumps(
            {"ignore_rules": ["secret.aws-access-key"]}))
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(["review-change", "--repo", str(self.repo), "--base", "main",
                             "--head", "feature", "--format", "json",
                             "--fail-on", "block"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["verdict"], "REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()
