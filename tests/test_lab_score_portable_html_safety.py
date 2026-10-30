"""Reject active HTML in forged unsigned portable review ZIPs.

A valid canonical archive and recomputed SHA-256 manifest do not certify
content safety. These tests use synthetic localhost sources only.
"""
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from lightup import lab_score_calibration as cli


def invoke(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(map(str, args)))
    return code, out.getvalue(), err.getvalue()


class PortableHTMLAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        base = Path(cls.temp.name)
        cls.base = base
        originals = [base / "run1", base / "run2"]
        for source in originals:
            assert cli.run_lab_score_calibration(source)["passed"]
        saved = base / "saved"
        assert invoke("--compare-history", *originals, "--format", "html",
                      "--html-output-dir", saved)[0] == 0
        result = base / "valid"
        assert invoke("--compare-history", *originals, "--format", "html",
                      "--verify-html-output-dir", saved,
                      "--portable-review-output-dir", result)[0] == 0
        cls.archive = result / "LightUp-SYNTHETIC-OFFLINE-REVIEW.zip"
        with ZipFile(cls.archive) as archive:
            cls.payloads = {name: archive.read(name) for name in archive.namelist()}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def forged(self, name, replace_index=None, replace_history=None, schema=None):
        files = self.payloads.copy()
        if replace_index:
            files["index.html"] = replace_index(files["index.html"])
        if replace_history:
            files["history.html"] = replace_history(files["history.html"])
        manifest = json.loads(files["manifest.json"])
        if schema is not None:
            manifest["schema"] = schema
        for key in ("index.html", "history.html"):
            manifest["files"][key] = hashlib.sha256(files[key]).hexdigest()
        files["manifest.json"] = (json.dumps(manifest, indent=2,
                                             sort_keys=True, allow_nan=False)+"\n").encode()
        folder = self.base/name
        folder.mkdir(mode=0o700)
        out = folder/self.archive.name
        with ZipFile(out, "w", compression=ZIP_DEFLATED) as writer:
            for key, value in sorted(files.items()):
                member = ZipInfo(key, date_time=(2026, 1, 1, 0, 0, 0))
                member.compress_type = ZIP_DEFLATED
                member.external_attr = 0o600 << 16
                writer.writestr(member, value)
        out.chmod(0o600)
        return out

    def test_canonical_first_party_dashboard_still_accepted(self):
        code, output, err = invoke("--verify-portable-review", self.archive)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("TRANSPORT VERIFIED", output)

    def test_forged_rehashed_active_html_is_refused(self):
        transforms = {
            "script": lambda b: b.replace(b"</body>",
                                          b"<script>/* synthetic */</script></body>"),
            "iframe": lambda b: b.replace(b"</body>",
                                          b"<iframe src='x'></iframe></body>"),
            "external-link": lambda b: b.replace(
                b"href='review.md'", b"href='https://example.invalid/fake'"),
            "inline-handler": lambda b: b.replace(
                b"<h1>", b"<h1 onclick='synthetic()'>"),
            "redirect": lambda b: b.replace(
                b"</head>", b"<meta http-equiv='refresh' content='0;url=x'></head>"),
            "css-import": lambda b: b.replace(
                b"</style>", b"@import 'https://example.invalid/fake.css';</style>"),
        }
        for name, transform in transforms.items():
            with self.subTest(name=name):
                package = self.forged(name, replace_index=transform)
                with ZipFile(package) as reader:
                    self.assertIsNone(reader.testzip())
                    self.assertIn(
                        hashlib.sha256(reader.read("index.html")).hexdigest(),
                        reader.read("manifest.json").decode())
                code, output, error = invoke("--verify-portable-review", package)
                self.assertEqual((code, output), (2, ""))
                self.assertIn("HOLD", error)
                self.assertNotIn(str(self.base), error)

    def test_forged_active_history_is_refused(self):
        package = self.forged(
            "history-script", replace_history=lambda b: b.replace(
                b"</body>", b"<script>/* synthetic */</script></body>"))
        self.assertEqual(invoke("--verify-portable-review", package)[0], 2)

    def test_rehashed_passive_dashboard_misinformation_is_refused_for_v3(self):
        # This HTML is inert and looks innocuous, unlike script injection.
        # Its headline lies about the admitted anonymous summary.
        tamper = lambda b: b.replace(b"Synthetic PASS only", b"Live approval granted")
        package = self.forged("fake-human-approval", replace_index=tamper)
        with ZipFile(package) as reader:
            self.assertIsNone(reader.testzip())
        code, output, error = invoke("--verify-portable-review", package)
        self.assertEqual((code, output), (2, ""))
        self.assertIn("HOLD", error)

    def test_forged_passive_history_approval_and_pair_rewrite_refused(self):
        changes = {
            "fake-history-headline": lambda b: b.replace(
                b"Canonical synthetic original history: PASS",
                b"Original evidence authenticated: PASS"),
            "fake-history-pair": lambda b: b.replace(
                b"Evidence independent: yes",
                b"Evidence independent: NOT CHECKED"),
        }
        for name, transform in changes.items():
            with self.subTest(name=name):
                package = self.forged(name, replace_history=transform)
                with ZipFile(package) as reader:
                    self.assertIsNone(reader.testzip())
                code, output, error = invoke("--verify-portable-review", package)
                self.assertEqual((code, output), (2, ""))
                self.assertIn("HOLD", error)

    def test_v2_downgrade_remains_inspectable_but_not_verified_pass(self):
        package = self.forged(
            "v2-false-history",
            replace_history=lambda b: b.replace(
                b"Canonical synthetic original history: PASS",
                b"Approved to assess live targets"),
            schema="lightup.lab-score-portable-human-review.v2")
        code, output, error = invoke("--verify-portable-review", package)
        self.assertEqual((code, error), (2, ""))
        self.assertIn("LEGACY review HTML contents NOT fully independently validated", output)
        self.assertIn("status HOLD", output)

    def test_unsigned_schema_downgrade_cannot_silently_promote_pass(self):
        # Even without active HTML, a forged v1 transport can never
        # advertise a validated PASS because content binding did not exist.
        package = self.forged(
            "v1-downgrade",
            replace_index=lambda b: b.replace(b"Synthetic PASS only",
                                             b"Approved by human"),
            schema="lightup.lab-score-portable-human-review.v1",
        )
        code, output, error = invoke("--verify-portable-review", package)
        self.assertEqual((code, error), (2, ""))
        self.assertIn("LEGACY review HTML contents NOT fully independently validated", output)
        self.assertIn("status HOLD", output)

    def test_legacy_inert_bodyless_index_is_still_supported(self):
        def legacy(b):
            return (
                "<!doctype html><html lang='en'><meta charset='utf-8'>"
                "<meta http-equiv='Content-Security-Policy' "
                "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
                "<title>LightUp synthetic offline review</title>"
                "<h1>Offline HUMAN review</h1><p>Source not authenticated.</p>"
                "<ul><li><a href='history.html'>History</a></li></ul></html>\n"
            ).encode("utf-8")
        package = self.forged("legacy", replace_index=legacy,
                              schema="lightup.lab-score-portable-human-review.v1")
        code, output, error = invoke("--verify-portable-review", package)
        self.assertEqual((code, error), (2, ""))
        self.assertIn("TRANSPORT VERIFIED", output)
        self.assertIn("LEGACY review HTML contents NOT fully independently validated", output)
        self.assertIn("status HOLD", output)
