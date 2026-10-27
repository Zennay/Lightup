"""Real registry and privacy-safe operator Markdown review regressions (#1372)."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from lightup.capabilities import Capability, CapabilityState, get_capabilities
from lightup.capability_registry_incubation_dossier import review_atomic_incubation_dossier
from lightup.capability_registry_incubation_markdown_report import (
    render_incubation_dossier_markdown,
)
from scripts.export_scope_capability_registry_offline import snapshot_manifest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts/render_scope_incubation_dossier_offline.py"
_PATCH = "lightup.capability_registry_incubation_markdown_report.review_atomic_incubation_dossier"


class IncubationMarkdownReportTests(unittest.TestCase):
    def setUp(self):
        self.registry = get_capabilities()
        self.raw = snapshot_manifest(self.registry)

    def mutate(self, ident="web-baseline", **fields):
        return snapshot_manifest(tuple(
            replace(c, **fields) if c.capability_id == ident else c
            for c in self.registry
        ))

    def assert_non_authorizing(self, report, code):
        self.assertIn("**Authority: NONE.**", report)
        self.assertIn("No target interaction", report)
        self.assertIn(code, (2, 3))
        self.assertNotIn("permit_issued=True", report)
        self.assertLessEqual(len(report), 32768)

    def test_real_unchanged_registry_exits_nonzero_review_only(self):
        report, code = render_incubation_dossier_markdown(self.raw)
        self.assertEqual(code, 3)
        self.assertIn("**Verdict:** `REVIEW_ONLY`", report)
        self.assertIn("Checked", report.replace("checked", "Checked"))
        self.assertIn("No capability metadata changes", report)
        self.assert_non_authorizing(report, code)

    def test_three_real_component_status_rows_present(self):
        report, code = render_incubation_dossier_markdown(self.raw)
        self.assertIn("| Closed-world catalog | `REVIEW_ONLY` |", report)
        self.assertIn("| Incubation lab / activation posture | `REVIEW_ONLY` |", report)
        self.assertIn("| Name and description metadata | `REVIEW_ONLY` |", report)
        self.assertEqual(code, 3)

    def test_reference_fingerprint_uses_only_sha256(self):
        report, _ = render_incubation_dossier_markdown(self.raw)
        self.assertRegex(report, r"sha256:[0-9a-f]{64}")
        self.assertNotIn("https://", report)

    def test_name_drift_holds_and_redacts_new_text(self):
        report, code = render_incubation_dossier_markdown(
            self.mutate(name="CONFIDENTIAL_CUSTOMER_NAME"))
        self.assertEqual(code, 2)
        self.assertIn("**Verdict:** `HOLD`", report)
        self.assertIn("| `web-baseline` | `fields` | `name` |", report)
        self.assertNotIn("CONFIDENTIAL_CUSTOMER_NAME", report)
        self.assert_non_authorizing(report, code)

    def test_description_drift_holds_and_redacts_new_text(self):
        report, code = render_incubation_dossier_markdown(
            self.mutate(description="PRIVATE_ORIGIN_STRING"))
        self.assertEqual(code, 2)
        self.assertIn("| `web-baseline` | `fields` | `description` |", report)
        self.assertNotIn("PRIVATE_ORIGIN_STRING", report)

    def test_name_description_drift_shows_both_fixed_labels(self):
        report, code = render_incubation_dossier_markdown(
            self.mutate(name="SECRET_N", description="SECRET_D"))
        self.assertEqual(code, 2)
        self.assertIn("| `web-baseline` | `fields` | `name` |", report)
        self.assertIn("| `web-baseline` | `fields` | `description` |", report)
        self.assertNotIn("SECRET_", report)

    def test_multiple_canonical_capability_fields_are_sorted(self):
        entries = tuple(
            replace(c, name="Secret later") if c.capability_id == "web-baseline"
            else replace(c, description="Secret earlier")
            if c.capability_id == "api-baseline" else c
            for c in self.registry
        )
        report, code = render_incubation_dossier_markdown(snapshot_manifest(entries))
        self.assertEqual(code, 2)
        self.assertLess(
            report.index("| `api-baseline` |"),
            report.index("| `web-baseline` |"),
        )
        self.assertNotIn("Secret earlier", report)

    def test_ordinary_state_reclassification_holds_with_fixed_code(self):
        report, code = render_incubation_dossier_markdown(
            self.mutate(state=CapabilityState.DISABLED))
        self.assertEqual(code, 2)
        self.assertIn("| `web-baseline` | `catalog` | `incubation_state_changed` |", report)

    def test_sensitive_lab_change_holds_both_catalog_and_posture(self):
        report, code = render_incubation_dossier_markdown(
            self.mutate("wireless-lab", state=CapabilityState.PLANNING))
        self.assertEqual(code, 2)
        self.assertIn("| `wireless-lab` | `catalog` | `incubation_state_changed` |", report)
        self.assertIn(
            "| `wireless-lab` | `posture` | `sensitive_lab_capability_reclassified` |",
            report,
        )

    def test_disabled_activation_holds_both_gates(self):
        report, code = render_incubation_dossier_markdown(
            self.mutate(requires_explicit_activation=False))
        self.assertEqual(code, 2)
        self.assertIn("| `web-baseline` | `catalog` | `explicit_activation_required` |", report)
        self.assertIn("| `web-baseline` | `posture` | `explicit_activation_required` |", report)

    def test_unknown_added_capability_holds(self):
        extra = Capability("new-synthetic-id", "Synthetic", "Temporary",
                           CapabilityState.PLANNING)
        report, code = render_incubation_dossier_markdown(
            snapshot_manifest(self.registry + (extra,)))
        self.assertEqual(code, 2)
        self.assertIn("| `new-synthetic-id` | `catalog` | `unreviewed_capability_added` |", report)
        self.assertNotIn("Temporary", report)

    def test_missing_safety_sensitive_capability_holds(self):
        records = tuple(c for c in self.registry if c.capability_id != "ot-lab")
        report, code = render_incubation_dossier_markdown(snapshot_manifest(records))
        self.assertEqual(code, 2)
        self.assertIn("| `ot-lab` | `catalog` | `required_capability_missing` |", report)
        self.assertIn("| `ot-lab` | `posture` | `required_lab_capability_missing` |", report)

    def test_invalid_empty_input_holds_without_metadata(self):
        report, code = render_incubation_dossier_markdown(b"")
        self.assertEqual(code, 2)
        self.assertIn("**Verdict:** `HOLD`", report)
        self.assertIn("Fingerprint:** unavailable", report)
        self.assertNotIn("sha256:", report)
        self.assert_non_authorizing(report, code)

    def test_invalid_utf8_input_holds_without_details(self):
        report, code = render_incubation_dossier_markdown(b"\xff\x00")
        self.assertEqual(code, 2)
        self.assertNotIn("| `web-baseline` |", report)
        self.assert_non_authorizing(report, code)

    def test_legacy_three_field_manifest_holds_without_digest(self):
        obj = json.loads(self.raw)
        for record in obj["capabilities"]:
            del record["name"]
            del record["description"]
        report, code = render_incubation_dossier_markdown(json.dumps(obj).encode())
        self.assertEqual(code, 2)
        self.assertIn("Fingerprint:** unavailable", report)

    def test_unknown_json_key_holds_without_echo(self):
        obj = json.loads(self.raw)
        obj["PRIVATE_CUSTOMER_DOMAIN"] = "SECRET"
        report, code = render_incubation_dossier_markdown(json.dumps(obj).encode())
        self.assertEqual(code, 2)
        self.assertNotIn("PRIVATE_CUSTOMER_DOMAIN", report)
        self.assertNotIn("SECRET", report)

    def test_untrusted_script_html_never_printed(self):
        report, code = render_incubation_dossier_markdown(
            self.mutate(description="<script>PRIVACY_LEAK</script>"))
        self.assertEqual(code, 2)
        self.assertNotIn("PRIVACY_LEAK", report)
        self.assertNotIn("<script>", report)

    def test_mutant_reported_green_with_error_cannot_be_rendered_green(self):
        bad = review_atomic_incubation_dossier(self.raw)
        forged = replace(bad, catalog_violations=(
            ("web-baseline", "incubation_state_changed"),
        ))
        with patch(_PATCH, return_value=forged):
            report, code = render_incubation_dossier_markdown(self.raw)
        self.assertEqual(code, 2)
        self.assertIn("**Verdict:** `HOLD`", report)
        self.assertNotIn("incubation_state_changed", report)

    def test_untrusted_markdown_identifier_does_not_enter_report(self):
        original = review_atomic_incubation_dossier(
            self.mutate(state=CapabilityState.DISABLED))
        forged = replace(original, catalog_violations=(
            ("bad|<script>PRIVATE", "incubation_state_changed"),
        ))
        with patch(_PATCH, return_value=forged):
            report, code = render_incubation_dossier_markdown(self.raw)
        self.assertEqual(code, 2)
        self.assertNotIn("PRIVATE", report)
        self.assertNotIn("<script>", report)

    def test_forged_fingerprint_html_does_not_enter_report(self):
        good = review_atomic_incubation_dossier(self.raw)
        with patch(_PATCH, return_value=replace(good, fingerprint="javascript:PRIVATE")):
            report, code = render_incubation_dossier_markdown(self.raw)
        self.assertEqual(code, 2)
        self.assertNotIn("javascript:", report)
        self.assertNotIn("PRIVATE", report)

    def test_cli_current_source_nonzero_and_privacy_banner(self):
        process = subprocess.run([sys.executable, str(_SCRIPT)], capture_output=True,
                                 text=True, timeout=15)
        self.assertEqual(process.returncode, 3, process.stderr)
        self.assertIn("**Authority: NONE.**", process.stdout)
        self.assertIn("**Verdict:** `REVIEW_ONLY`", process.stdout)

    def test_cli_denies_all_target_like_arguments_without_success(self):
        for arg in ("--help", "--scan", "https://synthetic.invalid", "../target.json"):
            with self.subTest(arg=arg):
                process = subprocess.run([sys.executable, str(_SCRIPT), arg],
                                         capture_output=True, text=True, timeout=15)
                self.assertEqual(process.returncode, 2, process.stderr)
                self.assertIn("**Authority: NONE.**", process.stdout)
                self.assertIn("**Verdict:** `HOLD`", process.stdout)


if __name__ == "__main__":
    unittest.main()
