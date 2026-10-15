from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.advisories import AdvisoryDatabase
from lightup.ai.orchestration import RunContext, ToolRegistry
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.supply_chain import (
    ManifestError,
    diff_dependency_risk,
    parse_manifest,
    parse_package_lock,
    parse_requirements,
    register,
    scan_manifests,
    TOOL_ID,
)


def _osv(advisory_id, ecosystem, name, introduced, fixed, kev=False):
    return {
        "id": advisory_id,
        "aliases": [],
        "summary": "x",
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"known_exploited": kev},
        "affected": [{"package": {"ecosystem": ecosystem, "name": name},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": introduced}, {"fixed": fixed}]}]}],
    }


class RequirementsParserTest(unittest.TestCase):
    def test_only_pinned_are_components(self):
        manifest = parse_requirements(
            "flask==2.0.1\nrequests>=2.0\n# comment\ndjango==4.2  # inline\n-e .\n")
        pinned = {(c.name, c.version) for c in manifest.components}
        self.assertEqual(pinned, {("flask", "2.0.1"), ("django", "4.2")})
        self.assertIn("requests", manifest.unpinned)

    def test_extras_and_markers_stripped(self):
        manifest = parse_requirements("celery[redis]==5.3.0; python_version>='3.8'\n")
        self.assertEqual([(c.name, c.version) for c in manifest.components],
                         [("celery", "5.3.0")])


class PackageLockParserTest(unittest.TestCase):
    def test_v2_packages_map(self):
        data = {"lockfileVersion": 2, "packages": {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/left-pad": {"version": "1.1.0"},
            "node_modules/x": {"link": True, "version": "0"}}}
        manifest = parse_package_lock(json.dumps(data))
        names = {(c.name, c.version) for c in manifest.components}
        self.assertIn(("left-pad", "1.1.0"), names)
        self.assertNotIn(("x", "0"), names)

    def test_v1_nested_dependencies(self):
        data = {"lockfileVersion": 1, "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}
        manifest = parse_package_lock(json.dumps(data))
        self.assertEqual({(c.name, c.version) for c in manifest.components},
                         {("a", "1.0.0"), ("b", "2.0.0")})


class ManifestDispatchTest(unittest.TestCase):
    def test_unsupported_type_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest("notes.md", "hello")

    def test_cyclonedx_detected(self):
        sbom = {"bomFormat": "CycloneDX", "components": [
            {"name": "demo", "purl": "pkg:pypi/demo@1.0.0"}]}
        manifest = parse_manifest("bom.json", json.dumps(sbom))
        self.assertEqual([(c.ecosystem, c.name, c.version) for c in manifest.components],
                         [("PyPI", "demo", "1.0.0")])


class ScanAndDiffTest(unittest.TestCase):
    def setUp(self):
        self.db = AdvisoryDatabase.from_records([
            _osv("V-1", "PyPI", "demo-lib", "0", "2.0.1", kev=True),
            _osv("V-2", "PyPI", "other", "0", "3.0.0"),
        ])

    def test_scan_reports_matches(self):
        report = scan_manifests({"requirements.txt": "demo-lib==1.0\nsafe==9.9\n"}, self.db)
        self.assertEqual(report.component_count, 2)
        self.assertEqual(len(report.matches), 1)
        self.assertEqual(report.to_dict()["vulnerable_components"], 1)

    def test_diff_block_on_introduced_kev(self):
        before = {"requirements.txt": "safe==1.0\n"}
        after = {"requirements.txt": "safe==1.0\ndemo-lib==1.0\n"}
        delta = diff_dependency_risk(before, after, self.db)
        self.assertEqual(delta.verdict, "block")
        self.assertEqual(len(delta.introduced), 1)

    def test_diff_pass_when_resolved(self):
        before = {"requirements.txt": "demo-lib==1.0\n"}
        after = {"requirements.txt": "demo-lib==2.0.1\n"}
        delta = diff_dependency_risk(before, after, self.db)
        self.assertEqual(delta.verdict, "pass")
        self.assertEqual(len(delta.resolved), 1)
        self.assertEqual(len(delta.introduced), 0)


class SupplyChainToolTest(unittest.TestCase):
    def test_analysis_tool_runs_in_passive_discovery_mode(self):
        db = AdvisoryDatabase.from_records([_osv("V-1", "PyPI", "demo-lib", "0", "2.0.1")])
        registry = ToolRegistry()
        register(registry, db)
        definition, handler = registry.get(TOOL_ID)
        context = RunContext(
            run_id="r", client_id="c", engagement_id="e",
            mode=AssessmentMode.PASSIVE_DISCOVERY, approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None, is_lab=False,
            created_at=__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc))
        output = handler(context, {"filename": "requirements.txt", "content": "demo-lib==1.0\n"})
        self.assertIn("vulnerable-dependency:V-1", dict(output.metadata)["issues"])


if __name__ == "__main__":
    unittest.main()
