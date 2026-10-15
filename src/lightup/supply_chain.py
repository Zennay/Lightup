"""Software supply-chain analysis: lockfiles -> components -> known advisories.

This is an **analysis-only** capability: it never touches a target. It parses
dependency manifests the client supplied (or that a pull request changes) and
matches every pinned component against an :class:`AdvisoryDatabase`. That
makes it useful in both product lanes:

- **Current Security** — what vulnerable components ship today;
- **Future Security** — :func:`diff_dependency_risk` says whether a proposed
  change *introduces* or *removes* known-vulnerable components, which is
  exactly the pre-merge verdict the Security Twin promises.

Supported formats: ``requirements*.txt``, ``Pipfile.lock``, ``poetry.lock``,
``package-lock.json`` (v1, v2, v3) and CycloneDX JSON SBOMs. Unpinned
requirements are reported as a coverage gap, never silently dropped.

The tool handler takes manifest *content* as an argument, not a file path, so
a model-proposed plan can never make LightUp read arbitrary local files.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .advisories import AdvisoryDatabase, AdvisoryMatch, Component
from .ai.orchestration import (
    ParamKind,
    RunContext,
    ToolDefinition,
    ToolOutput,
    ToolParameter,
    ToolRegistry,
)
from .engagements import RiskLevel
from .execution_policy import InteractionKind

TOOL_ID = "supply-chain-advisory-scan"
CAPABILITY_ID = "supply-chain"
MAX_MANIFEST_BYTES = 5 * 1024 * 1024


class ManifestError(ValueError):
    """A manifest could not be parsed."""


@dataclass
class ParsedManifest:
    filename: str
    ecosystem: str
    components: list[Component] = field(default_factory=list)
    unpinned: list[str] = field(default_factory=list)


_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(===?|~=|>=|<=|!=|<|>)?\s*([^\s;#,]*)")


def parse_requirements(text: str, filename: str = "requirements.txt") -> ParsedManifest:
    manifest = ParsedManifest(filename, "PyPI")
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://")):
            continue
        match = _REQ_LINE.match(line)
        if not match:
            continue
        name, _extras, operator, version = match.groups()
        if operator in {"==", "==="} and version and "*" not in version:
            manifest.components.append(Component("PyPI", name, version, filename))
        else:
            manifest.unpinned.append(name)
    return manifest


def parse_pipfile_lock(text: str, filename: str = "Pipfile.lock") -> ParsedManifest:
    data = _load_json(text, filename)
    manifest = ParsedManifest(filename, "PyPI")
    for section in ("default", "develop"):
        for name, spec in (data.get(section) or {}).items():
            version = str((spec or {}).get("version", "")).lstrip("=")
            if version:
                manifest.components.append(Component("PyPI", name, version, filename))
            else:
                manifest.unpinned.append(name)
    return manifest


def parse_poetry_lock(text: str, filename: str = "poetry.lock") -> ParsedManifest:
    """Minimal TOML-free parse of ``[[package]]`` name/version pairs."""
    manifest = ParsedManifest(filename, "PyPI")
    name = version = None
    for raw in text.splitlines() + ["[[package]]"]:
        line = raw.strip()
        if line == "[[package]]" or (line.startswith("[") and not line.startswith("[[")):
            if name and version:
                manifest.components.append(Component("PyPI", name, version, filename))
            name = version = None
            if line != "[[package]]":
                name = version = None
            continue
        match = re.match(r'^(name|version)\s*=\s*"([^"]+)"', line)
        if match:
            if match.group(1) == "name" and name is None:
                name = match.group(2)
            elif match.group(1) == "version" and version is None:
                version = match.group(2)
    return manifest


def parse_package_lock(text: str, filename: str = "package-lock.json") -> ParsedManifest:
    data = _load_json(text, filename)
    manifest = ParsedManifest(filename, "npm")
    seen: set[tuple[str, str]] = set()

    def add(name: str, version: str | None) -> None:
        if not name:
            return
        if not version or version.startswith(("file:", "link:", "git", "http")):
            manifest.unpinned.append(name)
            return
        if (name, version) not in seen:
            seen.add((name, version))
            manifest.components.append(Component("npm", name, version, filename))

    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        for path, spec in packages.items():
            if not path or not isinstance(spec, dict) or spec.get("link"):
                continue
            name = spec.get("name") or path.rsplit("node_modules/", 1)[-1]
            add(name, spec.get("version"))
        return manifest

    def walk(dependencies: dict[str, Any]) -> None:  # lockfileVersion 1
        for name, spec in (dependencies or {}).items():
            if isinstance(spec, dict):
                add(name, spec.get("version"))
                walk(spec.get("dependencies") or {})

    walk(data.get("dependencies") or {})
    return manifest


_PURL = re.compile(r"^pkg:([a-z]+)/(.+)@([^?#]+)")
_PURL_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go",
                    "cargo": "crates.io", "gem": "RubyGems", "nuget": "NuGet",
                    "composer": "Packagist"}


def parse_cyclonedx(text: str, filename: str = "bom.json") -> ParsedManifest:
    data = _load_json(text, filename)
    if data.get("bomFormat") != "CycloneDX":
        raise ManifestError(f"{filename}: not a CycloneDX JSON SBOM")
    manifest = ParsedManifest(filename, "mixed")
    for component in data.get("components", []) or []:
        purl = str(component.get("purl", ""))
        match = _PURL.match(purl)
        if not match:
            if component.get("name"):
                manifest.unpinned.append(str(component["name"]))
            continue
        kind, path, version = match.groups()
        ecosystem = _PURL_ECOSYSTEMS.get(kind)
        if ecosystem is None:
            manifest.unpinned.append(path)
            continue
        from urllib.parse import unquote
        name = unquote(path)
        if ecosystem == "Maven":
            name = name.replace("/", ":", 1)
        manifest.components.append(Component(ecosystem, name, unquote(version), filename))
    return manifest


def _load_json(text: str, filename: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{filename}: invalid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{filename}: expected a JSON object")
    return data


_PARSERS: tuple[tuple[Callable[[str], bool], Callable[[str, str], ParsedManifest]], ...] = (
    (lambda n: n.endswith("package-lock.json") or n.endswith("npm-shrinkwrap.json"),
     parse_package_lock),
    (lambda n: n.endswith("pipfile.lock"), parse_pipfile_lock),
    (lambda n: n.endswith("poetry.lock"), parse_poetry_lock),
    (lambda n: n.endswith(".cdx.json") or n.endswith("bom.json") or "cyclonedx" in n,
     parse_cyclonedx),
    (lambda n: n.endswith(".txt") and "requirement" in n, parse_requirements),
)


def parse_manifest(filename: str, text: str) -> ParsedManifest:
    if len(text.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise ManifestError(f"{filename}: manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    lowered = filename.lower().rsplit("/", 1)[-1]
    for predicate, parser in _PARSERS:
        if predicate(lowered):
            return parser(text, filename)
    raise ManifestError(f"{filename}: unsupported manifest type")


@dataclass
class SupplyChainReport:
    manifests: list[ParsedManifest]
    matches: list[AdvisoryMatch]

    @property
    def component_count(self) -> int:
        return sum(len(m.components) for m in self.manifests)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifests": [{"filename": m.filename, "ecosystem": m.ecosystem,
                           "components": len(m.components),
                           "unpinned": sorted(set(m.unpinned))}
                          for m in self.manifests],
            "components_scanned": self.component_count,
            "vulnerable_components": len({(m.component.key, m.component.version)
                                          for m in self.matches}),
            "matches": [m.to_dict() for m in self.matches],
        }


def scan_manifests(files: dict[str, str], database: AdvisoryDatabase) -> SupplyChainReport:
    manifests = [parse_manifest(name, text) for name, text in sorted(files.items())]
    matches: list[AdvisoryMatch] = []
    for manifest in manifests:
        matches.extend(database.match_all(manifest.components))
    return SupplyChainReport(manifests, matches)


@dataclass(frozen=True)
class DependencyRiskDelta:
    """Pre-merge verdict input: which known vulnerabilities a change adds or removes."""

    introduced: tuple[AdvisoryMatch, ...]
    resolved: tuple[AdvisoryMatch, ...]
    unchanged: tuple[AdvisoryMatch, ...]

    @property
    def verdict(self) -> str:
        if any(m.advisory.known_exploited for m in self.introduced):
            return "block"
        if any(m.advisory.severity().value in {"critical", "high"} for m in self.introduced):
            return "block"
        if self.introduced:
            return "warn"
        return "pass"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "introduced": [m.to_dict() for m in self.introduced],
            "resolved": [m.to_dict() for m in self.resolved],
            "unchanged_count": len(self.unchanged),
        }


def _match_key(match: AdvisoryMatch) -> tuple[str, str, str]:
    return (match.component.key[0], match.component.key[1], match.advisory.advisory_id)


def diff_dependency_risk(before: dict[str, str], after: dict[str, str],
                         database: AdvisoryDatabase) -> DependencyRiskDelta:
    """Compare known-vulnerability exposure before and after a proposed change."""
    old = {_match_key(m): m for m in scan_manifests(before, database).matches}
    new = {_match_key(m): m for m in scan_manifests(after, database).matches}
    return DependencyRiskDelta(
        introduced=tuple(new[k] for k in sorted(set(new) - set(old))),
        resolved=tuple(old[k] for k in sorted(set(old) - set(new))),
        unchanged=tuple(new[k] for k in sorted(set(new) & set(old))),
    )


# --------------------------------------------------------------------------
# Orchestration tool (analysis-only; never touches a target)
# --------------------------------------------------------------------------

SUPPLY_CHAIN_TOOL = ToolDefinition(
    tool_id=TOOL_ID,
    capability_id=CAPABILITY_ID,
    interaction=InteractionKind.ANALYSIS,
    min_risk=RiskLevel.ANALYSIS_ONLY,
    description="Offline: match pinned components in a supplied dependency "
                "manifest against the loaded advisory database. No network.",
    parameters=(
        ToolParameter("filename", ParamKind.STRING, required=True,
                      description="Manifest file name (selects the parser)"),
        ToolParameter("content", ParamKind.STRING, required=True,
                      description="Manifest content as text"),
    ),
)


def make_handler(database: AdvisoryDatabase):
    def run_supply_chain_scan(context: RunContext, arguments: dict[str, Any]) -> ToolOutput:
        del context  # analysis-only: valid in every run mode
        report = scan_manifests({str(arguments["filename"]): str(arguments["content"])},
                                database)
        check_ids = sorted({f"vulnerable-dependency:{m.advisory.advisory_id}"
                            for m in report.matches})
        return ToolOutput(
            summary=(f"supply-chain scan of {arguments['filename']}: "
                     f"{report.component_count} components, "
                     f"{len(report.matches)} advisory matches"),
            evidence_kind="supply-chain-advisory-matches",
            evidence_payload=json.dumps(report.to_dict(), sort_keys=True).encode("utf-8"),
            metadata=(("issues", ",".join(check_ids)),
                      ("components", str(report.component_count))),
        )
    return run_supply_chain_scan


def register(registry: ToolRegistry, database: AdvisoryDatabase) -> None:
    registry.register(SUPPLY_CHAIN_TOOL, make_handler(database))
