"""Offline vulnerability-advisory matching (OSV format).

Finding *known* vulnerabilities is where most real-world risk lives: an
outdated component with a public advisory is usually the cheapest path for an
attacker. This module matches observed components (from lockfiles, SBOMs or
version fingerprints) against an advisory database in the open
`OSV schema <https://ossf.github.io/osv-schema/>`_.

Design rules:

- **Offline and deterministic.** The database is loaded from local files that
  an operator downloads (e.g. OSV per-ecosystem exports). No network access
  happens here, so matching can run in analysis-only mode and in CI.
- **Evidence over vibes.** Every match records the exact advisory id, the
  affected range that matched and the earliest fixed version, so a finding is
  reproducible and the fix is concrete.
- **Exploitation context.** A CISA KEV-format catalog (``vulnerabilities[].cveID``)
  can be loaded to flag advisories with known in-the-wild exploitation; OSV
  ``database_specific.known_exploited: true`` is honoured as well.
- **Honest about limits.** Version comparison is a generic, well-tested
  approximation of PEP 440 / SemVer ordering. ``GIT`` ranges are skipped (they
  need commit graphs), and the match result says so.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .models import Severity

# --------------------------------------------------------------------------
# Version ordering
# --------------------------------------------------------------------------

_PRE_TAGS = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2,
             "c": 3, "rc": 3, "pre": 3, "preview": 3}
_POST_TAGS = {"post", "p", "rev", "r", "patch", "pl"}
_RELEASE_RE = re.compile(r"^(\d+(?:[.]\d+)*)(.*)$")


@dataclass(frozen=True, order=True)
class VersionKey:
    release: tuple[int, ...]
    phase: int  # 0..3 pre-release, 4 final, 5 post-release, 6 unknown suffix
    phase_number: int
    remainder: str


def parse_version(raw: str) -> VersionKey:
    """Parse a version into a comparable key (PEP 440 / SemVer approximation)."""
    text = raw.strip().lower()
    if text.startswith("v") and text[1:2].isdigit():
        text = text[1:]
    text = text.split("+", 1)[0]  # build metadata never affects ordering
    match = _RELEASE_RE.match(text)
    if not match:
        raise ValueError(f"unparseable version: {raw!r}")
    release = [int(part) for part in match.group(1).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    suffix = match.group(2).lstrip(".-_")
    if not suffix:
        return VersionKey(tuple(release), 4, 0, "")
    tag_match = re.match(r"^([a-z]+)[.\-_]?(\d*)(.*)$", suffix)
    if tag_match:
        tag, number, rest = tag_match.groups()
        num = int(number) if number else 0
        if tag in _PRE_TAGS:
            return VersionKey(tuple(release), _PRE_TAGS[tag], num, rest)
        if tag in _POST_TAGS:
            return VersionKey(tuple(release), 5, num, rest)
    if suffix.isdigit():  # "1.0-1" style revisions sort after the release
        return VersionKey(tuple(release), 5, int(suffix), "")
    return VersionKey(tuple(release), 6, 0, suffix)


def compare_versions(left: str, right: str) -> int:
    a, b = parse_version(left), parse_version(right)
    return (a > b) - (a < b)


# --------------------------------------------------------------------------
# CVSS v3.x base score (so severity is computed, not guessed)
# --------------------------------------------------------------------------

_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS3_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
             "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(value: float) -> float:
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float:
    """Compute a CVSS v3.0/v3.1 base score from its vector string."""
    parts = vector.strip().split("/")
    if not parts or not parts[0].upper().startswith("CVSS:3"):
        raise ValueError(f"not a CVSS v3 vector: {vector!r}")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError(f"malformed CVSS component {part!r}")
        key, value = part.split(":", 1)
        metrics[key.upper()] = value.upper()
    try:
        scope = metrics["S"]
        av = _CVSS3_WEIGHTS["AV"][metrics["AV"]]
        ac = _CVSS3_WEIGHTS["AC"][metrics["AC"]]
        ui = _CVSS3_WEIGHTS["UI"][metrics["UI"]]
        pr = _CVSS3_PR[scope][metrics["PR"]]
        c = _CVSS3_WEIGHTS["C"][metrics["C"]]
        i = _CVSS3_WEIGHTS["I"][metrics["I"]]
        a = _CVSS3_WEIGHTS["A"][metrics["A"]]
    except KeyError as exc:
        raise ValueError(f"incomplete CVSS v3 vector {vector!r}: {exc}") from None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def severity_for_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


_TEXT_SEVERITY = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "moderate": Severity.MEDIUM, "medium": Severity.MEDIUM,
    "low": Severity.LOW, "info": Severity.INFO, "none": Severity.INFO,
}

# --------------------------------------------------------------------------
# Advisories
# --------------------------------------------------------------------------

_PYPI_NORMALIZE = re.compile(r"[-_.]+")


def normalize_package(ecosystem: str, name: str) -> tuple[str, str]:
    eco = ecosystem.strip()
    if eco.lower() == "pypi":
        return "PyPI", _PYPI_NORMALIZE.sub("-", name.strip()).lower()
    if eco.lower() == "npm":
        return "npm", name.strip().lower()
    return eco, name.strip().lower()


@dataclass(frozen=True)
class Component:
    """A concrete, versioned software component that was observed."""

    ecosystem: str
    name: str
    version: str
    source: str = ""  # where it was observed (lockfile path, header, SBOM)

    @property
    def key(self) -> tuple[str, str]:
        return normalize_package(self.ecosystem, self.name)


@dataclass(frozen=True)
class AffectedRange:
    range_type: str
    events: tuple[tuple[str, str], ...]  # (kind, version) in declared order


@dataclass(frozen=True)
class AffectedPackage:
    ecosystem: str
    name: str
    ranges: tuple[AffectedRange, ...] = ()
    versions: tuple[str, ...] = ()


@dataclass(frozen=True)
class Advisory:
    advisory_id: str
    summary: str
    aliases: tuple[str, ...]
    affected: tuple[AffectedPackage, ...]
    cvss_vector: str | None = None
    declared_severity: str | None = None
    known_exploited: bool = False
    references: tuple[str, ...] = ()

    @property
    def cve_ids(self) -> tuple[str, ...]:
        ids = (self.advisory_id,) + self.aliases
        return tuple(i for i in ids if i.upper().startswith("CVE-"))

    def score(self) -> float | None:
        if self.cvss_vector:
            try:
                return cvss3_base_score(self.cvss_vector)
            except ValueError:
                return None
        return None

    def severity(self) -> Severity:
        score = self.score()
        if score is not None:
            return severity_for_score(score)
        if self.declared_severity:
            return _TEXT_SEVERITY.get(self.declared_severity.lower(), Severity.MEDIUM)
        return Severity.MEDIUM  # unknown severity is never silently "info"

    @staticmethod
    def from_osv(data: dict[str, Any]) -> "Advisory":
        if not isinstance(data, dict) or not data.get("id"):
            raise ValueError("OSV record requires an 'id'")
        affected: list[AffectedPackage] = []
        for entry in data.get("affected", []) or []:
            package = entry.get("package") or {}
            if not package.get("ecosystem") or not package.get("name"):
                continue
            ranges = tuple(
                AffectedRange(
                    str(r.get("type", "")).upper(),
                    tuple((kind, str(value))
                          for event in r.get("events", []) or []
                          for kind, value in event.items()),
                )
                for r in entry.get("ranges", []) or []
            )
            affected.append(AffectedPackage(
                package["ecosystem"], package["name"], ranges,
                tuple(str(v) for v in entry.get("versions", []) or []),
            ))
        vector = None
        for item in data.get("severity", []) or []:
            if str(item.get("type", "")).upper().startswith("CVSS_V3"):
                vector = str(item.get("score"))
                break
        db_specific = data.get("database_specific") or {}
        return Advisory(
            advisory_id=str(data["id"]),
            summary=str(data.get("summary") or data.get("details") or "")[:300],
            aliases=tuple(str(a) for a in data.get("aliases", []) or []),
            affected=tuple(affected),
            cvss_vector=vector,
            declared_severity=db_specific.get("severity"),
            known_exploited=bool(db_specific.get("known_exploited", False)),
            references=tuple(str(r.get("url")) for r in data.get("references", []) or []
                             if isinstance(r, dict) and r.get("url")),
        )


def _range_contains(affected_range: AffectedRange, version: str) -> bool:
    """OSV range evaluation for SEMVER / ECOSYSTEM ranges."""
    target = parse_version(version)
    affected = False
    events = []
    for kind, value in affected_range.events:
        if kind == "introduced":
            events.append((None if value == "0" else parse_version(value), 0, kind))
        elif kind in {"fixed", "last_affected"}:
            events.append((parse_version(value), 1, kind))
        # 'limit' events only bound GIT walks; ignored for version ranges
    # Sort by version; "introduced: 0" first.
    events.sort(key=lambda e: (e[0] is not None, e[0] or VersionKey((), 0, 0, ""), e[1]))
    for key, _order, kind in events:
        if kind == "introduced":
            if key is None or target >= key:
                affected = True
        elif kind == "fixed":
            if target >= key:
                affected = False
        elif kind == "last_affected":
            if target > key:
                affected = False
    return affected


@dataclass(frozen=True)
class AdvisoryMatch:
    component: Component
    advisory: Advisory
    fixed_versions: tuple[str, ...]
    match_basis: str  # "range:SEMVER", "range:ECOSYSTEM" or "explicit-version"

    @property
    def recommended_version(self) -> str | None:
        """Lowest fixed version above the observed one, if the advisory has one."""
        above = [v for v in self.fixed_versions
                 if _safe_compare(v, self.component.version) > 0]
        if not above:
            return None
        return min(above, key=parse_version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": {"ecosystem": self.component.ecosystem,
                          "name": self.component.name,
                          "version": self.component.version,
                          "source": self.component.source},
            "advisory_id": self.advisory.advisory_id,
            "aliases": list(self.advisory.aliases),
            "summary": self.advisory.summary,
            "severity": self.advisory.severity().value,
            "cvss_score": self.advisory.score(),
            "known_exploited": self.advisory.known_exploited,
            "fixed_versions": list(self.fixed_versions),
            "recommended_version": self.recommended_version,
            "match_basis": self.match_basis,
        }


def _safe_compare(left: str, right: str) -> int:
    try:
        return compare_versions(left, right)
    except ValueError:
        return 0


@dataclass
class AdvisoryDatabase:
    advisories: list[Advisory] = field(default_factory=list)
    skipped_records: int = 0
    _index: dict[tuple[str, str], list[tuple[Advisory, AffectedPackage]]] = field(
        default_factory=dict, repr=False)

    def add(self, advisory: Advisory) -> None:
        self.advisories.append(advisory)
        for package in advisory.affected:
            key = normalize_package(package.ecosystem, package.name)
            self._index.setdefault(key, []).append((advisory, package))

    def __len__(self) -> int:
        return len(self.advisories)

    @classmethod
    def from_records(cls, records: Iterable[dict[str, Any]]) -> "AdvisoryDatabase":
        database = cls()
        for record in records:
            try:
                database.add(Advisory.from_osv(record))
            except (ValueError, TypeError, AttributeError):
                database.skipped_records += 1
        return database

    @classmethod
    def load(cls, *paths: str | Path, kev_path: str | Path | None = None) -> "AdvisoryDatabase":
        """Load OSV JSON files (single record, list, or ``{"vulns": [...]}``) or directories."""
        records: list[dict[str, Any]] = []
        for path in paths:
            path = Path(path)
            files = sorted(path.rglob("*.json")) if path.is_dir() else [path]
            for file in files:
                data = json.loads(file.read_text(encoding="utf-8"))
                if isinstance(data, dict) and isinstance(data.get("vulns"), list):
                    records.extend(data["vulns"])
                elif isinstance(data, list):
                    records.extend(data)
                else:
                    records.append(data)
        database = cls.from_records(records)
        if kev_path is not None:
            database.apply_kev(json.loads(Path(kev_path).read_text(encoding="utf-8")))
        return database

    def apply_kev(self, catalog: dict[str, Any]) -> int:
        """Flag advisories whose CVE ids appear in a CISA KEV-format catalog."""
        exploited = {str(v.get("cveID", "")).upper()
                     for v in catalog.get("vulnerabilities", []) or []}
        flagged = 0
        updated: list[Advisory] = []
        for advisory in self.advisories:
            if not advisory.known_exploited and any(c.upper() in exploited
                                                    for c in advisory.cve_ids):
                advisory = Advisory(**{**advisory.__dict__, "known_exploited": True})
                flagged += 1
            updated.append(advisory)
        self.advisories = []
        self._index = {}
        for advisory in updated:
            self.add(advisory)
        return flagged

    def match(self, component: Component) -> list[AdvisoryMatch]:
        matches: list[AdvisoryMatch] = []
        try:
            parse_version(component.version)
        except ValueError:
            return matches
        seen: set[str] = set()
        for advisory, package in self._index.get(component.key, []):
            if advisory.advisory_id in seen:
                continue
            basis = None
            if component.version in package.versions:
                basis = "explicit-version"
            else:
                for affected_range in package.ranges:
                    if affected_range.range_type not in {"SEMVER", "ECOSYSTEM"}:
                        continue
                    try:
                        if _range_contains(affected_range, component.version):
                            basis = f"range:{affected_range.range_type}"
                            break
                    except ValueError:
                        continue
            if basis is None:
                continue
            seen.add(advisory.advisory_id)
            fixed = tuple(sorted(
                {value for r in package.ranges for kind, value in r.events
                 if kind == "fixed"},
                key=lambda v: (_try_key(v) is None, _try_key(v) or VersionKey((), 0, 0, "")),
            ))
            matches.append(AdvisoryMatch(component, advisory, fixed, basis))
        return matches

    def match_all(self, components: Iterable[Component]) -> list[AdvisoryMatch]:
        results: list[AdvisoryMatch] = []
        for component in components:
            results.extend(self.match(component))
        return results


def _try_key(version: str) -> VersionKey | None:
    try:
        return parse_version(version)
    except ValueError:
        return None
