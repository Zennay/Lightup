#!/usr/bin/env python3
"""Private offline LightUp Lab Design Catalog v1 -> native LabScenario conversion.

This script NEVER starts a LabEvaluationHarness, resolves DNS, calls tools, scans,
connects to a target, creates a grant, or obtains runtime authorization.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys

SCHEMA = "lightup.lab_design_catalog.v1"
FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
LEVELS = {"critical", "high", "medium", "low", "info"}
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", re.ASCII)
MAX_CATALOG_BYTES = 262144
LAB_V4 = tuple(ipaddress.ip_network(x) for x in
    ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
LAB_V6 = tuple(ipaddress.ip_network(x) for x in
    ("::1/128", "fc00::/7", "fe80::/10"))


class Hold(ValueError):
    """No original targets or source details in errors."""


def ensure(ok: bool) -> None:
    if not ok:
        raise Hold("Non-canonical, ambiguous or non-private lab input")


def exact(value: object, keys: set[str]) -> bool:
    return type(value) is dict and set(value) == keys


def label(value: object, minimum: int, maximum: int) -> bool:
    return (type(value) is str and minimum <= len(value) <= maximum and
            value == value.strip() and all(32 <= ord(c) <= 126 for c in value))


def pairs_hook(items: list[tuple[str, object]]) -> dict:
    out = {}
    for key, value in items:
        ensure(key not in out)
        out[key] = value
    return out


def private_ip(value: object) -> str:
    ensure(type(value) is str and 1 <= len(value) <= 45 and
           value == value.strip() and
           all(c not in value for c in ("%", "/", " ", "\t", "\r", "\n")))
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise Hold("Non-canonical, ambiguous or non-private lab input") from exc
    # Enforce deterministic numeric-only surface, not CIDRs, ports, DNS, URLs,
    # IPv4-mapped IPv6, documentation/test ranges, interfaces or hostnames.
    ensure(address.version == 4 and str(address) == value or
           address.version == 6 and ":" in value and "." not in value)
    networks = LAB_V4 if address.version == 4 else LAB_V6
    ensure(any(address in net for net in networks))
    return str(address)


def read_stable_catalog_bytes(path: Path) -> bytes:
    """Read one bounded regular catalog without following a final symlink or accepting drift."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        ensure(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_CATALOG_BYTES)
        raw = bytearray()
        while True:
            chunk = os.read(fd, min(65536, MAX_CATALOG_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            ensure(len(raw) <= MAX_CATALOG_BYTES)
        after = os.fstat(fd)
        ensure((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns))
        ensure(len(raw) == before.st_size)
        return bytes(raw)
    finally:
        os.close(fd)


def read_catalog(path: Path) -> list[dict]:
    try:
        raw = read_stable_catalog_bytes(path)
        obj = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs_hook,
                         parse_constant=lambda _: (_ for _ in ()).throw(Hold("Invalid JSON")))
        ensure(exact(obj, {"schema", "status", "scenarios", *FLAGS}))
        ensure(obj["schema"] == SCHEMA and obj["status"] == "DRAFT_ONLY")
        ensure(all(obj[key] is False for key in FLAGS))
        scenarios = obj["scenarios"]
        ensure(type(scenarios) is list and 1 <= len(scenarios) <= 32)
        result: list[dict] = []
        seen: set[str] = set()
        for scenario in scenarios:
            ensure(exact(scenario, {"scenario_id", "name", "description", "targets", "expected_findings"}))
            scenario_id = scenario["scenario_id"]
            ensure(type(scenario_id) is str and TOKEN.fullmatch(scenario_id) is not None)
            ensure(scenario_id not in seen)
            seen.add(scenario_id)
            ensure(label(scenario["name"], 1, 160) and label(scenario["description"], 0, 500))
            targets = scenario["targets"]
            ensure(type(targets) is list and 1 <= len(targets) <= 16)
            targets = tuple(private_ip(t) for t in targets)
            ensure(len(targets) == len(set(targets)))
            findings = scenario["expected_findings"]
            ensure(findings is None or type(findings) is list and len(findings) <= 64)
            found: set[str] = set()
            if findings is not None:
                clean_findings = []
                for item in findings:
                    ensure(exact(item, {"identifier", "title", "capability_id", "severity"}))
                    ident = item["identifier"]
                    ensure(type(ident) is str and TOKEN.fullmatch(ident) is not None)
                    ensure(ident not in found)
                    found.add(ident)
                    cap = item["capability_id"]
                    ensure(type(cap) is str and TOKEN.fullmatch(cap) is not None)
                    ensure(label(item["title"], 1, 160) and item["severity"] in LEVELS and
                           type(item["severity"]) is str)
                    clean_findings.append(item)
                findings = clean_findings
            result.append({"scenario_id": scenario_id, "name": scenario["name"],
                "description": scenario["description"], "targets": targets,
                "expected_findings": findings})
        return result
    except (UnicodeError, OSError, TypeError, json.JSONDecodeError, RecursionError,
            OverflowError, MemoryError) as exc:
        raise Hold("Non-canonical, ambiguous or non-private lab input") from exc


def build_native_catalog(rows: list[dict]) -> tuple:
    # Import only the existing original offline dataclasses. No runner imported.
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root / "src"))
    from lightup.labeval import ExpectedFinding, LabScenario

    output = []
    try:
        for row in rows:
            findings = row["expected_findings"]
            native = None if findings is None else tuple(
                ExpectedFinding(**finding) for finding in findings)
            # Original ScopePolicy.normalize_host expects bracketed IPv6 URL-host
            # literals. Input remains strict bare numeric IP, never a URL or DNS.
            endpoints = tuple(f"[{t}]" if ":" in t else t for t in row["targets"])
            output.append(LabScenario(scenario_id=row["scenario_id"], name=row["name"],
                description=row["description"], targets=endpoints,
                expected_findings=native))
        return tuple(output)
    except (ValueError, TypeError, PermissionError, AttributeError) as exc:
        raise Hold("Original LabScenario admission rejected a proposed private catalog") from exc


def preview(rows: list[dict], native: tuple) -> None:
    by_severity = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for row in rows:
        for finding in row["expected_findings"] or ():
            by_severity[finding["severity"]] += 1
    print("DRAFT_ONLY / PLAN-LAB ONLY / REVIEW_ONLY; no authority, consent, dispatch or release")
    print("Native LabScenario objects constructed in memory:", len(native))
    print("Lab targets (unlisted):", sum(len(s.targets) for s in native))
    print("Explicitly scored:", sum(s.expected_findings is not None for s in native))
    print("Unscored:", sum(s.expected_findings is None for s in native))
    print("Expected findings by severity:", ", ".join(f"{s}={n}" for s, n in by_severity.items()))
    print("No original names, IPs, identifiers, descriptions or notes printed.")


def render_private_python(rows: list[dict]) -> str:
    # Opt-in private code-generation. The output only constructs dataclasses
    # within load_lab_scenarios() when a human *calls it*; never starts a run.
    lines = [
        '"""PRIVATE lab-only authoring handoff; no grants or active execution."""',
        "from lightup.labeval import LabScenario, ExpectedFinding", "",
        "DRAFT_ONLY = True",
        "AUTHORIZED = CONSENT_VERIFIED = DISPATCH_ALLOWED = RELEASE_ALLOWED = False", "",
        "def load_lab_scenarios():",
        '    """Construct original dataclasses only; does not run lab assessments."""',
        "    return ("]
    for row in rows:
        findings = row["expected_findings"]
        serialized = "None" if findings is None else "(" + ", ".join(
            "ExpectedFinding(identifier={0!r}, title={1!r}, capability_id={2!r}, severity={3!r})".format(
                f["identifier"], f["title"], f["capability_id"], f["severity"]) for f in findings
        ) + ("," if len(findings) == 1 else "") + ")"
        lines += ["        LabScenario(",
                  f"            scenario_id={row['scenario_id']!r},",
                  f"            name={row['name']!r},",
                  f"            description={row['description']!r},",
                  f"            targets={tuple(f'[{t}]' if ':' in t else t for t in row['targets'])!r},",
                  f"            expected_findings={serialized},",
                  "        ),"]
    lines += ["    )", ""]
    return "\n".join(lines)


def compare_private_catalogs(before: list[dict], after: list[dict]) -> dict:
    """Unsigned human source-delta summary, never a remediation verdict."""
    old = {r["scenario_id"]: r for r in before}
    new = {r["scenario_id"]: r for r in after}
    common = set(old) & set(new)
    changed = {k for k in common if old[k] != new[k]}
    return {
        "schema": "lightup.lab_design_revision_review.v1",
        "status": "REVIEW_ONLY",
        "authorized": False, "consent_verified": False,
        "dispatch_allowed": False, "release_allowed": False,
        "source_authenticated": False,
        "disclaimer": "Unsigned lab design comparison. ABSENT never means remediated.",
        "baseline_scenarios": len(old), "candidate_scenarios": len(new),
        "added": len(set(new) - set(old)),
        "absent_not_remediated": len(set(old) - set(new)),
        "changed": len(changed), "unchanged": len(common) - len(changed),
        "changed_target_sets": sum(old[k]["targets"] != new[k]["targets"] for k in changed),
        "changed_ground_truth_sets": sum(
            old[k]["expected_findings"] != new[k]["expected_findings"] for k in changed),
    }


def private_create(path: Path, data: bytes) -> None:
    ensure(not path.is_symlink())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="PRIVATE offline LabScenario catalog review only; never executes a lab")
    parser.add_argument("catalog", type=Path, help="original PRIVATE LightUp Lab Design Catalog JSON")
    parser.add_argument("--emit-python", type=Path,
        help="create NEW private Python dataclass-constructor module (no execution)")
    parser.add_argument("--compare", type=Path,
        help="second independently accepted private catalog for aggregate review")
    parser.add_argument("--comparison-out", type=Path,
        help="new owner-only aggregate-only JSON report (requires --compare)")
    args = parser.parse_args()
    try:
        rows = read_catalog(args.catalog)
        native = build_native_catalog(rows)
        preview(rows, native)
        ensure(not args.comparison_out or args.compare)
        comparison = None
        if args.compare:
            other = read_catalog(args.compare)
            build_native_catalog(other)
            comparison = compare_private_catalogs(rows, other)
            print("Offline lab source revision only; ABSENT never implies fixed:")
            for key in ("baseline_scenarios", "candidate_scenarios", "added",
                        "absent_not_remediated", "changed", "unchanged",
                        "changed_target_sets", "changed_ground_truth_sets"):
                print(f"  {key}: {comparison[key]}")
        if args.emit_python:
            dest = args.emit_python
            ensure(dest.suffix == ".py" and not dest.is_symlink())
            data = render_private_python(rows).encode("utf-8")
            # exclusive-create with owner-only permissions; no overwrites.
            private_create(dest, data)
            print("PRIVATE constructor-only Python module created; no run/scan performed.")
        if args.comparison_out and comparison is not None:
            ensure(args.comparison_out.suffix == ".json")
            private_create(args.comparison_out, (
                json.dumps(comparison, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            print("Owner-only aggregate source-revision JSON created; no source IDs.")
        return 0
    except Hold:
        print("HOLD: unsupported, malformed, ambiguous or non-private original lab catalog. No execution.", file=sys.stderr)
        return 3
    except (OSError, ValueError):
        print("HOLD: could not safely create PRIVATE handoff file; no execution.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
