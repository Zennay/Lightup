"""Offline detection benchmark across all planted lab fixtures.

One number nobody should trust is "findings: N". The number that matters is
whether the engine finds *what was planted* and nothing else. This module
runs every header and web-exposure fixture profile, scores the engine against
each profile's hand-maintained ground truth, and aggregates precision, recall
and F1 plus the per-profile breakdown.

It is fully offline and loopback-only: each profile is served on 127.0.0.1 for
the duration of its run. It is the thing to watch in CI to catch detection
regressions, and the thing to show a prospect to prove the engine is measured,
not asserted.
"""

from __future__ import annotations

import contextlib
import threading
from dataclasses import dataclass, field
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator

from .labeval import (
    LabEvaluationHarness,
    LabScenario,
    score_findings,
)
from .ai.orchestration import ToolCall, ToolExecutor
from .labfixtures import PROFILES, expected_findings, make_handler
from .labfixtures_web import WEB_PROFILES, make_web_handler, web_expected_findings
from .labrun import full_lab_registry
from .state import StateStore
from .workers import http_baseline, web_exposure


@dataclass(frozen=True)
class ProfileResult:
    profile_id: str
    worker: str
    expected: tuple[str, ...]
    found: tuple[str, ...]
    valid: int
    invalid: int
    missed: int
    soft_404: bool

    @property
    def precision(self) -> float:
        total = self.valid + self.invalid
        return self.valid / total if total else 1.0

    @property
    def recall(self) -> float:
        total = self.valid + self.missed
        return self.valid / total if total else 1.0

    @property
    def perfect(self) -> bool:
        return self.invalid == 0 and self.missed == 0

    def to_dict(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "worker": self.worker,
            "expected": sorted(self.expected),
            "found": sorted(self.found),
            "valid": self.valid,
            "invalid": self.invalid,
            "missed": self.missed,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "perfect": self.perfect,
            "soft_404": self.soft_404,
        }


@contextlib.contextmanager
def _serve(handler) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()


def _run_worker(tool_id: str, url: str, state_path: Path) -> tuple[str, ...]:
    registry = full_lab_registry()
    executor = ToolExecutor(registry, StateStore(state_path))
    harness = LabEvaluationHarness()
    scenario = LabScenario("benchmark", "benchmark", (url,))
    context = harness.start_run(scenario)
    result = executor.execute(
        context, ToolCall(tool_id, asset=scenario.targets[0], arguments=(("url", url),)))
    meta = dict(result.metadata)
    found = tuple(i for i in meta.get("issues", "").split(",") if i)
    return found + ((f"__soft404__{meta.get('soft_404')}",) if "soft_404" in meta else ())


@dataclass
class BenchmarkReport:
    results: list[ProfileResult] = field(default_factory=list)

    @property
    def totals(self) -> tuple[int, int, int]:
        return (sum(r.valid for r in self.results),
                sum(r.invalid for r in self.results),
                sum(r.missed for r in self.results))

    def micro_scores(self) -> dict[str, float]:
        valid, invalid, missed = self.totals
        precision = valid / (valid + invalid) if (valid + invalid) else 1.0
        recall = valid / (valid + missed) if (valid + missed) else 1.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) else 0.0)
        return {"precision": round(precision, 4), "recall": round(recall, 4),
                "f1": round(f1, 4)}

    @property
    def all_perfect(self) -> bool:
        return all(r.perfect for r in self.results)

    def to_dict(self) -> dict:
        valid, invalid, missed = self.totals
        return {
            "profiles": [r.to_dict() for r in self.results],
            "micro": self.micro_scores(),
            "totals": {"valid": valid, "invalid": invalid, "missed": missed,
                       "profiles": len(self.results),
                       "perfect_profiles": sum(1 for r in self.results if r.perfect)},
            "all_perfect": self.all_perfect,
        }


def run_benchmark() -> BenchmarkReport:
    """Run every planted fixture profile and score the engine against ground truth."""
    report = BenchmarkReport()
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        for name, profile in sorted(PROFILES.items()):
            with _serve(make_handler(profile)) as url:
                found = _run_worker(http_baseline.TOOL_ID, url, base / f"h-{name}.db")
                found = tuple(f for f in found if not f.startswith("__soft404__"))
                expected = tuple(e.identifier for e in expected_findings(profile))
                valid, invalid, missed = score_findings(expected_findings(profile), found)
                report.results.append(ProfileResult(
                    name, "http-baseline", expected, found, valid, invalid, missed, False))
        for name, profile in sorted(WEB_PROFILES.items()):
            with _serve(make_web_handler(profile)) as url:
                raw = _run_worker(web_exposure.TOOL_ID, url, base / f"w-{name}.db")
                soft = any(f == "__soft404__true" for f in raw)
                found = tuple(f for f in raw if not f.startswith("__soft404__"))
                expected = tuple(e.identifier for e in web_expected_findings(profile))
                valid, invalid, missed = score_findings(web_expected_findings(profile), found)
                report.results.append(ProfileResult(
                    name, "web-exposure", expected, found, valid, invalid, missed, soft))
    return report


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(prog="lightup-benchmark")
    parser.add_argument("--fail-under", type=float, default=1.0,
                        help="exit non-zero if micro-F1 is below this (default 1.0)")
    args = parser.parse_args(argv)

    report = run_benchmark()
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.micro_scores()["f1"] >= args.fail_under else 1


if __name__ == "__main__":
    raise SystemExit(main())
