"""Offline diagnostic ONLY: measure optional #1023 JSON shape preparse costs.

Use with synthetic local byte buffers, never client-provided targets.
Python-tracked allocation and elapsed time are observability samples, NOT
hard process RSS, CPU-time guarantees, proof of installed ingress or consent.
This module is NOT imported by production WSGI/authorization/executor code.
"""
from __future__ import annotations

import json
import time
import tracemalloc
from dataclasses import asdict, dataclass

from .envelope_preflight_optin_1023 import bounded_envelope_shape_optin


MAX_DIAGNOSTIC_INPUT_BYTES = 256 * 1024


@dataclass(frozen=True)
class EnvelopeDiagnostic:
    size_bytes: int
    bytes_limit: int
    depth_limit: int
    nodes_limit: int
    shape_eligible_only: bool
    elapsed_ns: int
    python_traced_peak_bytes: int


def measure_synthetic_envelope(
    raw: bytes, *, max_bytes: int = 4096, max_depth: int = 8,
    max_nodes: int = 128,
) -> EnvelopeDiagnostic:
    """Measure one local in-memory shape check. Never derives authorization.

    Rejects inputs above the diagnostic cap even if the caller asks the
    reference for larger budgets. Avoids overwriting an existing profiler.
    Caller owns the byte buffer; no target, client, grant, socket, or DB.
    """
    if type(raw) is not bytes:
        raise TypeError("diagnostic requires built-in bytes")
    if len(raw) > MAX_DIAGNOSTIC_INPUT_BYTES:
        raise ValueError("synthetic diagnostic sample is too large")
    if tracemalloc.is_tracing():
        raise RuntimeError("do not overwrite an existing tracemalloc session")
    snapshot = raw[:]
    tracemalloc.start()
    try:
        begin = time.perf_counter_ns()
        outcome = bounded_envelope_shape_optin(
            raw, max_bytes=max_bytes, max_depth=max_depth, max_nodes=max_nodes)
        elapsed = time.perf_counter_ns() - begin
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    if raw != snapshot:
        raise AssertionError("shape check modified its caller buffer")
    return EnvelopeDiagnostic(
        size_bytes=len(raw),
        bytes_limit=max_bytes,
        depth_limit=max_depth,
        nodes_limit=max_nodes,
        shape_eligible_only=outcome,
        elapsed_ns=elapsed,
        python_traced_peak_bytes=peak,
    )


def synthetic_profile_rows() -> list[dict[str, int | bool]]:
    """Generate reproducible offline synthetic sizes, not user data."""
    cases = (
        (0, 1), (4, 8), (32, 12), (128, 64), (256, 300),
    )
    rows = []
    for count, nodes_limit in cases:
        payload = json.dumps({"values":list(range(count))},
                             separators=(",", ":")).encode("ascii")
        report = measure_synthetic_envelope(
            payload, max_bytes=max(4096, len(payload)),
            max_depth=3, max_nodes=nodes_limit)
        rows.append(asdict(report))
    return rows


def main() -> int:
    """Optional local inspection: PYTHONPATH=src python -m lightup.envelope_profile_optin_1023"""
    print(json.dumps({
        "mode": "synthetic-offline-non-authorizing",
        "metrics_are_release_proof": False,
        "warnings": ["tracemalloc excludes unmanaged native/process RSS",
                     "elapsed time depends on host and Python version",
                     "shape eligible never means consent or a valid grant"],
        "rows": synthetic_profile_rows(),
    }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
