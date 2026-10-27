"""Opt-in synthetic memory measurement for evidence rendering; never imports production data.

Usage: python tools/evidence_memory_lab.py module:function --budget-kib 32768
The callable must accept one synthetic string and return text or raise.
"""
import argparse
import importlib
import json
import resource
import sys
import tracemalloc


def measure(target, sample):
    tracemalloc.start()
    before, _ = tracemalloc.get_traced_memory()
    outcome = "ok"
    output_bytes = None
    try:
        result = target(sample)
        output_bytes = len(result.encode("utf-8")) if isinstance(result, str) else None
    except Exception as exc:
        outcome = type(exc).__name__
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"case": sample[0], "source_bytes": len(sample[1].encode("utf-8")),
            "outcome": outcome, "output_bytes": output_bytes,
            "python_peak_delta_bytes": max(0, peak - before),
            "rss_max_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="module:function (explicit opt-in only)")
    parser.add_argument("--budget-kib", type=int, required=True)
    args = parser.parse_args()
    module, function = args.target.split(":", 1)
    target = getattr(importlib.import_module(module), function)
    cases = [("empty", ""), ("unicode", "Café 🛡️"),
             ("boundary", "x" * 16384), ("over_boundary", "x" * 16385),
             ("escape_heavy", "<&" * 8192)]
    rows = [measure(target, case) for case in cases]
    print(json.dumps({"measurements": rows, "note": "tracemalloc is not RSS; no hard bound implied"}, indent=2))
    return int(any(row["python_peak_delta_bytes"] > args.budget_kib * 1024 for row in rows))


if __name__ == "__main__":
    sys.exit(main())
