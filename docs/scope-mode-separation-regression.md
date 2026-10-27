# Scope interaction-mode separation regression

This additive, offline-only acceptance module pins the baseline decision boundaries of `ExecutionPolicy` before any handler, network adapter, or durable authorization state is involved.

| Mode | Positive control | Negative control |
| --- | --- | --- |
| ANALYSIS | ANALYSIS_ONLY | PASSIVE, STANDARD, DESTRUCTIVE_LAB_ONLY |
| PASSIVE_PUBLIC | PASSIVE | STANDARD, DESTRUCTIVE_LAB_ONLY |
| LAB_ACTIVE | explicit `is_lab=True` | `is_lab=False` |
| TARGET_ACTIVE | none without a grant | `is_lab=True` must never substitute for an authorization grant |

Run: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_mode_separation_regression.py' -v`.

This is a read-only in-memory test contract, **not** activation authority. It deliberately does not assert noncanonical enum inputs, unknown interaction kinds, live grant validation, persisted state, scanning, or real target execution: those are separate owner lanes (#986, #987, #107). Existing production source ownership remains unchanged. Do not merge until exact-head CI is green and the responsible owner has reviewed the non-overlap.
