# Offline scope-review CLI socket fleet — #1388

## Purpose

LightUp stays **INCUBATE M3/M7 · PLAN/LAB ONLY**. This additive regression runs eight real developer-facing offline registry and scope review commands. They must not allocate even an unconnected socket while rendering a REVIEW_ONLY/HOLD receipt, a registry export, or a static Markdown review. This closes a **separate fleet-wide test coverage gap** after the single finite-NUMBER entrypoint in [#1386](https://github.com/Zennay/Lightup/issues/1386).

## Tested commands and proof

The test `tests/test_scope_offline_cli_socket_fleet_20261014.py` invokes these **actual scripts** in fresh Python subprocesses, with copied/synthetic local manifest files only:

- `export_scope_capability_registry_offline.py` (from fixture setup).
- `review_scope_capability_registry_offline.py` (equal and modified manifests).
- `review_scope_registry_history_offline.py` (equal and modified history).
- `review_scope_history_against_checkout_offline.py` (equal and stale history).
- `render_scope_registry_history_offline.py` (human-readable equal/HOLD Markdown).
- `review_scope_incubation_registry_offline.py` (ordinary and forbidden activation args).
- `review_scope_incubation_catalog_offline.py` (ordinary and forbidden activation args).
- `review_scope_finite_number_offline.py` (valid finite and invalid nonfinite JSON).

Every subprocess loads a hermetic `sitecustomize.py` *before* its CLI. It aborts via noncatchable `os._exit(92)` when Python-level `socket.socket`, direct `_socket.socket`, `socket.socketpair`, `socket.create_connection`, `socket.create_server` or `socket.fromfd` is invoked. Seven disposable negative controls deliberately try each constructor inside a swallowed `BaseException`; all must abort with exit 92 and **zero stdout/stderr**. Positive and HOLD commands still return expected nonzero status 3/2 respectively, and all exposed authority flags remain exact `false`. Synthetic workspace files are checked byte-for-byte after each call; no live target, customer, service or network is used.

## Explicit limits

- This is a **Python-level regression tripwire**, not kernel egress fencing. Native libraries, dynamically loaded system calls, prior imported aliases, or non-Python processes are not universally constrained by these hooks. No real-network negative control is run.
- `REVIEW_ONLY` is never consent, an authenticated approval, a scan permit, an active execution gate, or a release authorization. A successful test cannot repair original live ToolExecutor/grant/policy defects or #1143 by itself.
- All changes are two new test/docs paths only; existing source owner PRs, other worker tests, runner files, workflows, main and services are not edited. Source-only merge after exact-head hosted Python3.11/3.14 units and independent producer integrations passes, with permanent VPS and real approval reserved as separate gates.

Run locally in the existing repository environment: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_offline_cli_socket_fleet_20261014.py' -v`.

**No active security scans, customer permission issuance, production deployment or claims of OS isolation.**