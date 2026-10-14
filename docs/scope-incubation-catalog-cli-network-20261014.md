# LightUp incubation catalog CLI — hermetic real-entrypoint guard

Issue [#1358](https://github.com/Zennay/Lightup/issues/1358) adds an
independent opt-in regression to the previously merged #1355/#1357
scope-authorization catalog tooling.

The original hermetic test suite checks six different offline scope CLIs.
The newly added `review_scope_incubation_catalog_offline.py` must likewise
remain **offline and non-authorizing**, even when the source registry changes.

The new `tests/test_scope_incubation_catalog_cli_network_20261014.py` executes
the **actual CLI** in a disposable child Python interpreter, installs
socket/DNS attempt tripwires **before importing the CLI**, and requires no
blocked-attempt marker. A separate child-only fixture overrides the local
registry getter with 6 synthetic variations: altered capability description,
name, state, activation requirement, plus one unknown or one removed ID.
It confirms the actual source-to-CLI path returns `HOLD` (exit code **2**)
with a bounded, privacy-safe denial receipt. The unchanged source control
returns `REVIEW_ONLY` (exit code **3**), not Unix success. Real CLI invocation
with `--activate`, a URL or a path traversal argument also returns HOLD
before any target/address interpretation.

Every receipt's authorization/permit/execution/merge/release flag remains
**false**; no free-text source name or description may appear in output.

## Execute in checkout

```sh
python3 -m unittest discover -s tests -p 'test_scope_incubation_catalog_cli_network_20261014.py' -v
```

These are **Python-level tripwires**, not OS-enforced network isolation or
proof against arbitrary native code, malicious Python imports or untrusted
Git checkout. The forged source getter is changed only inside a disposable
subprocess and does not modify the actual repository or grant anything.
No actual customer data, network address, scan, run permit, local DB,
permission or deployment is used. Nothing is installed into LightUp
production execution policy.

LightUp remains **INCUBATE M3/M7, PLAN/LAB ONLY**. Hosted source tests
do not substitute for registered permanent VPS runner/release evidence,
trusted operator/tenant/asset authorization or active-test permission.
