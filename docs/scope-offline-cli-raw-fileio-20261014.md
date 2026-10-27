# Direct raw FileIO no-read canary — LightUp #1404

LightUp remains **INCUBATE M3/M7, PLAN/LAB ONLY**.

## Why this exists
The independent Python-only test fixture in `tests/test_scope_offline_cli_socket_fleet_20261014.py` restricts ordinary `open`, `io.open`, `Path.open`, `os.open`, direct `os.read*` and descriptor duplication. Explicit construction via `io.FileIO` / `_io.FileIO` can bypass those Python hook points. This is a gap **in the synthetic regression instrument**, not evidence of a production breach.

## Separate, additive acceptance
New, solely owned `tests/test_scope_offline_cli_raw_fileio_20261014.py` imports the existing no-network/no-process/no-write tripwire and **extends it only inside isolated disposable Python subprocesses** to intercept direct raw file-object constructors. Four genuinely executed negative-control subprocesses attempt an explicitly synthetic local decoy file or inherited stdin FD through both exposed FileIO symbols, wrapped in broad `except BaseException`. Every attempt must abort before raw file construction with exit code 92, no stdout/stderr and unchanged file bytes.

The same extended fixture runs the **real** opt-in `scripts/review_scope_finite_number_offline.py` against a normal finite JSON case (status REVIEW_ONLY / exit 3) and deliberately nonfinite JSON (HOLD / exit 2). Each real receipt must preserve all five hardcoded authorization/permit/execution/merge/release flags as **false**.

`_io.open_code` is intentionally **not** intercepted; Python imports may depend on it. This is a scoped regression, not universal filesystem isolation. The other seven actual review CLIs are continuously exercised by the existing fleet test. No live CLI, production source-owner implementation, runner, workflow, active scan, customer DB, grant or deploy changes.

## Gates
Use existing hosted offline preflight on the exact PR SHA, Python 3.11 and 3.14 full unit suite and genuinely separate producer integrations; raw logs must be checked. Registered permanent VPS evidence and explicit independent security/privacy/source-owner release decision remain separate. **No merge/deploy/real scans based on these Python hooks alone.**
