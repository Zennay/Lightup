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
## W20 — no child processes or shell from any offline scope CLI (#1390)

The same early `sitecustomize` test fixture now additionally denies `subprocess.Popen` (covering `subprocess.run`), `os.system`, `os.popen`, available `os.fork`/`forkpty`, `os.spawn*`, `os.exec*` and `os.posix_spawn*` before a review script can invoke them. The original fleet-wide REVIEW_ONLY/HOLD/Markdown/byte-for-byte tests run with these process tripwires active, not just socket tripwires. Eight disposable negative subprocesses intentionally attempt process/shell operations inside `except BaseException`, each requiring noncatchable exit 92, no stdout/stderr and unchanged disposable local files. No real child/shell command, target, scanner, grant or deployment is launched in these negative controls.

This is still only **Python monkeypatch coverage for specific entrypoints**, not an OS-level process sandbox, proof against native syscalls, or a production admission control. Independently owned orchestration, risk-5 operator approval and verified lab-isolation gates remain necessary. Hosted exact-head test evidence and separate permanent VPS evidence must be recorded before broader release.

## W21 — fail-hard filesystem and SQLite mutation canaries (#1392)

The very same eight real opt-in offline CLI entrypoints now also run under early `sitecustomize` guards for write-capable built-in, `io.open`, `Path.open` and `os.open` modes; `os.fdopen`; Path creation, deletion, rename and permission changes; `os.mkdir`/rename/delete/chmod/chown/truncate; and `sqlite3.connect` / `sqlite3.dbapi2.connect`. Exact open modes and integer flags are checked before any attempt. Valid local read-only manifest opens remain allowed. The hooks terminate with **`os._exit(92)`** on attempted writes, so broad application `except BaseException` cannot suppress the failing test.

Ten deliberately mutated disposable child processes attempt each distinct write or SQLite route under a catch-all, and each must exit 92 with zero stdout/stderr and an unchanged disposable parent sandbox. The real CLI happy/HOLD matrix is exercised with these fail-hard hooks, keeping normal output non-authorizing and avoiding all real network/targets. This complements prior #1362's catchable marker-based test without modifying that independently owned suite.

**Limits:** Python monkeypatch-based evidence is not a kernel filesystem sandbox, cannot police native syscalls or aliases saved before hook installation, and does not prove production consent/authorization. No durable grant issuance, active scans, remote access, deployment or production state mutation are added.

## W22 — low-level file descriptor and `_sqlite3` no-I/O regressions (#1394)

High-level file/SQLite methods are not the entire Python API: `os.write`, `writev`, `pwrite`, `pwritev`, `sendfile`, `copy_file_range` and `splice` can directly change data through inherited or pre-opened descriptors without calling the previously protected `open()` methods. Likewise, direct `_sqlite3.connect` can bypass a wrapper patched only at `sqlite3.connect`. The early child-process test hook now rejects these APIs with immediate `os._exit(92)`, wherever the OS/Python interpreter exposes them. Clean real CLI cases continue to use `sys.stdout` for developer receipts.

One separate Python unittest executes up to eight disposable subprocess mutation variants under broad `except BaseException`. Every installed API must hit exit 92, zero stdout/stderr and no changed fixture bytes; unsupported optional OS functions are skipped. The `_sqlite3` mutation uses a disposable local path but must be intercepted **before** opening it. Existing eight real CLI positive/HOLD checks still must pass.

These controls deliberately do **not** patch the kernel, raw C syscalls, all pre-bound extension aliases, or native binaries. They are negative tests for specific Python entrypoints, not trusted OS confinement or a grant/release/security scan permit. Runtime source owners #1143/#1173 and registered permanent VPS CI remain separate.

## W23 — socketless DNS / reverse lookup tripwires (#1396)

A Python CLI can trigger libc-backed hostname/reverse-DNS resolution with `socket.getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, `getnameinfo` or `getfqdn` without first constructing a Python socket. Constructor-only tripwires therefore do **not** prove DNS-free review. This test-only update patches the public `socket` names and independently exposed `_socket` C-extension exports at Python's `sitecustomize` pre-import step. Any attempt aborts with noncatchable `os._exit(92)` before actual DNS and before a benign receipt.

The regression runs up to eleven independent child mutants targeting public/direct resolvers with a broad `except BaseException`. Each supported call must exit 92 with zero stdout and stderr, with the sandbox manifest files unchanged. The existing eight genuine offline scope-review CLI cases (valid and invalid) must still behave as REVIEW_ONLY/HOLD and never request DNS. A synthetic `synthetic.invalid` hostname is passed to intercepted functions but is never queried on a network.

**Limit:** this is Python-level negative testing, not OS/libc egress fencing, not a proof about alternate native resolver APIs or pre-bound method references, not permission for real scans, and never source-owner production authorization enforcement. LightUp remains **INCUBATE M3/M7 PLAN/LAB ONLY**.
