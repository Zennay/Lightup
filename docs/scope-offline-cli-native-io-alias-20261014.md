# LightUp offline scope direct _io.open denial — #1410

**INCUBATE M3/M7, PLAN/LAB ONLY.** This independent Python-only regression does not grant assessment authorization, cannot isolate native syscalls, and is never installed into production.

## Why a second alias matters

The original synthetic no-I/O reviewer fleet uses a pre-import `sitecustomize` to bind reads to three disposable fixture files through `builtins.open`, `io.open`, `Path.open` and `os.open`. The separately exported C-module `_io.open` symbol can still construct a file handle without those public-Python wrapper calls. This is a test-instrumentation coverage gap only; there is no customer-file or active-target reproduction.

## Offline implementation and acceptance

A **new independent test file** `tests/test_scope_offline_cli_native_io_alias_20261014.py` imports the existing verified fleet's tripwire and adds one narrowly scoped wrapper for `_io.open` before the real CLI is loaded. Its exact string/Path and custom-opener refusal is self-contained so its correctness does not depend on the ordering of separate opener/PathLike PR #1409.

Five disposable child variants attempt the direct alias against an invented private-decoy fixture, inherited stdin, keyword/positional descriptor-substitution opener and a custom executable PathLike object. The test requires immediate uncatchable exit 92 and zero stdout/stderr even if each child swallows `BaseException`; it compares fixture hashes after each run. No real private customer/host files are opened.

The same guard also executes **real existing** `review_scope_finite_number_offline.py` valid/invalid input (REVIEW_ONLY exit 3 / HOLD exit 2; all five authority/permit/execution/merge/release flags exactly false) and the real capability-registry exporter (synthetic REVIEW_ONLY exit 3). All leave the lab files unchanged. `_io.open_code` remains intentionally untouched so normal Python import behavior is preserved.

## Limits and release

This extension is **not a kernel filesystem/no-network sandbox**: pre-bound aliases, native extensions and arbitrary syscalls are not globally confined. It adds zero grant issuance, network contact, target scans, customer DB writes or production runtime changes. New test/docs paths are owned solely by this lane and disjoint from the parallel in-progress source-owner branches. Hosted immutable-head Python3.11/3.14 unit and real producer integration logs must be reviewed; a permanent registered runner and explicit human/security/privacy release are separate prerequisites before any production authorization.

## W30 hosted-CI interpreter bootstrap correction

The first exact-head hosted Python3.11/3.14 jobs FAILED on three genuine positive controls (exit92 instead of 3/2). Temporary *branch-only* diagnostics traced the first native alias read to the interpreter's own source-file bootstrap: `_io.open(".../scripts/review_scope_finite_number_offline.py", "rb")` (or the equivalent registry exporter). The direct native alias is invoked before the actual CLI runs, so a blanket alias ban would wrongly reject program startup. The failed CI is not security acceptance evidence.

The isolated fixture now captures **one exact harness-selected trusted entrypoint pathname** from startup environment, before CLI code. Only an exact built-in string pathname matching this selection, read-binary `rb` mode and zero positional/keyword options pass to the original native opener for interpreter bootstrap. All other direct alias paths use strict synthetic read admission, including inherited descriptors, custom openers and executable path-like classes. Negative `python -c` controls inherit no bootstrap exception. The exception cannot be widened by changing the environment after hook installation.

This permits ordinary Python interpreter startup only; it does not grant customer scope, authorization, deployment or general code-file access, and remains a Python test fixture rather than OS sandbox. This correction needs its own immutable-head hosted 3.11/3.14 units and genuine producer integration job logs.

## W30 second-source diagnostic: exact standard-library import boundary

The next hosted attempt also FAILED because the interpreter subsequently reads core CPython bytecode through the direct native alias: the immutable diagnostic showed an exact binary __future__.cpython-311.pyc module under the installed standard-library lib/python3.11/__pycache__ directory. This is required before the actual offline CLI can import normal dependencies. Temporary trace output was removed again.

The standalone test hook now freezes the interpreter's sys.base_prefix/lib root on startup and permits a direct native alias read only with exact built-in string pathname, read-binary mode, no extra opener/options, and one of:

- The exact preselected immutable harness-supplied Python entrypoint script.
- Built-in Python .py/.pyc files whose real resolved location is beneath the current interpreter standard-library lib tree; third-party site-packages excluded.

Untrusted synthetic fixture decoys, inherited descriptor integers, executable PathLike objects, custom openers, arbitrary unselected code paths and other local data files do not receive the exception. Negative python -c controls inherit no entrypoint whitelist. This is narrowly scoped Python test-harness import support, not a general runtime authorization or OS security confinement. New immutable-head hosted positive and negative Python3.11/3.14 and genuine producer CI still required before source-only merge.

## W30 end-to-end bootstrap resolution and final negative-control hardening

The third diagnostic hosted head after adding a narrowly frozen interpreter stdlib + owned Python package source allowance produced authentic CLI return codes **3, 2 and 3 as expected**, without hitting exit92. Its three remaining test failures were exclusively caused by temporary diagnostic stderr output, not an authorization bypass. The trace is now **fully removed** in the next immutable-head branch revision.

One additional disposable source-looking decoy called synthetic-private.py was added to the negative matrix. These child mutants now run with the **same explicitly frozen trusted code roots** as the real CLI controls, proving that merely using a Python filename suffix does not admit a foreign arbitrary path. All original five native alias negative routes remain; no real private customer file is opened or target contacted. The isolated exact-head hosted matrix must be green, including both producer integration jobs, before PR merge.
