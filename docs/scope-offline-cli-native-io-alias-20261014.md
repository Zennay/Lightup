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
