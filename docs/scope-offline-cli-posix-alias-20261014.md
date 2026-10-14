# Direct POSIX C-module aliases in synthetic offline scope review — #1420

**LightUp stays INCUBATE M3/M7 · PLAN/LAB ONLY.** This is opt-in Python-level test instrumentation, never a kernel sandbox, customer scope grant, or approval for active tests.

## Separate route into file, process and directory I/O
The merged offline CLI pre-import regression fixture guards os.open, os.read, os.write, os.listdir, descriptor duplication, and process entrypoints. On CPython POSIX builds, the separate importable native posix module exposes C-extension function aliases independent of public os module attributes. Direct calls can bypass public os monkeypatches, including file/FD reads and writes, directory enumeration, and process operations. This is a synthetic harness visibility gap only, not evidence of real production/customer exposure.

## Implemented independent test
The new isolated tests/test_scope_offline_cli_posix_alias_20261014.py uses an early disposable sitecustomize extending the existing protected eight-CLI fixture. Supported native posix.open/read/readv/pread/preadv/write/writev/pwrite/pwritev/listdir/scandir/dup/fork/exec/spawn and related aliases are replaced by noncatchable exit 92 before the offline CLI imports.

Up to nine separately launched test-only subprocesses attempt native calls against either an invented local decoy filename, inherited stdin/stdout, the disposable directory, or a local process entrypoint. Even if the caller swallows BaseException, the process must terminate with exit92, zero stdout/stderr and byte-identical fixture files. Unsupported platform methods are skipped; tests require POSIX to exercise this extension.

The same stricter fixture executes the **authentic source** finite-NUMBER scope review CLI twice (valid REVIEW_ONLY / nonfinite HOLD), retaining all five authority/permit/execution/merge/release flags exactly false, and the real capability registry exporter with expected nonzero REVIEW_ONLY. All checks are offline, with no network or real target.

## Limits and release
Python module monkeypatching does not confine native C syscalls, earlier-bound aliases, or processes outside the harness. It does not change production authorizations, domain stores, grants, active scanners, source-owner PRs, runner/workflows or deployments. Exactly two new uniquely owned test/docs files. An immutable-head Python3.11 and Python3.14 hosted unit suite plus genuine producer integrations must pass before source-only merge. Permanent registered VPS proof, trusted live consent and explicit independent human security/privacy release remain separately necessary.
