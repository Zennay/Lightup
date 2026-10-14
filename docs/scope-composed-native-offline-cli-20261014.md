# Composed native-alias / no-I/O offline scope acceptance — #1414

## User value
One self-contained Python 3.11/3.14 source-only regression proves that **eight existing authentic LightUp scope-review CLIs** work with the combined read admission, no-network, no-process, no-write, custom-opener, memory-map, native-I/O-alias and FD-provenance Python test guards. Previously the native alias proof had only run the finite-NUMBER reviewer and exporter; the other six were exercised only under the older fleet hook. This is integration **of test instrumentation**, not production code.

## Genuine offline scenarios

The independent `tests/test_scope_composed_native_offline_cli_20261014.py` creates a disposable source manifest with the real capability-registry exporter (exit 3) and copies the returned JSON into **distinct files** as required by the real historical reviewer. It then runs seven real additional CLIs with REVIEW_ONLY receipts (including human-readable Markdown) and seven expected HOLD variants, using the composed early `sitecustomize` instrumentation from the already merged #1408/#1410/#1412 source-only tests.

Every JSON receipt must carry the exact five False authority/permit/execution/merge/release booleans. Every Markdown receipt must clearly print REVIEW_ONLY/HOLD and Authority: NONE. All CLI runs must return the expected non-zero exit 3/2, without stderr, and leave every synthetic fixture file hash unchanged. The real exporter and all reviewers are unmodified; no network, customer database, grant or target is involved. Parent and tested child processes are local only; subprocess restrictions apply *inside the child fixture*, not to the test runner itself.

The interpreter-only startup exception for exact selected scripts and current trusted Python code imports was independently verified in #1410 and is supplied per subprocess; unknown files and inherited descriptors remain disallowed by the tripwire.

## Gates and limitations

This is an **additive two-new-path integration test**, not an authorization primitive and not OS-level security confinement. Native syscalls/pre-import aliases outside specific instrumented Python names remain out of scope. Do not interpret REVIEW_ONLY as consent or execution permission. Immutable-head hosted Python 3.11/3.14 unit and separate genuine producer integration success, path conflict review, permanent registered VPS and explicit independent release/permission are separate requirements. **LightUp stays INCUBATE M3/M7 · PLAN/LAB ONLY; no merge/deploy/real scans based on test success.**
