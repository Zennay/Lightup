# Synthetic scope-review CLI directory enumeration boundary — #1415

**LightUp remains INCUBATE M3/M7, PLAN/LAB ONLY.** This is a *test-only Python regression*, not an OS filesystem sandbox, verified customer permission, or production security gate.

## The uncovered observation route
The existing eight-command offline scope-review test fleet blocks Python-level unauthorized file-body reads, writes, descriptor duplication, native `_io.open` aliases and network/socket attempts. Directory enumeration is a separate way of observing names of files and folders without opening their contents. An arbitrary `os.listdir`, `os.scandir`, `pathlib.Path.iterdir`, `glob.glob` or `os.walk` could return filename metadata outside the original read allowlist.

## Independent test implementation
The newly added `tests/test_scope_offline_cli_directory_enumeration_20261014.py` extends the already merged **pre-import** synthetic `sitecustomize` fixture in its own disposable subprocess only. It denies `os.listdir`, `scandir`, `walk` (and optional `fwalk`), `Path.iterdir` / `glob` / `rglob` / optional `walk`, and `glob.glob` / `iglob` with noncatchable process exit 92. Eight separate negative subprocess controls execute attempted calls in `try/except BaseException` and must abort with zero stdout/stderr and unchanged hashes of **fictional-only** lab files.

The same stronger fixture runs actual source `review_scope_finite_number_offline.py` for valid finite NUMBER input (REVIEW_ONLY exit 3) and invalid NaN (HOLD exit 2). It verifies all five authorization, permit, execution, merge, and release flags are **exactly false** and no file changes. The authentic registry exporter likewise must work with exit 3 and a capabilities JSON manifest. The pre-existing fleet suite independently continues to exercise its full eight genuine offline entrypoints.

## Safety / limits / release
These Python symbol hooks are **not kernel/OS isolation** and cannot constrain native syscalls or pre-bound aliases in arbitrary extensions. The test contains no external network, real customer private paths, active scan, grant issuance, workflow/runner modification, or deployment; only two new isolated test/docs files were added. Hosted immutable SHA Python 3.11/3.14 units and real producer integration jobs must pass before any source-only merge. Permanent registered VPS proof and independent human security/privacy release decisions remain separate blockers for production authorization.
