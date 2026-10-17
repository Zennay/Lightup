# LightUp #1535 — Python 3.14 warning/native I/O tripwire compatibility

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** No merge, deploy, target, scan, grant, handler or release.

## Original-source discovery
The original Python source of `src/lightup/capability_registry_history_report.py` included two invalid string escapes `\\` ` within a Markdown f-string. Under Python3.14.4 those can emit `SyntaxWarning`. Python's warnings formatter calls `linecache.getline -> tokenize.open` to print the offending code line. The existing real scope offline native I/O tripwire correctly rejects this extra source read with hard exit 92. In a read-only diagnostic on `vps-bb300bba`, only the Markdown reporter's REVIEW_ONLY and HOLD cases failed (2 ordinary failures among 1281 tests in a separate disposable composite test checkout). No native guard bypass or real asset access was shown.

## Minimal original-source fix
Escape the backslashes in the f-string source properly while retaining **byte-for-byte the same original Markdown output**, including literal backslash-backtick delimiters required by original renderer regression tests. This is a no-op for authority, consent, dispatch, network, output format or execution. The existing no-I/O guard and warning-path tests are untouched.

## Dedicated reproducible evidence
- New isolated `test_scope_registry_warning_1535_20261017.py` requires compilation with warnings promoted to errors, a truly isolated interpreter import under error-on-warning, and absence of guard-disable hooks.
- Existing actual `test_scope_registry_history_report.py` asserts unchanged Markdown semantics.
- Existing actual `test_scope_composed_native_offline_cli_20261014.py` invokes eight original CLI entrypoints and insists that native I/O blockers remain hard-fail, with zero real targets.
- Own no-secrets GitHub Actions matrix on Python3.11/3.14, exact pinned original main ancestry and exclusive modified/new path check.
- The separate full original hosted suite still has historical #301 stale-date fixture RED, owned by draft #1452. Named permanent VPS runner #1144, full CI, separate authenticated client/operator consent with at-use revoke, privacy/security and HUMAN GO remain independent.

**DRAFT/HOLD. No release authority follows from offline green tests.**
