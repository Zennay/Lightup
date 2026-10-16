# #897 — Immutable source-matched local Python verification (2026-10-16)

**Status remains INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This receipt is LOCAL TEST EVIDENCE for a standalone, opt-in no-authority review helper. The actual project runtime, installed source tests, registered self-hosted VPS matrix and release consent **are not proven by this receipt**.

## Precise tested source and procedure

Branch: [`chatgpt/scope-897-sqlite-connection-lifetime-20261016-w18`](https://github.com/Zennay/Lightup/tree/chatgpt/scope-897-sqlite-connection-lifetime-20261016-w18) based on source version **`984a6934a1591298b371bc2cdac8400d09c57578`** immediately before this evidence-only documentation commit. Both local Python file bytes were independently checked against the exact GitHub git-blob SHA (not just file names or timestamps):

- standalone reviewer: `49c13e9c265b74fd83e92d9d42d3612e6e02c21d`;
- regression test module: `45ea76644d652ced2c7eee3c2331351115c61d2e`.

Runtime: **Python 3.13.5**, local isolated interpreter with available unittest and pytest; network not used. Real executed command:

```bash
cd /mnt/data/lightup_scope_897/tests && PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s . -p 'test_scope_*.py' -q && PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider
```

**ACTUAL RESULTS: `unittest` 16 methods OK; `pytest` 16 passed, 29 subtests passed.** These are the same 16 methods executed under two runners, not `32` independent scenarios. Original subprocess CLI tests and synthetic fixture controls are included.

## Mutation sensitivity: actual broken code MUST be rejected

Five independent **test-only local mutations** were created across the three isolated helpers, never pushed to GitHub and never applied to LightUp source; **all five were correctly caught by the new targeted regression tests**, each with two failed tests (ten intentional local failures in total). For this issue specifically:

Removing exact per-key typing in a disposable local pre-cleanup copy: 2/2 spoof-key tests FAIL. Restoring old caller-argv equality comparison: 2/2 option-spoof tests FAIL. Both regression groups detected the intentional mutations. The extra W18 change replaces context-only sqlite3.connect usage with contextlib.closing(sqlite3.connect(...)) in two hermetic in-memory fixture cases; it makes actual connection lifetime explicit and keeps original row-equality assertions.

Failures above are intentionally induced test-oracle evidence, **not failures of the GitHub version**. The pristine source-matched files were retested successfully.

## Safety / constraints

- All receipts remain generic HOLD/REVIEW_ONLY, nonzero CLI exit 2/3 and six explicit FALSE authority flags. Neither status grants real scope, consent, permit, execution or deployment.
- This helper is **not wired into production**, does not validate authentic durable grants or transport/reviewer authority, and must not be represented as an installed security fix.
- Original source owners (#107/#146 for grant/risk; #202 for transport) retain production boundaries. The original RED acceptance contracts remain open unless integrated owners demonstrate genuine RED→PASS on their code.
- Hosted Python 3.11/3.14 and assigned permanent VPS `[self-hosted,zcloud,vps]`, expected host `vps-bb300bba`, are **not** run or proven for this child. Operator issue #1144 owns actual runner health/queue investigation.
- No competing PR, merge, CI dispatch, grant issuance, target/network probe, handler invocation or deployment. Independent security/privacy, authentic client/operator consent and explicit human GO remain absent.

**Local tests = PASS. Production authorization/release = HOLD.**
