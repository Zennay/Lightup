# #896 — Immutable source-matched local Python verification (2026-10-16)

**Status remains INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This receipt is LOCAL TEST EVIDENCE for a standalone, opt-in no-authority review helper. The actual project runtime, installed source tests, registered self-hosted VPS matrix and release consent **are not proven by this receipt**.

## Precise tested source and procedure

Branch: [`chatgpt/scope-896-exact-cli-optin-20261016-w17`](https://github.com/Zennay/Lightup/tree/chatgpt/scope-896-exact-cli-optin-20261016-w17) based on source version **`3744de4f20f98c2a379c6168a86f35f4f455bb6b`** immediately before this evidence-only documentation commit. Both local Python file bytes were independently checked against the exact GitHub git-blob SHA (not just file names or timestamps):

- standalone reviewer: `22b9215099244195a3ce6c0ea6c077150a32e978`;
- regression test module: `fc8e06274f508ec5913292760463e2fbc66e583e`.

Runtime: **Python 3.13.5**, local isolated interpreter with available unittest and pytest; network not used. Real executed command:

```bash
cd /mnt/data/lightup_scope_896/tests && PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s . -p 'test_scope_*.py' -q && PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider
```

**ACTUAL RESULTS: `unittest` 12 methods OK; `pytest` 12 passed, 31 subtests passed.** These are the same 12 methods executed under two runners, not `24` independent scenarios. Original subprocess CLI tests and synthetic fixture controls are included.

## Mutation sensitivity: actual broken code MUST be rejected

Five independent **test-only local mutations** were created across the three isolated helpers, never pushed to GitHub and never applied to LightUp source; **all five were correctly caught by the new targeted regression tests**, each with two failed tests (ten intentional local failures in total). For this issue specifically:

Old caller-argv equality comparator restored in a disposable local copy: targeted 2/2 new CLI tests correctly FAILED (detected regression).

Failures above are intentionally induced test-oracle evidence, **not failures of the GitHub version**. The pristine source-matched files were retested successfully.

## Safety / constraints

- All receipts remain generic HOLD/REVIEW_ONLY, nonzero CLI exit 2/3 and six explicit FALSE authority flags. Neither status grants real scope, consent, permit, execution or deployment.
- This helper is **not wired into production**, does not validate authentic durable grants or transport/reviewer authority, and must not be represented as an installed security fix.
- Original source owners (#107/#146 for grant/risk; #202 for transport) retain production boundaries. The original RED acceptance contracts remain open unless integrated owners demonstrate genuine RED→PASS on their code.
- Hosted Python 3.11/3.14 and assigned permanent VPS `[self-hosted,zcloud,vps]`, expected host `vps-bb300bba`, are **not** run or proven for this child. Operator issue #1144 owns actual runner health/queue investigation.
- No competing PR, merge, CI dispatch, grant issuance, target/network probe, handler invocation or deployment. Independent security/privacy, authentic client/operator consent and explicit human GO remain absent.

**Local tests = PASS. Production authorization/release = HOLD.**
