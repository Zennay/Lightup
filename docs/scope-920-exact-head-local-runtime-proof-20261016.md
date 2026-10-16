# #920 — Immutable source-matched local Python verification (2026-10-16)

**Status remains INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This receipt is LOCAL TEST EVIDENCE for a standalone, opt-in no-authority review helper. The actual project runtime, installed source tests, registered self-hosted VPS matrix and release consent **are not proven by this receipt**.

## Precise tested source and procedure

Branch: [`chatgpt/scope-920-exact-map-keys-20261016-w17`](https://github.com/Zennay/Lightup/tree/chatgpt/scope-920-exact-map-keys-20261016-w17) based on source version **`090c0567849674971c2d8b9cd4bde09fdd2dcf95`** immediately before this evidence-only documentation commit. Both local Python file bytes were independently checked against the exact GitHub git-blob SHA (not just file names or timestamps):

- standalone reviewer: `ffc3350c2d192ad71ac786095ee71cd7a22e341b`;
- regression test module: `baa58c444b3b094b05b779ee5625156642370fb2`.

Runtime: **Python 3.13.5**, local isolated interpreter with available unittest and pytest; network not used. Real executed command:

```bash
cd /mnt/data/lightup_scope_920/tests && PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s . -p 'test_scope_*.py' -q && PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider
```

**ACTUAL RESULTS: `unittest` 17 methods OK; `pytest` 17 passed, 41 subtests passed.** These are the same 17 methods executed under two runners, not `34` independent scenarios. Original subprocess CLI tests and synthetic fixture controls are included.

## Mutation sensitivity: actual broken code MUST be rejected

Five independent **test-only local mutations** were created across the three isolated helpers, never pushed to GitHub and never applied to LightUp source; **all five were correctly caught by the new targeted regression tests**, each with two failed tests (ten intentional local failures in total). For this issue specifically:

Removing exact per-key typing in a disposable local copy: targeted 2/2 adversarial key tests FAIL. Restoring the old untyped CLI comparison: targeted 2/2 forged opt-in tests FAIL. Both deliberately broken inputs were caught.

Failures above are intentionally induced test-oracle evidence, **not failures of the GitHub version**. The pristine source-matched files were retested successfully.

## Safety / constraints

- All receipts remain generic HOLD/REVIEW_ONLY, nonzero CLI exit 2/3 and six explicit FALSE authority flags. Neither status grants real scope, consent, permit, execution or deployment.
- This helper is **not wired into production**, does not validate authentic durable grants or transport/reviewer authority, and must not be represented as an installed security fix.
- Original source owners (#107/#146 for grant/risk; #202 for transport) retain production boundaries. The original RED acceptance contracts remain open unless integrated owners demonstrate genuine RED→PASS on their code.
- Hosted Python 3.11/3.14 and assigned permanent VPS `[self-hosted,zcloud,vps]`, expected host `vps-bb300bba`, are **not** run or proven for this child. Operator issue #1144 owns actual runner health/queue investigation.
- No competing PR, merge, CI dispatch, grant issuance, target/network probe, handler invocation or deployment. Independent security/privacy, authentic client/operator consent and explicit human GO remain absent.

**Local tests = PASS. Production authorization/release = HOLD.**
