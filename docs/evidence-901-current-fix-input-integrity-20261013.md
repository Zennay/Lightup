# #901 — current remediation/fix input must be admitted before model invocation

LightUp **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE · NO DEPLOY**.

## Precise parent and collision boundary

Immutable parent: original [PR #846](https://github.com/Zennay/Lightup/pull/846) exact SHA `26b0ca5e89648c3604ff3b9ca1ba2fab81dd2dd6`. This is an independent **tests/docs-only** child: `tests/test_review_current_fix_integrity_901.py` plus this document. **No production edits** to source-owner `src/lightup/ai/pipeline.py`, ModelGateway/provider, labrun, authorization, target-capable execution, reporting, live remediation, verdict, another worker's branch, or databases.

The current review pipeline builds the verifier request, immediately dispatches a verifier model, and later includes `finding["fix"]` in the advisor payload with no type/emptiness gate. A malformed `current_fix` is therefore transmitted to a role before validation, potentially causing misleading synthesized remediation. This tests-only sidecar proves what the real source-owner must enforce and does not pretend to fix it.

## Executable acceptance matrix

All inputs are synthetic, `ScriptedProvider` captures all model dispatch; zero actual model/network calls, no scanners, only `asset://offline-only`.

- **Two ordinary PASS controls**: exact built-in, nonempty current fix, including leading/trailing spaces (preserved byte-for-byte), reaches advisor with original evidence refs and verifier/advisor/report role order; multiple valid findings keep their distinct fixes and ordering.
- **Seven deliberately unresolved expected RED**: empty fix, whitespace fix, `None`, integer, JSON list, `str` subclass, and **a later invalid finding after a valid first finding** all must refuse with controlled `ValueError` *before ANY model dispatch* and without input mutation.
- Whole-batch fail-before-dispatch is important: a later bad fix must not allow an earlier finding to dispatch the verifier or advisor. Rejecting only before each advisor would be too late.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_review_current_fix_integrity_901.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

`OK (expected failures=7)` is an **unresolved product gap**, not accepted security. The source owner should implement pre-model full-batch input admission (canonical exact `type(fix) is str` + `fix.strip()` without altering original text), preserve evidence context and role ordering, convert all expected RED into nine ordinary passing tests, and retain existing safe error semantics. Independently validate exact-head GitHub-hosted Python 3.11/3.14, separately registered permanent VPS CI, latest-main conflict/composition, privacy/security and explicit human release. No authorization expansion, live target, real evidence, customer model input, remediation/retest or deployment occurs.
