# Issue #285 — current-main explicit Unicode/IDNA scope identity acceptance

**15 October 2026 · INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**

## Why this separate slice exists

The 6 October add-only test branch is now visible in [draft PR #1441](https://github.com/Zennay/Lightup/pull/1441), but diverges from `main` and cannot be regarded as current-head validation. This additional independent slice starts from the **current main** instead; it edits none of the former owner's two files and touches no authorization source, live handler, CI workflow, runner, or target path.

`tests/test_scope_idna_current_main_matrix_285_20261015.py` provides eight dedicated, **pure in-memory** test methods. It uses the real installed `ScopePolicy.decide` and `Target` with a **synthetic and explicitly non-real** `Authorization` fixture only to exercise existing membership decisions.

## Measurable acceptance

- Unicode/punycode names must not silently borrow authority **in either direction**, checked for Unicode, ASCII punycode and URL spellings, including another independent label.
- Composed and decomposed Unicode must remain **distinct in both directions**.
- All three common Unicode dot-lookalike code points U+3002, U+FF0E and U+FF61 must not inherit ASCII-host scope.
- Within one declared exact host identity, ordinary case and trailing-dot normalization must remain functional.
- Even an **exact listed host** must deny when the separate authorization fixture is absent.
- An empty allowlist must not admit unknown internationalized names.
- ScopePolicy and Target state must remain unchanged by a rejected decision.
- DNS, socket creation and subprocess launch are patched to raise if accidentally used in the pure policy path.

The test-only positive `ScopeDecision.allowed=True` with a synthetic fixture is **not** proof of signed customer consent, a current durable grant, a real client, capability/destination authorization, revocation, an installed ingress, an approved live execution, or external asset ownership.

## Commands for the owned self-hosted runner / hosted checks

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_idna_current_main_matrix_285_20261015.py' -v
python -m unittest discover -s tests -v
```

Run the dedicated tests on Python 3.11 and 3.14, and check original job logs plus real producer integrations on the **exact PR head SHA**. A queued workflow is not success. A hosted run does **not** prove permanent VPS runner execution. No network/target scans or grant issuance is required or permitted.

## Owner and release gate

This does **not** modify original #285 or current source-owner `src/lightup/scope.py`, and does not supersede the 6 October branch. Future changes to IDNA interpretation must coordinate explicit allow/exclude/authorization identity and require separate source-owner, security/privacy, canonical VPS and human approval. Maintain **DRAFT/HOLD — NO MERGE, DEPLOY, ACTIVE SCAN OR REAL GRANT**.
