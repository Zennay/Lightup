# Issue #898 — multi-finding remediation advice output integrity (W26)

**Status: expected-RED acceptance only; M3/M7 PLAN/LAB; DRAFT/HOLD/NO MERGE/NO DEPLOY.**

This child branch is pinned to original source-owner [PR #846](https://github.com/Zennay/Lightup/pull/846) at `26b0ca5e89648c3604ff3b9ca1ba2fab81dd2dd6` through existing tests/docs child `f050e437263a71e614db4a2ed7a26719f968c5a3`. The new file `tests/test_remediation_advisor_batch_atomicity_w26.py` is **tests only**. It changes no default source, gateway, provider, scope gate, tenant data, report renderer or execution path.

Acceptance:
- Two valid findings retain ordering and exact untrimmed nonblank advice.
- A blank/whitespace-only advisor response on **the second finding** fails closed before the report synthesizer is invoked, without mutating input.
- A blank first response fails before invoking the verifier for the second finding.
- Role-request sequence is asserted, so merely raising after reporting does not pass.
- Synthetic `ScriptedProvider` only: no real model, network, target, scan, authorization grant, remediation, retest or customer data.

Run from repository root:

```bash
PYTHONPATH=src python -m unittest tests.test_remediation_advisor_batch_atomicity_w26 -v
```

**Expected outcome against unmodified #846 pipeline:** one valid-case PASS, two invalid-case FAIL (with three subcases in the later-finding method), because the default pipeline forwards blank advice. These are **not** passing production-entrypoint acceptance tests. Do not mark a green CI run on a separate opt-in helper as resolution of #898. Source-owner #846 must implement canonical validation and turn these into ordinary passing regressions, then verify exact-head hosted and registered permanent self-hosted CI plus independent review on current main.

No merge/deployment or security-verdict authority is authorized by this artifact.
