# LightUp opt-in local remediation evidence intake CLI

**State:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE · NO DEPLOY. Explicit user-run offline diagnostics, **not the default application flow**.

## What is executable

This child is pinned **exactly** above already hosted-validated opt-in evidence review PR #1282 at `7f7b4af30fe32b35aac4ee3b612c35138d1ed5a7`. It adds ONLY three new independent paths:
- `scripts/check_remediation_review_intake_optin.py`: invoke the installed-in-branch pure `prepare_remediation_review_inputs()` on a bounded UTF-8 JSON file;
- `tests/test_remediation_intake_cli_optin.py`: **20 subprocess tests** on synthetic data;
- this doc.

The tool does not need a configured provider, account, token, target, approval, network or database. It **never invokes** `AssessmentReviewPipeline`, ModelGateway, scanners, authorization services, remediation or retest. Even when preflight is successful, the output **does not grant permission to scan** and is not a verification, remediation or release verdict.

## Invocation

Create an offline synthetic fixture:

```json
{
  "target": "asset://synthetic-local",
  "findings": [{
    "finding": "Synthetic security-header finding",
    "severity": "medium",
    "target": "asset://synthetic-local",
    "impact": "Synthetic impact only",
    "fix": "Set a secure lab configuration and retest",
    "evidence_summary": "An offline synthetic observation",
    "evidence_ids": ["evidence:synthetic-1"]
  }]
}
```

```bash
PYTHONPATH=src python scripts/check_remediation_review_intake_optin.py --input /path/to/owned-synthetic.json
PYTHONPATH=src python -m unittest discover -s tests -p 'test_remediation_intake_cli_optin.py' -v
```

Success (exit 0) emits JSON with `status=ready`, aggregate finding/evidence-reference **counts only**, `metadata_only=true`, `model_dispatched=false`, `authorized=false`. Invalid input (exit 2) emits **only** `status=rejected`, fixed non-sensitive `code`, `model_dispatched=false` and `authorized=false`, with empty stderr. No filename, original JSON value, target, finding title, evidence ID, raw payload, exception chain, stack trace, token or path is echoed. Input files must be regular (no symlink), locally readable, and at most **1,048,576 bytes**; each read is bounded regardless of file size metadata. UTF-8 strict decoding, strict JSON object-key uniqueness (including nested dictionaries), nonstandard NaN/Infinity refusal, float exponent finiteness and containment of excessively nested JSON (explicit quote-aware structural depth cap of 128, portable across Python 3.11/3.14) all fail closed.

The validated JSON uses the exact optional `prepare_remediation_review_inputs` contract from PR #1282; malformed or polymorphic metadata, blank remediation, duplicate evidence IDs and oversized records reject the **entire batch** with no partial count output.

## Non-overlap and release

Main production review remains source-owned by PR #846 and open issues #899/#901/#902. Original #1282 source files remain untouched and this stack adds only opt-in operator ergonomics and tests. The CLI never invokes the opt-in model review adapter itself. No target, DNS, real customer record, external model, tool execution, evidence collection, security verdict, authorization, remediation, retest, merge or deployment.

Require **exact-head** hosted Python 3.11/3.14 plus separately registered permanent VPS CI, privacy/security and current-main integration review and explicit human merge/deploy approval. A VPS run that is merely queued is not evidence of success.

**Cross-version hardening:** a real hosted Python 3.14 test initially exposed divergence in how deeply nested JSON is accepted versus Python 3.11. This is addressed by an explicit byte-level, quote/escape-aware maximum structural depth of 128 before calling Python's version-dependent JSON decoder; the regression suite proves actual depth 128 is allowed, depth 129 is denied as `json_too_deep`, and bracket-like characters inside JSON strings never count as structural nesting. No raw input is printed when refused.
