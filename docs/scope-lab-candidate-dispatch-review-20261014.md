# Offline lab candidate × real LightUp run preview (#1173)

This additive, opt-in reviewer accepts an actual `RunContext`, `ToolCall`, `ToolDefinition` and a synthetic, disposable-SQLite `LabApprovalCandidateLedger`. It performs **NO dispatch**, no remote target I/O, no callback, no granting, no production authorization. This is solely a human **REVIEW_ONLY** hint when all declared identities appear coherent.

The preview requires exact built-in model types and strict canonical opaque IDs; lab-only mode and interaction, exact enum risk 5, `is_lab is True`, no real-target grant, exact asset/capability/tool/client/engagement/run identity, no parameterized arguments or destination-bearing tool schema until a trusted registry binding exists, and a context created after candidate issuance but before expiration. A candidate made inactive through per-run revocation, durable engagement HOLD, or tenant HOLD never returns `REVIEW_ONLY`. Corrupt SQLite timestamp rows, spoofed subclasses, opaque forged contexts, mismatched tenant and chronology all fail with privacy-safe `HOLD`.

Every result hardcodes `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `merge_approved=false`, and `release_approved=false`, even for a fully matching in-memory synthetic preview. **No REVIEW_ONLY result authenticates an operator, proves a customer owns an asset, demonstrates network isolation, validates current real consent, or authorizes active/destructive testing.** Original [executor source owner #107](https://github.com/Zennay/Lightup/pull/107) and [optional risk-5 lab gate #1172](https://github.com/Zennay/Lightup/pull/1172) are unchanged. Explicit human security/privacy review and an independently validated operator-role and isolated environment implementation are still missing.

### Synthetic local usage

```python
from lightup.lab_candidate_dispatch_review import review_lab_candidate_dispatch

# context, call, definition are real model objects. ledger is a disposable
# candidate-only SQLite store, not a source of real execution permission.
receipt = review_lab_candidate_dispatch(ledger, context, call, definition)
assert receipt["execution_enabled"] is False
```

Run the 23 real-model SQLite tests with `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_lab_candidate_dispatch_review.py' -v`. The original full hosted offline preflight also exercises existing producer and fail-closed regressions.

**Project phase: INCUBATE M3/M7 / PLAN-LAB ONLY. No deployment, no real scans, no authorization or activation.**
