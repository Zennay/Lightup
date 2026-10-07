# ST5 remediation text-proposal raw response bound

Issue: #818  
Source owner: PR #207  
Pinned source-owner head: `eaf03f3b672867ef3a22107e3c03ceeaedfb5ef7`

## Contract

The original remediation-text proposal producer declares a 16,000-character model-output boundary. That boundary must apply to the provider response **before** any whitespace normalization.

The producer may continue to store canonical trimmed remediation prose, but normalization must not turn an oversized raw provider response into an accepted in-bound response.

Required behavior:

- an exact built-in string of exactly 16,000 raw characters is accepted when otherwise valid;
- a raw response longer than 16,000 characters is rejected before `.strip()` can make it appear in-bound;
- ordinary small surrounding whitespace remains compatible with the existing canonical trimmed-content behavior;
- existing empty-content, NUL, role, model-identity and fail-closed authority checks remain unchanged.

## Why this is separate

This acceptance slice is intentionally narrower than nearby work:

- #786 owns exact shared-gateway response-content runtime typing;
- #814 owns remediation-advisor model **input** payload bounds;
- #815 owns remediation-reviewer raw response bounds;
- #816 owns revised-remediation-reviewer raw response bounds;
- #817 owns implementation-planner raw response bounds.

#818 owns only the first remediation-text proposal producer's raw-length-before-normalization invariant.

## Collision boundary

This branch is tests/docs-only and pinned directly above the exact #207 source-owner head. It must not modify `src/lightup/**`.

A future source-owner repair belongs on #207 (or its canonical absorption successor). The preferred minimal ordering is:

1. require the existing canonical response text type contract;
2. reject `len(response.content) > 16_000` before normalization;
3. normalize with `.strip()`;
4. retain the existing non-empty, NUL and canonical digest behavior.

## Safety and authority

The regression uses the existing in-memory recording provider only. It does not contact an external model, network service or target.

No code/config execution, tool call, target interaction, remediation execution, future-state retest, deployment, verdict creation or attack-path mutation is added. All action-authority flags remain false.
