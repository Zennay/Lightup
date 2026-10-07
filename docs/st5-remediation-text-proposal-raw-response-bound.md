# ST5 remediation text-proposal raw response bound

Issue: #818  
Source owner: PR #207  
Pinned original source-owner head: `eaf03f3b672867ef3a22107e3c03ceeaedfb5ef7`

## Contract

The original remediation-text proposal producer declares a 16,000-character model-output boundary. That boundary must apply to the provider response before whitespace normalization.

Required behavior:

- an exact built-in string of exactly 16,000 raw characters is accepted when otherwise valid;
- a raw response longer than 16,000 characters is rejected before `.strip()` can make it appear in-bound;
- ordinary small surrounding whitespace remains compatible with canonical trimmed-content behavior;
- existing empty-content, NUL, role, model-identity and fail-closed authority checks remain unchanged.

## Composition

PR #234 is an ancestry-safe descendant of PR #207, so this acceptance is also carried on the #819 branch as the preferred combined reproof head for the original + revised remediation prose producers.

## Safety

The regression uses the existing in-memory recording provider only. It does not contact an external model, network service or target and grants no code/tool/target/retest/deployment/verdict/attack-path authority.
