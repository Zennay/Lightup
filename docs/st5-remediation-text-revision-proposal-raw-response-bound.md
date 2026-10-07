# ST5 revised remediation-proposal raw response bound

Issue: #819  
Source owner: PR #234  
Pinned source-owner head: `7156a6dc00b79c1cfb87c2fe783a957e2e81ecf7`

## Contract

The revised remediation-text producer must apply its 16,000-character response boundary to the provider's raw response before whitespace normalization.

Required behavior:

- an otherwise valid exact 16,000-character raw response remains accepted;
- any raw response longer than 16,000 characters fails closed even if `.strip()` would reduce it to the limit;
- small ordinary surrounding whitespace remains compatible with the existing canonical trimmed revised prose;
- existing empty-content, NUL, role, model-identity and non-executable authority checks remain unchanged.

## Ownership and non-overlap

This contract originated as a tests/docs-only acceptance child and is now absorbed by source-owner PR #234 together with the minimal pre-normalization raw-length guard.

Nearby ownership is distinct:

- #786: shared gateway response-content runtime type;
- #814: remediation-advisor model input payload;
- #815: remediation reviewer raw response;
- #816: revised-remediation reviewer raw response;
- #817: initial implementation-planner raw response;
- #818: original remediation-text proposal raw response.

The source-owner repair belongs to #234 and preserves the existing authority stop line.

## Safety

The regression uses only the existing in-memory recording provider. It performs no external model/network/target interaction and grants no code, tool, target, retest, deployment, verdict or attack-path authority.
