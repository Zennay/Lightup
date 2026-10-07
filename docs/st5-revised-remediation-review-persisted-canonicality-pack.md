# ST5 revised-remediation review persisted canonicality pack

Tracking issue: #718  
Source owner: #248  
Exact source parent: `546716d6117918dbbb12a0720f7659b6a59ff002`  
Base composition: `chatgpt/st5-revised-remediation-review-integrity-pack-20261007`  
Mode: composition-only tests/docs acceptance

## Existing integrity composition

The base pack already carries exact raw JSON typing, persisted object/type
fidelity, direct-parser caller-input purity and snapshot isolation.

## Added producer-canonical contracts

- #437 canonical VERIFIER `reviewer_model_id` identity;
- #445 canonical producer-trimmed revised-review `summary` identity.

The model-id adversarial cases recompute `review_sha256`; the summary cases
retain the original producer digest to expose normalization-before-digest
verification. The real approved producer review remains the green control.

## Ownership and safety

No production source changes. #248 retains strict persisted review ownership;
reviewer production, live-validation, producer atomicity, upstream proposal and
review-request stages, gateway, scope authorization and target-capable work
remain separate.

Keep PR-less while permanent self-hosted capacity is occupied and the
canonicality cases remain expected RED. No external model invocation, target
interaction, scanning, code/config application, remediation/retest execution,
deployment, verdict creation or attack-path mutation.
