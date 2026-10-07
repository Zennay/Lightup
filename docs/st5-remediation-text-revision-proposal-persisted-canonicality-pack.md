# ST5 remediation revision-proposal persisted canonicality pack

Tracking issue: #717  
Source owner: #238  
Exact source parent: `ef38622caf8c63be34785f971d0526e85740b55d`  
Base composition: `chatgpt/st5-remediation-text-revision-proposal-integrity-pack-20261007`  
Mode: composition-only tests/docs acceptance

## Existing integrity composition

The base pack already carries exact raw JSON typing, persisted object/type
fidelity, direct-parser caller-input purity and snapshot isolation.

## Added producer-canonical contracts

- #435 canonical REMEDIATION_ADVISOR `model_id` identity;
- #443 canonical producer-trimmed revision `content` identity.

The model-id adversarial cases recompute the public revision-proposal digest.
The content cases retain the original producer digests to prove current
normalization can hide altered persisted bytes. The real producer revision
proposal remains the green control.

## Ownership and safety

No production source changes. #238 retains strict persisted handoff ownership;
its producer, live-validation, producer-atomicity, prior review/revision-request,
downstream revised-review, gateway, scope-authorization and target-capable lanes
remain separate.

Keep PR-less while permanent self-hosted capacity is occupied and the
canonicality cases remain expected RED. No external model invocation, target
interaction, scanning, code/config application, remediation/retest execution,
deployment, verdict creation or attack-path mutation.
