# ST5 remediation-text review persisted canonicality pack

Tracking issue: #716  
Source owner: #220  
Exact source parent: `82126cfccdcef85f51cd5d34cdcccfb05ebe8270`  
Base composition: `chatgpt/st5-remediation-text-review-integrity-pack-20261007`  
Mode: composition-only tests/docs acceptance

## Existing integrity composition

The base pack already carries:

- raw persisted JSON exactness;
- persisted object/key/container/scalar exactness;
- direct-parser caller-input purity;
- snapshot detachment and post-parse isolation.

## Added producer-canonical persisted contracts

This extension adds:

- #432 canonical verifier `reviewer_model_id` identity;
- #441 canonical producer-trimmed review `summary` identity.

The model-identity adversarial cases recompute `review_sha256`. The summary
cases deliberately retain the canonical producer digest to prove that current
persisted normalization can hide altered bytes. In both contracts, the real
approved producer review remains the green control.

## Ownership boundary

No production source changes are made. #220 retains persisted review source
ownership; #217 retains reviewer production. Live-validation atomicity,
reviewer producer atomicity, proposal/review-request and downstream revision
owners, gateway source, scope authorization and target-capable work remain
separate.

## Promotion use

Keep this branch PR-less while permanent self-hosted LightUp capacity is
occupied and #432/#441 remain expected RED. After #220 absorbs the narrow
canonicality guards, restack/reprove this exact extension and require all
existing integrity controls plus both producer-canonical regressions to be
green before promotion.

## Safety

No external model invocation, target interaction, scanning, code/config
application, remediation/retest execution, deployment, security-verdict
creation or attack-path mutation.
