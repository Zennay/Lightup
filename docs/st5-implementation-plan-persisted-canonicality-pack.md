# ST5 implementation-plan persisted canonicality pack

Tracking issue: #714  
Source owner: #237  
Exact source parent: `f8da50cae174d372be20ccef4a203a766db63618`  
Mode: composition-only tests/docs acceptance

## Included contracts

This pack composes the persisted canonicality boundaries that share the exact
#237 handoff source head:

- #595 — exact built-in raw JSON text;
- #601 — exact built-in direct-object mappings, schema keys, sequence
  containers and persisted strings;
- #665 — post-hash stored-text whitespace canonicality.

Together these contracts distinguish valid producer normalization from strict
persisted identity. Once `plan_sha256` exists, the consumer must neither admit
producer-impossible Python runtime subclasses nor trim altered stored bytes
back into the canonical pre-hash value.

Canonical producer dict/JSON round-trips remain the green controls. The
polymorphic object-shape and post-hash whitespace cases remain acceptance RED
until #237 absorbs the corresponding minimal fail-closed guards.

## Excluded ownership

This pack deliberately does not absorb:

- #358 parser caller-input purity;
- #360 live-validation input atomicity;
- #361 composed parse-to-live chain atomicity;
- nested duplicate-key JSON integrity;
- snapshot isolation;
- producer #277 output bounds/normalization;
- scope authorization, model/gateway, target-capable or execution work.

Those owners remain separate and no production source is changed here.

## Promotion use

Keep this pack PR-less while permanent self-hosted LightUp capacity is occupied
and its adversarial cases are expected RED. After #237 source hardening lands,
restack/reprove this exact pack and require every canonical control and
canonicality regression to be green before promotion.

## Safety

Persistence-integrity validation only. No model invocation, evidence
collection, target interaction, scanning, code/config generation,
remediation/retest execution, deployment, security-verdict creation or
attack-path mutation.
