# ST5 remediation-text proposal persisted canonicality pack

Tracking issue: #715  
Source owner: #209  
Exact source parent: `38c40d112751728c238dcf5d7ab556079528c38e`  
Base composition: `chatgpt/st5-remediation-text-proposal-integrity-pack-20261007`  
Mode: composition-only tests/docs acceptance

## Existing integrity composition

The base pack already carries the strict proposal persisted-boundary proofs for:

- #584 exact raw JSON text type;
- #621 persisted object/key/scalar exactness;
- #641 direct-parser caller-input purity;
- #636 snapshot detachment and post-parse isolation.

## Added producer-canonical persisted contracts

This extension adds:

- #427 canonical gateway-normalized `model_id` identity;
- #439 canonical producer-trimmed proposal `content` identity.

Both adversarial regressions recompute the relevant public digest(s), so
stale-digest rejection cannot mask the missing canonicality check. The real
producer proposal remains the green control.

## Ownership boundary

This pack changes no production source. #209 retains persisted parser source
ownership and #207 retains proposal production. Live-validation atomicity,
producer atomicity, review/revision stages, gateway source, scope authorization,
target-capable code and execution remain separate.

## Promotion use

Keep this extension PR-less while permanent self-hosted LightUp capacity is
occupied and #427/#439 remain expected RED. After #209 absorbs the narrow
canonicality guards, restack/reprove the exact composition and require the
existing integrity controls plus both producer-canonical regressions to be
green before promotion.

## Safety

No external model invocation, target interaction, scanning, code/config
application, remediation/retest execution, deployment, security-verdict
creation or attack-path mutation.
