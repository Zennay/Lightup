# ST5 remediation authoring request — resolution/effect lineage acceptance

Issue #419 isolates canonical resolution/effect lineage at the persisted #198
authoring-request boundary.

## Contract

The #196 producer copies resolution and effect lineage from a live-valid
remediation evidence bundle. Persisted requests must therefore preserve
producer-reachable structure rather than accepting arbitrary non-empty text.

Required shape:

- `resolution_id`: exact `transition-resolution:<24 lowercase hex>`;
- `effect_ids`: non-empty;
- every effect identifier is already trimmed, contains no ASCII control
  characters/DEL, and is at most 256 characters.

The regression keeps a canonical WORSENED producer request as a green control.
Every forged case recomputes `request_sha256`, so stale-digest rejection cannot
satisfy the acceptance contract.

## Expected pre-fix result

Seven forged subcases are intentionally RED on current #198:

- wrong resolution prefix;
- wrong resolution suffix length;
- uppercase resolution hex;
- empty effect lineage;
- padded effect identifier;
- control-character effect identifier;
- over-256-character effect identifier.

## Collision and safety boundary

Tests/documentation only. No #198/#196/#60 source or existing tests are changed.
This remains separate from #410 identifier ordering/shape for capability/path,
#412 evidence kind, #414 capability coverage, #416 positive versions, and #418
classification-dependent current-path presence.

No model invocation, target interaction, code/config generation, tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation is introduced.
