# ST5 remediation authoring request — classification/current-path acceptance

Issue #417 isolates the classification-dependent current-path invariant on exact
active #198 head `7f41af2dcbecd84eee7830cae8b05c6acecdb923`.

## Contract

The producer lineage has two authoring-eligible transition classifications with
different current-path shapes:

- `introduced`: no current attack-path lineage;
- `worsened`: at least one current attack-path id remains.

The strict persisted authoring-request boundary must preserve that distinction.
A caller must not be able to invert the shape and regain a typed request by
recomputing the public request digest.

## Acceptance

The regression keeps canonical INTRODUCED and WORSENED producer requests as
green controls. It then:

1. gives the canonical INTRODUCED item the already-canonical current path from
   the WORSENED control;
2. removes all current paths from the canonical WORSENED item;
3. recomputes `request_sha256` for each forged request;
4. requires both parser calls to fail closed for classification/path semantics.

The path value used for the INTRODUCED forgery is producer-derived so this test
does not overlap #409/#410's identifier-shape and canonical-order acceptance.

## Expected pre-fix result

Both forged cases are intentionally RED on the current #198 parser. The #198
source owner can absorb only the classification/path-presence invariant and
then re-run this exact contract.

## Collision and safety boundary

Tests/documentation only. No #198/#196/#60 source or existing tests are changed.
This is separate from #409/#410 identifier canonicalization, #411/#412 evidence
kind, #413/#414 capability coverage, and #415/#416 positive twin versions.

No model invocation, target interaction, code/config generation, tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation is introduced.
