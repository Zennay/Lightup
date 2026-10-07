# ST5 evidence-collection consumer integrity acceptance pack

Issue #753 composes the collision-free PR #136 consumer-integrity sidecars into
one preferred tests/docs-only proofhead.

## Pinned production owner

The pack is based on exact PR #136 head
`931d71ad393df9cdfbcc3e068e65c20f3c0a7227`. It changes no
`src/lightup/**` path.

## Included acceptance contracts

- #747 — exact outer persisted runtime types and pre-dispatch rejection;
- #749 — persisted/strict rejection completes before live-lineage validation;
- #750 — rejection-path caller-owned persisted input atomicity;
- #751 — success-path caller-owned persisted input atomicity;
- #752 — typed live-lineage and durable StateStore read-only behavior.

## Expected proof partition

Against the pinned #136 source:

- #747's equal-content `str` and top-level `dict` subclass cases are
  intentionally expected RED until #136 replaces broad outer `isinstance`
  acceptance with exact built-in runtime-type checks;
- #749/#750/#751/#752 are intended GREEN controls for ordering, caller-input
  atomicity and read-only validation behavior;
- any unexpected failure outside the documented #747 subclass gap is a pack
  regression and must not be normalized away.

The pack deliberately does not absorb direct #64 parser exactness (#611/#746),
request snapshot isolation (#318), direct parser input purity (#323/#329), or
production source ownership.

## Promotion policy

Keep the pack branch-only while root #62 canonical LightUp CI remains queued.
When the dependency chain and permanent runner lane open, first absorb the
runtime-type repair at the #136 source owner, then restack/reprove this exact
composition against that resulting head. Do not promote from expected-RED or
hosted-only evidence.

## Safety

Persistence/live-validation integrity only. No evidence collection,
capability/tool selection, target interaction, remediation/retest execution,
deployment, classification, verdict creation, or attack-path mutation.
