# ST5 freshness-coverage consumer integrity acceptance pack

Issue #762 composes the collision-free PR #128 consumer-integrity sidecars into
one preferred tests/docs-only proofhead.

## Pinned production owner

The pack is based on exact PR #128 head
`fd5f9c39ae2f1d268b72359b904dc93b1e5e4a57` and changes no
`src/lightup/**` path.

## Included acceptance contracts

- #755 — exact outer persisted runtime types and pre-dispatch rejection;
- #757 — invalid persisted/strict input fails before live validation;
- #758 — rejection-path caller-owned persisted input atomicity;
- #760 — success-path caller-owned persisted input atomicity;
- #761 — typed live-lineage and durable StateStore read-only behavior.

## Expected proof partition

Against the pinned PR #128 source:

- #755's equal-content `str` and top-level `dict` subclass cases are
  intentionally expected RED until #128 replaces broad outer `isinstance`
  acceptance with exact built-in runtime-type checks;
- #757/#758/#760/#761 are intended GREEN controls for ordering, caller-input
  atomicity and read-only live validation;
- any unexpected failure outside the documented #755 subclass gap is a pack
  regression and must not be normalized away.

Direct strict-parser persisted-object exactness remains owned by #619. The
freshness-constraints consumer remains a separate ownership lane.

## Promotion policy

Keep this branch PR-less while the canonical self-hosted queue remains stalled.
After the #128 source owner absorbs the outer exact-type guard and the dependency
chain is available, restack and reprove this exact composition on hosted Python
3.11/3.14 and the canonical self-hosted lane before promotion.

## Safety

Freshness-coverage persistence/live-validation integrity only. No evidence
sufficiency decision, classification, transition, collection, target
interaction, remediation/retest execution, deployment, verdict creation, or
attack-path mutation.
