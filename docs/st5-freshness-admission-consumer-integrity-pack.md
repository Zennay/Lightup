# ST5 freshness-admission consumer integrity acceptance pack

Issue #768 composes the collision-free PR #141 consumer-integrity sidecars into
one preferred tests/docs-only proofhead.

## Pinned production owner

The pack is based on exact PR #141 head
`cfa22936bb2e3fc95665a0a032143d708a4568fe` and changes no
`src/lightup/**` path.

## Included acceptance contracts

- #763 — exact outer persisted runtime types and pre-dispatch rejection;
- #764 — invalid persisted/strict input fails before live validation;
- #765 — rejection-path caller-owned persisted input atomicity;
- #766 — success-path caller-owned persisted input atomicity;
- #767 — typed live-lineage and durable StateStore read-only behavior.

## Expected proof partition

Against the pinned PR #141 source, #763's equal-content `str` and top-level
`dict` subclass cases are intentionally expected RED until the outer
`_persisted_payload()` boundary uses exact built-in runtime-type checks.
#764/#765/#766/#767 are intended GREEN controls for ordering, input atomicity
and read-only live validation.

Direct strict-parser persisted-object exactness remains owned by #613.

## Promotion policy

Keep this branch PR-less while the canonical self-hosted queue remains stalled.
After source-owner absorption and dependency unlock, restack and reprove the
exact pack head on hosted Python 3.11/3.14 and the canonical self-hosted lane
before promotion.

## Safety

Freshness-admission persistence/live-validation integrity only. No
suitability/sufficiency, classification, transition, collection, tool/target
execution, remediation/retest, deployment, verdict or attack-path authority.
