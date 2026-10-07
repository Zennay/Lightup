# Scope authorization — persisted assessment-request decision provenance

Issue #880 pins lifecycle/provenance coherence at the durable assessment-request
read boundary.

## Canonical state matrix

Open request states are undecided:

- `submitted` -> `decided_by = NULL`, `decided_at = NULL`;
- `under_review` -> `decided_by = NULL`, `decided_at = NULL`.

Terminal decision states carry complete provenance:

- `approved` -> non-blank decision actor + timezone-aware ISO-8601 decision time;
- `rejected` -> non-blank decision actor + timezone-aware ISO-8601 decision time.

Partial decision tuples, stale decision provenance on open rows, blank actors,
malformed timestamps and offsetless timestamps are producer-impossible and must
fail closed.

## Read-only rejection

Validation must not normalize, repair or delete a corrupt durable row. A failed
read leaves the stored `status`, `decided_by` and `decided_at` values
unchanged for forensic visibility.

Canonical submitted and canonically approved requests continue to round-trip.

## Why this matters

Assessment requests are intended to become authorization provenance for
request-to-grant binding (#177). A durable row must not become trusted merely
because its `status` string maps to `RequestStatus.APPROVED`; the corresponding
decision provenance must be coherent too.

## Expected state on the pinned parent

Pinned parent: `main` at
`1abc16a66fc490b1ba7272890dfbf498482fca9c`.

Canonical open/approved controls are expected GREEN. The corrupt-state matrix is
intentionally expected RED because `DomainStore._request_from_row()` currently
reconstructs all three fields independently.

## Collision boundary and safety

Tests and documentation only. No production source is modified. #133 retains
approval-decision source ownership, #177 retains request-to-grant semantics and
#875/#876/#877/#878 retain the adjacent assessment-request provenance slices.

The regression uses temporary SQLite only. It performs no DNS/network I/O,
target interaction, scanning, capability execution, remediation/retest
execution, deployment, verdict creation or attack-path mutation.
