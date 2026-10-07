# Scope authorization — persisted assessment-request asset integrity

Issue #877 pins the durable read boundary for `requested_assets_json`.

## Contract

`DomainStore._request_from_row()` must only reconstruct requested assets from a
JSON array containing at least one exact, non-blank string.

The following persisted shapes are producer-impossible and must fail closed:

- JSON objects;
- JSON strings;
- mixed-type arrays;
- empty arrays;
- arrays containing blank asset identities.

Rejection is read-only. Corrupt durable state must not be silently normalized,
rewritten or deleted. Canonical arrays continue to round-trip unchanged.

## Why this matters

Assessment requests are intended to become authorization provenance for
request-to-grant binding (#177). A corrupt row must not be transformed into
apparently canonical scope simply because Python can iterate the decoded JSON
value.

In particular, `tuple(json.loads(...))` must not turn object keys or string
characters into trusted requested assets.

## Expected state on the pinned parent

Pinned parent: `main` at
`1abc16a66fc490b1ba7272890dfbf498482fca9c`.

The canonical array control is expected GREEN. Object, string, mixed, empty and
blank-array cases are intended RED until the durable request reader validates
the decoded shape and members before constructing `AssessmentRequestRecord`.

## Safety and collision boundary

Tests and documentation only. No production source is modified. This slice is
separate from intake asset identity #654, intake risk/mode #875/#876,
approval-decision #133, request-to-grant #177, the active coverage-store chain,
execution, evidence-remediation, deployment, verdict and attack-path work.

The regression uses only temporary SQLite state and performs no DNS/network I/O
or target interaction.
