# Current state

LightUp is in **M0 — Genesis + guardrails**, with the product foundation now being expanded beyond the original single-target scaffold.

Current activation mode: **plan-only**.

The repository contains:

- authorization/scope contracts;
- product-level engagement, risk and execution-policy contracts;
- a hard separation between passive prospect discovery and active authorized assessment;
- an extensible security coverage registry;
- run/evidence state and collision-safe capability leases;
- reporting/redaction helpers;
- a loopback-only lab fixture;
- CI safety tests.

Active real-target interaction remains intentionally unimplemented in M0.

## Current product direction

LightUp is a standalone, multi-client web product with:

- an operator/admin dashboard;
- a minimal client portal;
- client-submitted assessment requests;
- operator approval before active execution;
- digital authorization and scope records;
- configurable risk levels with step-up approval;
- future recurring retests for subscription engagements;
- passive-first prospect discovery.

The UI direction is deliberately minimal and uses progressive disclosure. See `docs/ui-principles.md`.

## Safety invariant

`UNAUTHORIZED -> PASSIVE DISCOVERY ONLY`

No real-target active adapter may execute without a current authorization grant and successful scope/risk policy checks.

Canonical project planning and handoff live in the LightUp Notion project pages. zCloud only registers and monitors this repository.
