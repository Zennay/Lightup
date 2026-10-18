# Scope Schedule Board — offline proposal scheduling

**State:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is a human planning tool, not an authorization, consent, approval, booking, grant, evidence of ownership, security scan, permit, or execution path.

## What is delivered

Open **studio/scope-schedule-board.html** in a modern browser alongside **studio/scope-schedule-board.js**. Both files are self-contained, do not need a web server or credentials, make no network requests, and do not read/write the real LightUp SQLite domain database.

Import up to 20 actual lightup.scope_proposal_draft **v1 JSON files** produced by the independent Scope Planning Studio (draft PR #1567). Each file must be at most 64 KiB. The board does not depend on or modify the original Studio's HTML/JS owner paths; it can be used as an offline companion to the Studio drafts.

The board provides:

- A seven-, fourteen- or thirty-day UTC Gantt-style timeline with proposed interval bars, risk level and view-window clipping.
- A count and readable list of overlaps between supplied **resolved, self-consistent UTC windows**. This is **time-only** comparison, not proof that assets, resources, tenants or people coincide.
- A local-only unavailable-time editor: enter up to 30 unavailable UTC periods (31 days maximum each), remove individual periods, and see them as striped calendar bars; conflicting proposals receive warnings. These blocks are never exported to .ics and cannot imply authenticated staffing capacity.
- Explicit **HOLD** notices for missing, incomplete, ambiguous or non-resolved schedule evidence. Such drafts never produce an event, clash-free assurance, or alternative-time suggestion.
- For every valid proposed interval, a **first possible equal-duration UTC time gap with a 30-minute buffer** relative to the other imported proposals **and the unavailable UTC periods**. No live calendars, owner approval or resource availability is consulted; proposed alternatives are not written back into source files.
- **Interactive what-if scheduling**: choose a resolved imported draft, enter a different UTC start time while keeping its original duration, use its first suggested gap, revert one shift or revert all shifts. Each local edit immediately updates the timeline, warnings, alternate slots and calendar export; the original Studio JSON and stored request are never changed.
- **Bounded multi-draft arrangement**: first-fit reschedules all resolved draft intervals around each other and local unavailable blocks, with a minimum 30-minute buffer. Any proposal requiring more than 31 days of shift fails the entire operation atomically, preserving the earlier what-if scenario. A clash-free speculative proposal never means resources or targets are authorized or free.
- **Scenario restoration**: reload a previously exported review-only scenario only after loading the same number/order of original Studio proposals with exactly matching source UTC start/end and requested risk/mode. Shifted intervals must preserve duration and remain within 31 days of their original; local unavailable blocks are restored atomically. If *any* field is malformed or incompatible, the entire import is HOLD without modifying the active scenario. This is a convenience consistency check, **not cryptographic source identity verification**, and assets/names are intentionally not present in the handoff.
- **Unsigned scenario JSON handoff**: export per-tab ordinal source and proposed UTC intervals, shifted flags, local unavailable windows and overlap counters. Omits client identifiers, actual targets, names, contacts, notes and raw source proposal contents; the file still exposes sensitive scheduling times and is **not portable proof of identity or consent**. Ordinals only refer to the current tab's import order. No scenario is submitted automatically.
- Print-friendly review view and an **anonymized .ics** export. Every exported event is STATUS:TENTATIVE, TRANSP:TRANSPARENT, with synthetic per-export UID and no invitation recipient, attendee or organizer. No assets, tenant labels, personal notes, client name, contacts or source IDs enter the calendar file. It *does* contain the proposed UTC times, which should still be treated as sensitive when shared.

## Usage

1. Obtain v1 JSON exports from Scope Planning Studio. Save them locally on a trusted device.
2. Open studio/scope-schedule-board.html locally, choose up to 20 files.
3. Select a UTC start day and 7/14/30-day horizon (initial load jumps to the earliest imported proposal). Optionally add UTC-local unavailable intervals to model team unavailability. Read the overlapping-window, unavailability and missing/unsafe-window HOLD notices.
4. Optionally apply a local what-if time shift or generate a bounded first-fit scenario for all resolved drafts. For a previous scenario, first import its original Studio drafts in the same order and then restore the local review-only scenario JSON. View the resulting proposed overlaps and export an anonymous scenario JSON for private review. Use the slot suggestions only as conversation starters during independent client/operator review. Export the anonymous **tentative** calendar if needed.
5. For any real proposed scheduling change, edit and re-export the **original Studio draft** and repeat authenticated intake/consent. The schedule board deliberately never changes or approves an existing proposal.

## Import and integrity

The import checks the original v1 schema shape, explicit **false** authority flags (including revocation_checked), requested-mode/risk types and bounds, bounded asset arrays and metadata, a bounded UTF-8 file, real local date components, exact UTC instants of the form YYYY-MM-DDTHH:MM:00.000Z, offset values and exact wall-time/UTC offset consistency. The claimed IANA timezone name is **not authenticated**. A supplied scope_fingerprint_sha256 is validated only for syntax: this board does **not** independently validate that Studio's original canonical fingerprint or any signature corresponds to trusted identities. Import is always considered untrusted and informational. Any corrupted or unknown source structure is rejected or excluded from calendar computations, not repaired.

The board does not parse scope semantics or contact assets and therefore deliberately **cannot** tell whether two clients own the same IP, whether a public endpoint is authorized, whether a CIDR exclusion actually protects a target, whether an operator approved the risk or whether a revocation happened after the draft. It never uses a saved local client/operator session, accesses the network, issues a scan, or calls an execution handler. The DRAFT_ONLY status cannot be promoted through this interface.

## Ownership and release

This feature adds only studio/scope-schedule-board.html, studio/scope-schedule-board.js, and this standalone document. It does not edit source-owner src/lightup/domain.py, scope.py, activation.py, webapp, existing Studio PR #1567 code, operator readiness PR #1569, client intake PR #1571, runner/CI configuration, tests, grants, or the deployed service.

Real use on authorized targets remains separately dependent on authenticated client/operator identities, explicit target ownership, exact approved scope, risk/consent/grant validation, action-time revocation, original full hosted and permanently registered VPS CI, independent security/privacy review and explicit HUMAN GO. This PR must remain **draft/HOLD** and must not be merged or deployed to production merely because an offline calendar exists.

**No QA/regression test suite is added or run for this change.**