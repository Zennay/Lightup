# LightUp · Offline scope withdrawal coordination desk

## Product delivered

Open `withdrawal-desk/index.html` from this branch in a modern browser. No web server is required. The desk is a **local, non-authorizing human preparation tool** for recording a request to stop proposed activities, narrow a proposed scope, postpone a planning window or withdraw an evidence-sharing request. It cannot determine whether a valid grant exists, revoke a grant, authenticate an actor, read operational state, stop handlers, cancel a real booking or trigger an assessment.

### End-to-end user workflow

1. Locally import up to 16 **original** `lightup.scope_proposal_draft` version-1 files produced by Scope Planning Studio [PR #1567](https://github.com/Zennay/Lightup/pull/1567). The maximum is 65,536 bytes per source. Files are read with fatal UTF-8 decoding, checked as syntactically bounded `DRAFT_ONLY` documents and fingerprinted by SHA-256 of the *actual source bytes* using local Web Crypto. Import across a selected group is atomic. Matching exact fingerprints reattach an existing restored case; conflicting derived source metadata HOLD. An unsigned SHA-256 does not prove actor, provenance or consent. Inputs remain untrusted even when they pass a shape check.
2. Choose a case. Record a human stop/narrow/postpone/share-withdraw intent, claimed priority, optional **manually supplied UTC** requested instant, private reference and brief private note. Press **Prepare**. Neither action changes a production scope or target.
3. Use the eight-lane human worklist: separate client identity/channel, independent operator contact, active-work stop request, actual grant owner/revocation check, scope/schedule follow-up, evidence privacy handling, independent acknowledgment and authoritative incident record. Track only `todo`, `drafted_local` or `requested_unverified`. No state claims confirmed authorization, live revocation or completed execution stop.
4. Download **pseudonymous REVIEW_ONLY JSON** or a **formula-resistant CSV action queue**: only original source byte digests, numeric scope counts, risk, requested coordination type, priority, claimed UTC and generic follow-up codes/statuses. No raw assets, client label, filename, note, contact, grant or authenticated actor identity. Exports contain literal false flags for client/operator authentication, approval, consent, authorization, grant, revocation, stop, dispatch, scan, deploy and release. They are not API payloads.
5. Optionally save a **private local JSON workspace** with per-case notes and labels. This document may be sensitive. On reload all cases are **UNBOUND** until the exact original Studio files have been reattached; public source-bound exports HOLD while unbound. Use a protected location. No localStorage, cookies, IndexedDB or backend save occurs.

An urgent operational STOP request must go through the **real independently authenticated client/operator contact path immediately**. Preparing, printing, saving or emailing a local draft never proves that a live scan, grant or scheduler has stopped. This desk deliberately cannot issue or cancel anything.

## Security, privacy and limitations

- No network calls, fetch, image loads, external scripts, remote assets, analytics, telemetry, credentials, active target probes, storage or service integrations. CSP denies network and forms; JS and CSS are local. Browser file download only on user action.
- Untrusted imported JSON is rendered with `textContent`/DOM nodes, never `innerHTML`; source field shape/type and sizes are bounded; exporting raw source content is intentionally unsupported.
- Current browser JSON.parse does **not** reject duplicate JSON keys. This is a structural intake interface, not a trusted authorization parser; never treat it as one. Its parser likewise does not verify the embedded unsigned Studio scope fingerprint or validate network/UTC source semantics as a canonical source owner would.
- The private session contains unverified metadata and user-entered notes, and is **not encrypted**. Use the separate private encrypted Scope Vault [PR #1574](https://github.com/Zennay/Lightup/pull/1574) for local encrypted storage after normal human review. No integration, import/export compatibility, key sharing or consent is asserted between these isolated PRs.
- `requested_effective_utc` is a *human-supplied claim* interpreted as UTC by UI convention, not a verified, timezone-aware agreement. Source Studio draft windows are displayed only by a coarse status string.
- Review-only exports use source SHA-256 as a *pseudonymous* correlation token. Do not treat a SHA as an anonymous guarantee: parties holding the same source may correlate exports.
- Saved private session restore refuses malformed tracked values and unbinds all sources. It does not preserve original file bytes. It is not a trusted journal or tamper-resistant chain.
- No actual post-approval narrowing/stop is safe until source owners implement a real authenticated request-to-grant link, at-use revocation, independent authorized operator path and explicit human GO.

## Isolation & release

Entirely new owned paths: `withdrawal-desk/index.html`, `withdrawal-desk/style.css`, `withdrawal-desk/desk.js`, `docs/scope-withdrawal-coordination-desk.md`. Does **not** edit source owner files `src/lightup/**`, webapp, domain/grant, engagement, activation, AI handlers, tests, workflows, CI, deployment, runner or any active Studio/coordination/Vault branches.

**Current project posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** No merge to production, deploy, live scans, grants, revocations or handler dispatch. Independent security/privacy review, source-owner integration with authenticated client/operator consent and revocation-at-use, original hosted + registered permanent VPS exact-head CI, and explicit HUMAN GO are mandatory before any operational authorization work. No QA/regression/test suite was authored or run for this branch; source syntax inspection is not release evidence.
