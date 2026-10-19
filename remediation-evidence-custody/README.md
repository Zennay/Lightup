# LightUp · PRIVATE Offline Evidence Custody Reconciliation

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an offline, human-only companion to the original Evidence Artifact Ledger and Authenticated Evidence Bridge, not a scan, a vulnerability assessment, a client consent or an authorization decision.

## Delivered
- Imports unmodified original PRIVATE Artifact Ledger v1 or Unified HUMAN Workspace v2 JSON with a 2 MiB ceiling. Rejects duplicate JSON property keys, malformed fingerprints, unknown field shapes, reused original finding/digest pairs, authority flags other than literal false, oversize inventories and incorrect source contract/version. Imports stay local and in memory.
- Compares up to 240 locally picked evidence files (16 MiB each) against indexed original finding ID + local file SHA-256 + length. WebCrypto hashes file bytes locally. Distinguishes exact byte/label agreement, exact byte agreement with different local label, index references absent from the selected local set, same filename with other bytes, and unindexed or oversize selected files.
- Supports optional local folder selection where the browser provides directory picking, plus searchable, status-filtered per-finding HUMAN comparison rows. Automatically invalidates comparisons on any input-file or manifest change, preventing a stale export after a new selection.
- Handles a single local matching file referenced by several original findings without claiming it has independent provenance for each one. Missing from the selection is not evidence missing on another machine or proof of remediation.
- Exports separate **anonymous counts-only CSV** (no source/ID/name/hash) and a user-confirmed **PRIVATE HUMAN source-bound CSV** with finding IDs, SHA-256 and filenames. Spreadsheet formula-style values are escaped. All text remains HUMAN-only observations, never cryptographic authenticity, security verification or custody signature.
- Clears sensitive records from the tab with Forget. Does not send, upload or persist evidence bytes and does not modify an original owner application.

## Build and operate

Open the generated offline [standalone.html](standalone.html) on a trusted private workstation; avoid public downloads, browser extensions and cloud-synced destinations for private client data. Deterministic build using the repository checkout:

    python3 remediation-evidence-custody/build.py
    node --check remediation-evidence-custody/custody.js

The bundler pins the exact inline JS and CSS to a SHA-256-based restrictive CSP. No network, remote assets, workers, or browser persistence. Needs only standard browser file picker and WebCrypto SHA-256. The manifest must come from an original, separately authorized and source-bound PRIVATE Evidence Ledger workflow. This companion itself **does not authenticate** its claimed client/engagement/source information and never assumes that human text or file matching equals true evidence provenance.

## Release and scope

No target requests, real scans, testsuites, grants, consent or existing owner file mutations. This branch is add-only under remediation-evidence-custody. Existing hosted and permanently named VPS exact-head CI, source-owner approval, independent privacy/security/crypto/browser review, original issues #177/#182/#829, independently authenticated current client/operator consent with action-time revocation and explicit HUMAN GO remain mandatory before any release. This standalone stays **DRAFT/HOLD**.
