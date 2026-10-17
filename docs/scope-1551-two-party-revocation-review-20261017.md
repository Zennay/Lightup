# LightUp #1551: two-party consent / revocation continuity (offline review)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NOT AUTHORIZATION.**

## Boundaries
The existing fictional client/operator reviewers #1507 and #1505 remain untouched. This new module checks consistency of a *claimed* pair against one exact claimed proposal Git SHA and one exact claimed scope SHA-256 digest, and insists that any revocation invalidates the packet. No real identity verification, signatures, durable source, actual clock, external references, grants, network, execution or release authority. Unwired from live LightUp. Do not interpret REVIEW_ONLY as permission.

## Version 1 synthetic packet
Strict UTF-8 JSON up to 32768 bytes. Root has exactly schema_version (exact integer 1), proposal_sha (lowercase 40 hexadecimal digits, nonzero), scope_sha256 (lowercase 64 hexadecimal digits, nonzero), review_at (canonical YYYY-MM-DDTHH:MM:SSZ UTC), consents and revocations.

consents has exactly two records, one client and one operator, with exact role/prefixed principal, proposal_sha, scope_sha256, issued_at, expires_at, event_seq. Both reference exactly the same scope and proposal, are issued before review time and have not expired; each lifetime <=24 hours, issuance gap <=15 minutes. Integer sequence is unique and globally temporally ordered.

revocations has 0–32 records each with role, principal, proposal_sha, scope_sha256, effective_at, event_seq. Only a known actor can revoke its record. Any real or hypothetical revocation claim fails review, as do future-dated revocations, timestamp inversions, unknown actors, replays and cross-scope/cross-revision events. A *missing* revocation from a synthetic packet does not establish no real revocation.

All dictionaries require exact keys and canonical types. Duplicate JSON keys, NaN, infinity, invalid UTF-8, oversized/truncated streams, unexpected CLI arguments, invalid identities and invalid time windows HOLD.

## CLI and contract
python3 -I -S -B scripts/review_scope_consent_revocation_1551_offline.py < synthetic-packet.json

Result is exactly a privacy-minimal JSON status and reason plus eight false flags: authorize, grant, scan, handler, dispatch, merge, deploy, release.
- Consistent fictional claims -> REVIEW_ONLY, reason UNAUTHENTICATED_CLAIMS_ONLY, exit **3**.
- Any failure/revocation -> HOLD, reason INVALID_OR_REVOKED, exit **2**.
- It **never exits 0**, never issues a live authorization, and never outputs principal, scope hashes or time details.
- If stdout fails, process returns nonzero, never grants authority.

## Validation and required independent gates
25 focused unit/subprocess methods + deterministic mutation, duplicate/temporal/replay/overlong input and no-network-source tests. Dedicated hosted Python3.11/3.14 exact-head workflow is NOT the complete original hosted / permanently registered LightUp VPS CI.

Before ANY integration/release: separately authenticated real client+operator identities; trusted immutable scope/PR snapshots; durable, append-only, privacy-reviewed revocation source; real at-use, concurrency-safe revocation revalidation; source-owner approval; original exact-release-head complete hosted+permanent named VPS CI; independent security/privacy review; and explicit HUMAN GO. Until then: HOLD, no merge/deploy/scan/grant/handlers/release.
