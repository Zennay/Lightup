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
29 focused unit/subprocess methods + deterministic mutation, duplicate/temporal/replay/overlong input and no-network-source tests. Dedicated hosted Python3.11/3.14 exact-head workflow is NOT the complete original hosted / permanently registered LightUp VPS CI.

Before ANY integration/release: separately authenticated real client+operator identities; trusted immutable scope/PR snapshots; durable, append-only, privacy-reviewed revocation source; real at-use, concurrency-safe revocation revalidation; source-owner approval; original exact-release-head complete hosted+permanent named VPS CI; independent security/privacy review; and explicit HUMAN GO. Until then: HOLD, no merge/deploy/scan/grant/handlers/release.

## W2: multi-snapshot continuity and externally pinned digest (non-authorizing)

New independent offline timeline reviewer (scripts/review_scope_consent_timeline_1551_offline.py) with dedicated tests. The timeline input is strict JSON with exactly schema_version 1 and entries (2–16; max 128 KiB). Each entry has packet (the original strict v1 claim packet) and previous_sha256. The first predecessor must be null; each later predecessor equals SHA-256 of canonical JSON bytes of the preceding full entry, including the preceding link. UTC review time must increase; proposal SHA, scope SHA, and the full fictional consent pair must remain immutable. Any revocation or malformed packet HOLD.

Two CLI modes:
- Plain stdin timeline: unanchored fictional internal continuity only, REVIEW_ONLY/exit3 if consistent.
- --expected-head followed by one lowercase 64-character SHA-256: verifies that the final canonical entry matches an *externally retained* expected digest, otherwise HOLD/exit2.
- Unexpected flags and invalid pins HOLD/exit2. No mode exits 0; all eight grant/scan/dispatch/merge/deploy/release authority flags remain false.

The caller must independently retain and trust the expected digest: a head digest that arrives with the same untrusted packet is NOT a trust anchor. A deliberate negative regression shows all fabricated entries can be rewritten and all internal digests recomputed to regain REVIEW_ONLY unanchored, whereas the old independent head pin makes that substitution HOLD. Even a pinned consistency result is not proof of real signatures, client/operator identity, complete real-world revocation or any execution permission.

The new code and source-owner boundaries remain isolated: no live scope, activation, grant, DB, worker, shared CI or production changes. Expected proof: **55 focused methods** (29 original and 24 timeline tests), plus 86 existing offline producer integrations, Python 3.14.4 VPS and exact-head isolated hosted Python 3.11+3.14 CI. The hosted ownership fence now allows only SIX new regular Git mode-100644 paths, original main pinned, zero source-file modifications. Permanent named VPS and full original release CI are NOT bypassed.

DRAFT/HOLD. No merge, release, target scan, handler, active execution or grant.

## W3: deterministic adversarial byte-fuzz and digest semantics

The owned Python3.14 zSSH verification has now exercised **3,000 repeatable corrupted timeline byte candidates** (seed 1551, replace/insert/delete/truncate) under a separately supplied original head digest. Exactly 2,998 became HOLD; two harmless inserted JSON whitespace bytes preserved semantically identical canonical claims and were still REVIEW_ONLY. All 3,000 had all eight authority flags literally false. Both behaviors are now encoded as two permanent regression methods; **55 own unit/subprocess methods** pass.

The digest covers canonical JSON **objects**, not the original raw whitespace and presentation. It is not a byte-exact wire signature. A trusted external pin can detect changes to the scope/consent/timestamp claims; it is still unable to prove caller identity, independent consent, revocation completeness, or release authorization.

Original main's existing #301 and #1535 failure modes are separate from this owned reviewer; do not convert any source-owner RED into an expected failure. Own hosted 3.11/3.14 and producer integration proofs remain required for the exact final head.

## W4: independently retained checkpoint + append-only extension

Previously, a final snapshot hash could prove equality to a previously retained exact *end state* but offered no way to review a legitimate new suffix relative to an older retained intermediate snapshot. The new offline checkpoint mode accepts a **zero-based checkpoint index and digest** supplied independently of the untrusted packet. It checks that the canonical full entry at the given index equals the frozen SHA-256, that every later entry remains correctly chained, and that **at least one newer entry exists**; empty replays of the same checkpoint HOLD.

CLI examples for fictional input (not client consent):
- `python3 -I -S -B scripts/review_scope_consent_timeline_1551_offline.py --checkpoint 1:<sha256> < timeline.json`
- `python3 -I -S -B scripts/review_scope_consent_timeline_1551_offline.py --checkpoint 1:<sha256> --expected-head <new_sha256> < timeline.json`
The order and syntax are exact; indexes must be canonical decimal, digests lower-case 64 hex and nonzero. The Python API accepts keyword-only `checkpoint_index` and `expected_checkpoint_sha256` together. Bad/missing/alias/index-at-last-entry arguments HOLD.

Red-before-green tests proved the prior API and CLI did not have this checkpoint mode; regression suite now verifies legitimate append, rewritten history with all internal digests recomputed, an empty suffix, malformed checkpoint identities, and CLI argument variants. **Both externally retained hashes remain unauthenticated assertions unless obtained from independent trusted provenance; an offline match never grants real permission.** No network, sourceowners, shared CI, runners, real targets or production grants changed.

## W5: detached exact bytes of independently provided fictional scope document

The synthetic JSON v1 scope_sha256 previously matched only a self-asserted digest in claim records. A new **opt-in offline binding** now checks SHA-256 of separately supplied exact document bytes against the same claimed scope SHA across every timeline step. Review API accepts scope_document_bytes as an exact nonempty builtin bytes object (max 64 KiB). A byte change, even a trailing whitespace byte, results in HOLD. This binds content *consistency*, not authorship, signatures, trustworthy scope, human approval or authorization.

A separate read-only local CLI (scripts/review_scope_document_binding_1551_offline.py) reads the timeline from bounded stdin and a specifically supplied regular local scope file. Example:

    python3 -I -S -B scripts/review_scope_document_binding_1551_offline.py --scope-document /path/to/fictional-scope.txt < fictional-timeline.json

Optional arguments (exact order) are --checkpoint INDEX:SHA256 then --expected-head SHA256, allowing existing independent history checkpoints and final pins to be combined with exact scope bytes. The CLI blocks symbolic links (O_NOFOLLOW), FIFOs/non-regular files (fstat + O_NONBLOCK), zero-length and >64 KiB files, oversized/invalid timeline streams, ambiguous flags, and changes to file size/inode/mtime/ctime during reading. No network calls, target interaction or disclosures of path, scope document, principal or hash in stdout. All eight authority flags remain false, exit 3 only for REVIEW_ONLY, otherwise 2, never 0.

Real regression before the final fix: a file modified in place *during* a file read was accepted. The validator now checks file identity and metadata again after reading and HOLDs on drift. New subprocess tests cover exact bytes, altered file, stale claim, missing/symlink/FIFO/directory, oversized/empty file, changing inode metadata, manipulated synthetic history and combined checkpoint/head. The source/scope bytes are not copied to a report.

**Safety note:** a caller able to replace *both* the external document and entire untrusted claim history can produce a new self-consistent REVIEW_ONLY unless an independent checkpoint is genuinely retained. Detached file hash correctness is neither legal consent nor runtime authority. Keep in DRAFT/HOLD until genuine independently authenticated separate client and operator approvals, revocation at time of use, privacy/security review, complete original hosted + permanent VPS CI, and explicit human release approval.

## W6: full path-component symlink rejection

A negative real subprocess test showed O_NOFOLLOW on the terminal file alone did not reject a symbolic link in a parent directory, and a path containing a dot component was admitted as equivalent. A dedicated fail-closed path walker now opens each directory by its already-open parent descriptor with O_DIRECTORY + O_NOFOLLOW and then opens the final file by that pinned directory descriptor. It rejects empty, dot, parent-traversal and NUL path segments. Directory descriptors are closed on every error path; only an explicitly supplied ordinary bounded file may be hashed, and no file contents or user pathname are emitted in a receipt.

Original failing cases (a symlinked parent and a dot component) were reproduced before the fix and now PASS alongside the earlier terminal-symlink, FIFO, TOCTOU, privacy and scope-byte tests. This remains unprivileged offline local input hardening and provides no authority to scan or issue grants.
