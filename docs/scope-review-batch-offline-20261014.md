# LightUp offline review packet batch preflight — W3

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/NO DEPLOY.**

This is an independent **optional local shape-and-consistency linter**, not a replacement for the production scope gate or a human authorization decision. It imports only the already-isolated single-packet parser `check_scope_review_packet_offline.py` from its own scripts directory; it does not import the LightUp runtime, open sockets, read a customer system, resolve DNS, authenticate identity, issue a grant, or execute scans.

## Offline review interface

```sh
python scripts/check_scope_review_batch_offline.py /path/to/offline-review-batch.json
python -m unittest discover -s tests -p 'test_scope_review_batch_offline.py' -v
```

The input is one **local regular UTF-8 JSON file**, consisting of **1–32** complete v1 packet objects that each meet the documented single-packet contract. Total input is bounded to **64 KiB**. Symlinks, FIFOs, directories, oversized files, malformed or duplicated JSON keys and nonfinite numbers all fail closed. No target host/IP, credential, customer secret or approval flag is accepted in any item. All examples must use invented tenant/asset references.

Every element must be in canonical ascending **(tenant_id, asset_id, request_id)** order. A batch with a duplicate request ID, a purported authorization/scope reference or digest shared across distinct tenants, or overlapping half-open review windows for the *same tenant, asset and capability*, yields a **whole-batch HOLD**. Adjacent windows (end = next start), distinct capabilities, or distinct assets do not constitute this syntactic collision. Lexicographic window comparison is possible only because the prerequisite single-packet validator has already required exact, second-resolution UTC `YYYY-MM-DDTHH:MM:SSZ` with real dates and strict start/end bounds.

A batch result is one privacy-safe fixed-field JSON receipt: `state` (`REVIEW_ONLY` or `HOLD`), `reason` (one fixed code), `packets_checked` (0 on any HOLD), `non_authorizing: true`, and five flags that **always remain false**: `authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved`, `release_approved`. Exit code is 0 only when the shape is consistent, 2 otherwise. The file's values and private references are never printed. The receipt is neither signed nor trusted and is not suitable for access-control or machine authorization.

## Important limitations / handoff

- References/digests have only **syntactic** identity, not trusted provenance; a valid shape cannot establish ownership, legal consent, requester identity, valid tenant linkage, digest integrity, time freshness, step-up approval or revocation state. Artificially unique references can conceal real-world shared authority; validation never upgrades confidence.
- Half-open window conflict checking is a **review consistency convention**, not a distributed lease or concurrency lock. There is no durable state, TOCTOU prevention, replay database or real-time authorization. Unrelated batches cannot be compared by this helper.
- False-positive HOLDs are acceptable in this narrow preview: an operator must investigate conflicting labels using trusted systems, not relax a live authorization gate.
- Independent original-source owner must enforce authentic grants and revocations immediately before any allowed dispatch. Latest-main compatibility, raw Python3.11/3.14 hosted and permanently registered VPS CI, security/privacy/source-owner review and **explicit human signoff** remain release requirements.
- No changes to `main`, active production owner PR #107, preparse owner #1264, branch isolation #1313, runner, CI workflow, network or targets are part of this feature.

**Never translate REVIEW_ONLY into authorization, permit, scan readiness, merge or deployment.**

## W4 local file identity hardening — fail-closed, not attestation

The read-only file intake performs a pre-open local `lstat` (reject symlinks, directories and FIFOs **before** calling `os.open`), then compares device/inode/size/mtime/ctime against the actually opened file descriptor and compares an additional post-read `fstat` snapshot. Bounded same-length tampering and path substitution that change these observed metadata fields produce an opaque `CHANGED_INPUT` HOLD; no private input bytes are logged. This is a race-detection **heuristic**, not a trusted immutable filesystem snapshot or anti-malware/consent proof. In particular a privileged concurrent writer able to preserve metadata could defeat local review consistency, and permission to test assets is **never** inferred. Eight new synthetic unittest methods in `tests/test_scope_review_file_identity_offline.py` cover both readers using deterministic injected metadata changes, symlinks and FIFO non-open behavior. Human and production gates remain unchanged.

## W5 optional POSIX private-file intake policy

For customer-sensitive review preparation, use `--require-private-file` on the **local CLI only**. This opt-in fails closed unless the directly named file is a regular file, owned by the current process's effective UID, has exactly one filesystem hard link, and has **no group or other permission bits** (for example `chmod 600` or `chmod 400`). It checks these conditions before opening, again on the opened descriptor, and after reading. Changing metadata during reading yields a HOLD. Non-POSIX runtimes without `os.geteuid()` fail closed when this mode is requested. The default remains compatible with synthetic fixture files and provides no assurance of file confidentiality. No permission repair (`chmod`, `chown`) is performed automatically. Example:

```sh
chmod 600 /path/to/local-review.json
python scripts/check_scope_review_batch_offline.py --require-private-file /path/to/local-review.json
```

File modes and link counts are **only local privacy hygiene**, not authentic provenance or customer consent; a malicious process with the same UID, inherited directory access, a privileged attacker, permission-changing race, hidden mount permissions or provider-specific filesystem behavior may defeat this heuristic. The result still has all five authority flags `false`. Dedicated synthetic POSIX tests cover insecure 0640/0604/0602, hard links, foreign UID, post-read permissions, malformed policy and CLI privacy-safe HOLD. No user content is echoed.
