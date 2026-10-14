# Offline LightUp scope review packet — non-authorizing intake lint

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE · NO DEPLOY.**

This optional, **never-installed** Python 3.11+ helper validates only a local JSON **review-packet shape**. It does not validate permission, signatures, owner identity, legal consent, grant recency, network destinations, repository CI or the permanent VPS runner. A well-formed packet is `REVIEW_ONLY`, **not** authorized, approved, safe to execute or release-ready. Both `REVIEW_ONLY` and `HOLD` unconditionally carry five strictly false authority flags. Never use this result as a production executor admission decision.

## Usage (explicit local opt-in, read-only)

```sh
python scripts/check_scope_review_packet_offline.py /path/to/local-packet.json
python -m unittest discover -s tests -p 'test_scope_review_packet_offline.py' -v
```

Accepts only a local regular file, never a URL, up to 16 KiB. Refuses symlinks, named pipes, directories, invalid UTF-8, duplicate JSON keys, nonfinite numbers, BOM, hidden format controls, unknown fields and noncanonical values. Output is fixed-size privacy-safe JSON on stdout with an enum and **no input values**. Exit 0 for shape-only `REVIEW_ONLY`; exit 2 for `HOLD`. Nothing is changed or sent to a remote endpoint.

## Example synthetic packet

This illustrates **unverified references**, not real consent. Do not put secrets or real customer data in repository fixtures. Metadata deliberately excludes IPs, URLs, cookie values, credentials, signatures and purported approval flags.

```json
{
  "schema_version": 1,
  "request_id": "req_123",
  "tenant_id": "tenant_456",
  "asset_id": "asset_789",
  "requester_id": "user_111",
  "authorization_reference": "AUTH-123",
  "scope_reference": "SCOPE-123",
  "requested_mode": "TARGET_ACTIVE",
  "risk_level": 3,
  "requested_capabilities": ["http_headers", "tls_baseline"],
  "review_evidence_digests": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
  "window_start": "2026-10-20T11:00:00Z",
  "window_end": "2026-10-20T12:00:00Z"
}
```

Request, tenant, asset and requester identifiers use 3–64 character ASCII canonical labels. References are 3–128 printable ASCII reference strings; these labels are **not resolved or trusted**. Digests must be 1–8 unique sorted lowercase 64-character hexadecimal SHA-256-shaped values; **their underlying data is not checked**. Requested capabilities are a bounded sorted unique list of known labels. ISO UTC second-resolution windows must be 1 minute to 24 hours; the check does not evaluate *current* time or grant freshness. Mode and risk restrictions are illustrative intake consistency only, not authorization policy. Target-active risk 5 is rejected even for shape review; highest risk remains local-lab-only. Analysis/passive mode cannot claim active-network capability labels.

## Required downstream human and source-owner gates

1. Privately check the original grant, identity, tenant, legal authorization source, asset ownership, target allowlist and time window using independently trusted systems. Review the actual content underlying each purported digest; do not rely on its formatting.
2. Enforce production source-owner preparse scope enforcement, live grant+revocation recheck at dispatch, capability/target gates, step-up and STOP policy. Synthetic examples cannot fix a failing active executor.
3. Require latest-main compatibility, source-owner and independent security/privacy review, original raw hosted CI and **separately registered permanent VPS CI** on the exact immutable HEAD, plus explicit human release approval.
4. Even after approval, a different production component must independently enforce grant and risk. This script will **never issue grants, permits, target scans, deploy or merge**.

The implementation does not import LightUp runtime modules, create network clients or call subprocesses. All 40 unit tests across two independent files are offline synthetic, including 400 deterministic malformed JSON fuzz inputs, all mode/risk combinations, POSIX FIFO denial, 13-field completeness, hostile primitive forms, duplicate/nonfinite JSON, time boundaries, control characters, file type/size/symlink handling and false-only receipts. The script and tests can remain isolated from other workers' production files/PRs.

## W4 local file identity hardening — fail-closed, not attestation

The read-only file intake performs a pre-open local `lstat` (reject symlinks, directories and FIFOs **before** calling `os.open`), then compares device/inode/size/mtime/ctime against the actually opened file descriptor and compares an additional post-read `fstat` snapshot. Bounded same-length tampering and path substitution that change these observed metadata fields produce an opaque `CHANGED_INPUT` HOLD; no private input bytes are logged. This is a race-detection **heuristic**, not a trusted immutable filesystem snapshot or anti-malware/consent proof. In particular a privileged concurrent writer able to preserve metadata could defeat local review consistency, and permission to test assets is **never** inferred. Eight new synthetic unittest methods in `tests/test_scope_review_file_identity_offline.py` cover both readers using deterministic injected metadata changes, symlinks and FIFO non-open behavior. Human and production gates remain unchanged.

## W5 optional POSIX private-file intake policy

For customer-sensitive review preparation, use `--require-private-file` on the **local CLI only**. This opt-in fails closed unless the directly named file is a regular file, owned by the current process's effective UID, has exactly one filesystem hard link, and has **no group or other permission bits** (for example `chmod 600` or `chmod 400`). It checks these conditions before opening, again on the opened descriptor, and after reading. Changing metadata during reading yields a HOLD. Non-POSIX runtimes without `os.geteuid()` fail closed when this mode is requested. The default remains compatible with synthetic fixture files and provides no assurance of file confidentiality. No permission repair (`chmod`, `chown`) is performed automatically. Example:

```sh
chmod 600 /path/to/local-review.json
python scripts/check_scope_review_packet_offline.py --require-private-file /path/to/local-review.json
```

File modes and link counts are **only local privacy hygiene**, not authentic provenance or customer consent; a malicious process with the same UID, inherited directory access, a privileged attacker, permission-changing race, hidden mount permissions or provider-specific filesystem behavior may defeat this heuristic. The result still has all five authority flags `false`. Dedicated synthetic POSIX tests cover insecure 0640/0604/0602, hard links, foreign UID, post-read permissions, malformed policy and CLI privacy-safe HOLD. No user content is echoed.

## W8 private-path ancestor rule

The opt-in `--require-private-file` policy now also walks the lexical parent directory chain with local `lstat` and rejects visible parent-directory symlinks as `PRIVATE_PARENT_SYMLINK`. Paths containing an explicit `..` traversal segment yield `PRIVATE_PATH_TRAVERSAL`. Missing or inaccessible parents yield the fixed `INPUT_UNAVAILABLE` HOLD **without leaking the path or creating a traceback**. This stricter rule is **only** active when the private-file flag is explicitly selected; the default offline review remains unchanged. All three CLIs share this rule through the common reader; ten isolated POSIX test methods cover direct parent links, nested links, traversal, CLI privacy, missing directory and inherited multi-snapshot zero-on-HOLD behavior.

**Limitation:** parent `lstat` checks are observational and non-atomic; another process, mount namespace or a privileged actor may change the path after inspection. This is not a trusted filesystem attestation, verified consent, authenticated tenant association, approved target or authorization for any scan, merge or deployment.
