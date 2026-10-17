# Fictional audit-tip MAC admission (issue #1558)

**Status:** LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.

This independent, **unwired** standard-library reviewer provides HMAC-SHA256 integrity for a *fictional offline audit-tip attestation* when the verifier already possesses an independently managed symmetric key. It deliberately does not wire into the production grant, activation, scope, web, client, agent, handler, evidence, SQLite or scanner paths, and does not fetch secrets or contact target assets.

## What the MAC proves—and what it cannot prove

A valid MAC means only that the attestation fields were produced by someone with access to the shared 32–64-byte secret (or a component capable of producing that MAC). It does **not** by itself authenticate the real person or organisation controlling the key, verify customer consent, provide asymmetric nonrepudiation, check current revocation, verify the chain content, or authorize a scan/merge/deployment. The key-to-actor mapping, creation, custody, revocation, compromise detection, rotation and distribution are **not implemented**. No HMAC output should be treated as legally or operationally binding consent. The verifier must receive the correct expected key identity and corresponding key from a genuinely trusted, separate channel. This module does not provide a signing API or key generation workflow in the running LightUp app.

In particular: a malicious party that picks both the key and the input can always fabricate a locally valid MAC. Coupling to the existing anchored chain reviewer from [#1556](https://github.com/Zennay/Lightup/issues/1556) requires independent security review; both PRs are DRAFT/HOLD and **neither automatically integrates the other**.

## Exact fictional envelope

UTF-8 JSON object with exactly these seven fields:

- `schema`: exact `LIGHTUP-FICTIONAL-AUDIT-TIP-MAC-V1`.
- `key_id`: ASCII `[A-Za-z0-9_-]{1,32}`; must match independently pinned expected key identifier.
- `tip_sha256`: 64 lowercase hexadecimal characters. This is only a **claim** about a fictional chain tip.
- `nonce`: 32 lowercase hexadecimal characters. Reuse detection **is not implemented**; a nonce does not create anti-replay protection without a separate durable replay registry.
- `issued_at`: exact UTC `YYYY-MM-DDTHH:MM:SSZ`.
- `expires_at`: exact UTC `YYYY-MM-DDTHH:MM:SSZ`, strictly later than `issued_at` and verifier `now`. Maximum attestation lifetime 24 hours; issued time cannot be more than five minutes ahead of verifier `now`.
- `mac_sha256`: HMAC-SHA256 over `b"LIGHTUP-FICTIONAL-AUDIT-TIP-MAC-V1\\x00"` + canonical JSON of the six other fields, sorted keys, separators `(',', ':')`, `ensure_ascii=True`, `allow_nan=False`.

Inputs over 8192 bytes, bad UTF-8, duplicate JSON keys, unknown keys (including forged approval fields), nonfinite JSON, incorrect types, noncanonical timestamps, mismatched key identity, invalid or expired validity window, wrong MAC or malformed key (not exact bytes of 32–64 bytes) all return **HOLD** with no partial data. Comparisons of digest and key id use constant-time `hmac.compare_digest`. No raw JSON, digest, MAC, key ID or secret is printed in the JSON result.

## Invocation without keys in command-line arguments or environment

The pure API is `verify_attestation(raw, secret, now_utc, expected_key_id)`; `now_utc` must be an exact timezone-aware `datetime` in UTC. For an isolated **fictional-only** CLI demonstration, an explicitly inherited file descriptor numbered 3–255 carries the synthetic key. The FD must refer to a regular disposable fixture file or an anonymous pipe; socket/device descriptors are rejected. A non-terminating/unclosed key pipe fails closed after a bounded two-second read budget, rather than hanging the CLI. Never supply keys via argv, environment, or user-facing chat. Example (using only a throwaway fake secret and fictional attestation, **not** production credentials):

```bash
PYTHONPATH=src python -m lightup.scope_audit_anchor_auth_offline \
  --synthetic-only --expected-key-id fictional-review-signer-01 --key-fd 3 \
  3< /secure/private/path/to/disposable-fictional-test-key.bin \
  < fictional-mac-receipt.json

PYTHONPATH=src python -m unittest discover -s tests -p test_scope_audit_anchor_auth_offline.py -v
```

Exit code **3** / `REVIEW_ONLY` means only that the fictional MAC and temporal shape validated against the provided key. Exit code **2** / `HOLD` means no approval. `consent_verified`, `authorization_granted` and `release_approved` are always literal `false`. Key material is not logged; the verifier does not store it persistently, but Python immutable byte buffers cannot be guaranteed wiped from memory. Test the FD with a throwaway key only. The CLI's read timeout is an availability guard, **not** key-custody protection. Use synthetic secrets exclusively for this incubating test.

## Offline in-batch duplicate and chronology review

The additional isolated `scope_audit_anchor_batch_offline.py` reviewer accepts a bounded object with exactly `schema: LIGHTUP-FICTIONAL-AUDIT-TIP-MAC-BATCH-V1` and `attestations: [receipt, ...]`, containing 1–32 individually MAC-verified fictional receipts. Maximum aggregate input is **266,240 UTF-8 bytes** (independent per-receipt 8 KiB bounds also apply). Every receipt must use the same externally pinned fictional HMAC key ID and caller-supplied symmetric key, have a valid unexpired MAC and canonical timestamp, and be strictly chronological by `issued_at`. A duplicated nonce, duplicated tip, replayed whole receipt, forged approval flag, bad MAC, expired record or ambiguous JSON produces atomic `HOLD` without any partial counts. Valid batch returns `REVIEW_ONLY` with count only; it never grants authority.

**Important limit:** This detects duplicates **within one supplied batch only**. No durable/global replay nonce registry, real issuer authentication, monotonic live revocation state, trusted key rotation or content-chain validation exists. A replay in a different batch is not stopped; the signature test is not a complete authorization system.

```bash
PYTHONPATH=src python -m lightup.scope_audit_anchor_batch_offline \
  --synthetic-only --expected-key-id fictional-batch-checker --key-fd 3 \
  3< /secure/private/path/to/disposable-fictional-test-key.bin \
  < fictional-mac-batch.json
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_audit_anchor*offline.py' -v
```

## Conditional cross-batch replay continuity (offline, no durable registry)

An extra **unwired** helper `scope_audit_anchor_replay_update_offline.py` can compare two fictional ledger snapshots against a **previous snapshot hash pinned independently by a trustworthy external channel**. This closes an in-memory review blind spot *only if* that old anchored ledger really is from a trusted custodian; it is **not** a global or production replay database.

The input is one UTF-8 JSON object with exactly `schema`, `before`, `after`, and `incoming`:

- Root `schema`: `LIGHTUP-FICTIONAL-MAC-REPLAY-UPDATE-V1`.
- Each ledger `before` / `after`: exactly `{"schema":"LIGHTUP-FICTIONAL-MAC-REPLAY-LEDGER-V1","key_id":"...","entries":[...]}`; no more than **256** strictly timestamp-ordered entries, no duplicates of nonce/tip.
- Each entry: **only** `nonce`, `tip_sha256` and `issued_at` as exact canonical fictional receipt fields (32/64 lowercase hex and canonical UTC).
- `incoming`: a complete, real synthetic HMAC batch envelope of 1–32 individually valid signed fictional receipts, with unexpired MACs from the externally provided key.
- CLI `--expected-ledger-tip`: an independent lowercase SHA-256 over `b"LIGHTUP-FICTIONAL-MAC-REPLAY-LEDGER-V1\\x00"` plus canonical `before` ledger JSON. The helper `compute_ledger_anchor` only calculates this candidate hash; **it does not authenticate its origin**, and an attacker controlling both the ledger and this expected value can fabricate continuity.
- `after.entries` must equal `before.entries` followed by **exactly** the newly MAC-checked receipt identities. New entries must remain strictly newer than all previous records, with no reused nonce or tip. Any historical rewrite, removal, duplicate, future/expired receipt, malformed input or missing anchor produces atomic `HOLD`.
- Maximum complete input: **524,288 bytes**; independently validated ledger and batch limits still apply.

```bash
PYTHONPATH=src python -m lightup.scope_audit_anchor_replay_update_offline \
  --synthetic-only \
  --expected-key-id fictional-batch-checker \
  --expected-ledger-tip <64-lowercase-hex-previously-trusted-ledger-hash> \
  --key-fd 3 \
  3< /secure/private/path/to/disposable-fictional-test-key.bin \
  < fictional-replay-update.json

PYTHONPATH=src python -m unittest discover -s tests \
  -p 'test_scope_audit_anchor*offline.py' -v
```

**Risk boundary:** No ledger or nonce is persisted, no external anchor is fetched/authenticated, and no atomic real-world storage transaction or cross-process replay lock is implemented. A client **must not** conclude that a global replay was prevented merely because this single offline input produced `REVIEW_ONLY`. The previous ledger would require separate authenticated tamper-resistant storage, immutable versioning, compare-and-swap, signer-to-principal binding and key revocation before any such assurance could be claimed. As elsewhere, consent/grant/release flags always remain `false`.

## Worker ownership and release fence

Exactly ten entirely new, independently owned source/tests/docs/isolated CI files on `chatgpt/scope-hmac-anchor-auth-20261017-w1` based on untouched `main`. Separate from active #1556 / PR #1557 checkpoint workers, #1551 two-party review and #554 durable source-owner. No changes to other workers' files, existing workflows, runner registration, production functionality, real grants or target access.

**No merge, deploy, active scan, real consent, grant issuance, handler dispatch or release.** Independent privacy/security review, trusted key management and binding to an authenticated principal, real at-use revocation and real client/operator consent, named VPS exact-head CI, and explicit human GO remain required.
