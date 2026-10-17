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

The pure API is `verify_attestation(raw, secret, now_utc, expected_key_id)`; `now_utc` must be an exact timezone-aware `datetime` in UTC. For an isolated **fictional-only** CLI demonstration, an explicitly inherited file descriptor numbered 3–255 carries the synthetic key. Never supply keys via argv, environment, or user-facing chat. Example (using only a throwaway fake secret and fictional attestation, **not** production credentials):

```bash
PYTHONPATH=src python -m lightup.scope_audit_anchor_auth_offline \
  --synthetic-only --expected-key-id fictional-review-signer-01 --key-fd 3 \
  3< /secure/private/path/to/disposable-fictional-test-key.bin \
  < fictional-mac-receipt.json

PYTHONPATH=src python -m unittest discover -s tests -p test_scope_audit_anchor_auth_offline.py -v
```

Exit code **3** / `REVIEW_ONLY` means only that the fictional MAC and temporal shape validated against the provided key. Exit code **2** / `HOLD` means no approval. `consent_verified`, `authorization_granted` and `release_approved` are always literal `false`. Key material is not logged; there is no routine for copying or persisting it, and Python immutable byte buffers cannot be guaranteed wiped from memory. Use synthetic secrets exclusively for this incubating test.

## Worker ownership and release fence

Only entirely new, independently owned source/tests/docs/isolated CI files on `chatgpt/scope-hmac-anchor-auth-20261017-w1` based on untouched `main`. Separate from active #1556 / PR #1557 checkpoint workers, #1551 two-party review and #554 durable source-owner. No changes to other workers' files, existing workflows, runner registration, production functionality, real grants or target access.

**No merge, deploy, active scan, real consent, grant issuance, handler dispatch or release.** Independent privacy/security review, trusted key management and binding to an authenticated principal, real at-use revocation and real client/operator consent, named VPS exact-head CI, and explicit human GO remain required.
