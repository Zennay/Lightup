# PRIVATE HUMAN Cockpit — detached keyed receipt

This add-only companion provides an **offline integrity/authentication-of-shared-key-possession** layer for the original, **source-free** `remediation-evidence-bundle-integrity/read_cockpit.py` product. It does **not** modify the original Evidence Relationship Desk, encrypted evidence, authorization, webapp, grants, runtime, scanners or existing owner files. Keep **Incubate · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD**.

## Operator flow (trusted devices, offline)

Prepare a **fresh owner-private 0700 directory** outside the canonical cockpit, for example:
```sh
install -d -m 700 "$HOME/private-lightup-handoff"
python3 remediation-cockpit-attestation/attest.py new-key \
  --key-file "$HOME/private-lightup-handoff/team-secret.key"
python3 remediation-cockpit-attestation/attest.py seal \
  --cockpit "$HOME/private-lightup-workroom/cockpit" \
  --key-file "$HOME/private-lightup-handoff/team-secret.key" \
  --receipt "$HOME/private-lightup-handoff/cockpit-receipt.json"
```

Transfer the **original canonical source-free cockpit directory** and `cockpit-receipt.json` privately to the intended receiver. Transfer the 32-byte secret **through an independent trusted channel**, never inside the cockpit or alongside its receipt. The destination must recreate owner-private 0700 parent directories, 0600 ordinary files, and preserve the native canonical cockpit's exact filename inventory. No uploading or network transfer is performed by this module.

On the receiving device, with the correct out-of-band shared key:

```sh
python3 remediation-cockpit-attestation/attest.py verify \
  --cockpit "$HOME/received-private-lightup/cockpit" \
  --key-file "$HOME/received-private-lightup-keys/team-secret.key" \
  --receipt "$HOME/received-private-lightup/cockpit-receipt.json"
```

**Success exits 2. HOLD exits 3** with deliberately generic errors. A receiver first checks the keyed HMAC over the exact canonical original `manifest.json` bytes. It then calls the unchanged native `read_cockpit.inspect` to validate exact owner-only file inventory, all SHA-256 content descriptors, anonymous stage schema, disclaimers and completely regenerated scriptless HTML. It rechecks the manifest after admission. The original cockpit remains unchanged; detached receipt is written exclusively as 0600 with no overwrite. Wrong key, modified manifest, missing content, changed native HTML or non-private/cross-owner files => HOLD.

## Encrypted one-file cockpit transfer (recommended for PRIVATE handoff)

[**Complete send/receive guide**](TRANSPORT.md) documents the new offline AES-256-GCM transport, including separate out-of-band key delivery, original manifest/HMAC verification, native fail-closed HTML/JSON re-admission and exclusive atomic owner-private recipient publication. Use `transport.py send` (one command), or `pack` with an existing detached receipt, followed by `transport.py receive`; original standalone HMAC flow above remains available. This companion requires an approved local `cryptography` installation on Linux; **no network install or runtime dependency is added**.

## Encrypted HUMAN team inbox and immutable history

[**INBOX.md**](INBOX.md) describes `inbox.py receive-many` (atomic private review workroom for 1–12 encrypted source-free HUMAN cockpits), `inbox.py inspect` (original native admission of every source-free member), and `extend.py` (append new encrypted deliveries as an entirely NEW immutable inbox snapshot, preserving original source and prior snapshots). The local browser `index.html` links each separately authenticated slot without blending client identities, evidence, findings or verified fixes. All files remain offline, owner-private and non-authorizing. One previously distributed 32-byte team key is required for all included packets.

## One encrypted portable complete team inbox

[**PORTABLE.md**](PORTABLE.md) documents `portable_inbox.py send/receive`: seal an already fully admitted 1–12 slot source-free PRIVATE HUMAN inbox into one bounded AEAD ciphertext (up to 32 MiB); on the second trusted device independently authenticate all original native HMAC/HTML/JSON members and reconstruct one new atomically published browser-ready owner-private inbox. This transmits only anonymous HUMAN work coordination and requires separately human-delivered team key, not sender identity or consent.

## NEW: encrypted HUMAN owner assignments, calendar and portable full workroom

[**COORDINATION.md**](COORDINATION.md) documents the independent fully offline HUMAN workflow built on originally validated source-free team inboxes: `coordination.py start/revise/overview/publish` creates immutable encrypted slot assignments, priority, due dates and PRIVATE notes with a scriptless HTML board; `agenda.py` provides privacy-minimal tentative all-day calendar or anonymous date counts; `carry.py` preserves original local HUMAN actions when an exact-prefix inbox is expanded; `workroom.py send/receive` transports the original source-free inbox **and its bound encrypted PRIVATE plan** as a single AES-256-GCM workroom; and `workroom_control.py inspect/revise` admits or publishes a **new complete immutable browser-ready workroom version**. No original source evidence, client consent, grant or security verdict is created or changed. These are separately reviewed offline companion tools, not production release authority.

## Rotate an existing trusted shared-key receipt without changing the cockpit

After generating a separate NEW 32-byte key in a different private keyfile, rotate only an already-authenticated cockpit. Rotation authenticates the **old** receipt with the original secret and native reader first, then binds the **same manifest bytes** to the new key with a new exclusive detached receipt. It refuses identical old/new key material and never overwrites the old receipt. The old key/receipt remain available for prior devices until a human separately revokes them. This procedure does **not** itself revoke a leaked key or invalidate previously copied receipts.

```sh
python3 remediation-cockpit-attestation/attest.py new-key \
  --key-file "$HOME/private-lightup-handoff/team-secret-2.key"
python3 remediation-cockpit-attestation/attest.py rotate \
  --cockpit "$HOME/private-lightup-workroom/cockpit" \
  --old-key-file "$HOME/private-lightup-handoff/team-secret.key" \
  --old-receipt "$HOME/private-lightup-handoff/cockpit-receipt.json" \
  --new-key-file "$HOME/private-lightup-handoff/team-secret-2.key" \
  --new-receipt "$HOME/private-lightup-handoff/cockpit-receipt-2.json"
```

Trusted operators can confirm they received the **same shared key** through an independent call on each device, without printing the key:

```sh
python3 remediation-cockpit-attestation/attest.py key-fingerprint \
  --key-file "$HOME/private-lightup-handoff/team-secret-2.key"
```

The short pairing hint is not a signature, authenticated identity or consent. Do not treat it as a substitute for verification of the full native cockpit and detached HMAC.

## Guarantees and non-guarantees

- HMAC-SHA256 with 256-bit random local key; a fixed domain separator and length-delimited exact manifest bytes; constant-time MAC comparison.
- Key file creation is exclusive `0600` under an existing `0700` owner-private directory. Reading requires one regular owner-only non-symlink, single-link, exact 32-byte file. Key bytes never appear in JSON or CLI output.
- Detached receipt is a canonical bounded JSON envelope with exact fields and no customer IDs, original findings, notes or underlying evidence bytes. Its digest refers only to the existing anonymous cockpit manifest.
- This confirms **that someone holding the out-of-band shared key signed these delivered manifest bytes**, *not which person signed them*. A copied/compromised key can sign forged content. It does not establish trusted original evidence, source provenance, reviewer identity, current access, customer consent, authorization, grant/revocation, a verified fix, validated retest, compliance retention or release permission.
- The HMAC is not encryption. Treat the source-free cockpit itself as private; the sender/recipient must separately handle transport/access and key rotation. For stronger authenticated identity, use a reviewed asymmetric-signature/identity scheme under independent security/crypto review, not assumptions about this shared secret.
- Preserve original exact-head hosted and named VPS CI, independent owner/privacy/browser/crypto/security reviews, #177/#182/#829, real separately authenticated current client/operator consent with revocation-at-action and explicit HUMAN GO. No main merge or deployment without those existing gates.

## Scope of this PR

Entirely new `remediation-cockpit-attestation/` paths only. Original cockpit source owner remains on its pinned DRAFT/HOLD PR #1661; this is a companion branch stacked on original source head `35c5d0bad2ba16883cb4ef991412112b529676f1`, not a competing edit. No QA suites are authored or invoked by this work.
