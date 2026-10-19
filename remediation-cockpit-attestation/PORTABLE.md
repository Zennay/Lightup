# Full PRIVATE HUMAN Inbox — encrypted portability across trusted devices

**Stage: Incubate / M3–M7 PLAN/LAB ONLY / DRAFT/HOLD.** This add-on sends one *already fully admitted* offline HUMAN inbox as a single portable **AES-256-GCM ciphertext** to another trusted device with the separately human-distributed team secret. The recipient reconstructs each original native, source-free HUMAN cockpit in a fresh 0700 private folder, verifies every per-slot HMAC receipt and the original rendered HTML/anonymous counts, and then atomically publishes a complete new browser index.

This workflow does **not** export any original evidence artifact bytes, source findings or finding identifiers, free-text HUMAN notes, customer identities, scope grants, verified remediation status, authorized targets, legal decisions or customer consent. It is for anonymous HUMAN follow-up workload coordination only.

## Prerequisites

Use trusted Linux hosts with Python 3.11+, the original unchanged native source-free cockpit modules pinned by PR #1661 and a locally approved copy of `cryptography`. No packages are downloaded or automatically installed. Existing source inbox must already have been created with `inbox.py receive-many` or `extend.py`, then independently admitted using `inbox.py inspect`. Each parent directory must be owned by the current user and have 0700 permissions; individual private encrypted files and keys require 0600. The sender and receiver need the **same separately out-of-band distributed 32-byte shared team key** (not stored inside the ciphertext). Every cockpit in the inbox must be signed with that same key. Never send the key with ciphertext.

## Sending a complete validated inbox as one file

```sh
python3 remediation-cockpit-attestation/portable_inbox.py send \
  --inbox "$HOME/private-incoming/lightup-human-inbox-EXACT-PRINTED-ID" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --output "$HOME/private-incoming/private-team-inbox.ltinbox"
```

The command reads and verifies the complete existing `inbox/` with its current native source-owner inspector, loads only the fixed original source-free manifest/receipt/HTML/JSON members of each slot, and encrypts a bounded canonical envelope into a **new exclusive** 0600 ciphertext file. Each encrypted package uses a fresh 96-bit nonce and a key domain-separated from the individual cockpit encryption and manifest HMAC functions. The original inbox is not modified; no plaintext export intermediate folder or network transfer is created.

The whole encrypted payload is deliberately limited to **32 MiB**. Larger workrooms fail closed without writing the delivery file; they must be reduced to smaller independently admitted inbox snapshots rather than bypassing size limits.

## Receiving on a separate already trusted device

```sh
python3 remediation-cockpit-attestation/portable_inbox.py receive \
  --input "$HOME/private-incoming/private-team-inbox.ltinbox" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --output-parent "$HOME/private-incoming"
```

The receiver AEAD-authenticates and decrypts the bounded 32-MiB envelope, checks canonical strict schema, exact 1–12 slot ordering and each original HMAC against the authenticated source-free manifest **before publishing any plaintext members**. It then recreates each untouched native `slot-XX/cockpit/` with original `receipt.json` inside an entirely new 0700 private temporary workroom. All slots are independently admitted through the unchanged original native `read_cockpit.inspect`; duplicate exact manifest bytes fail closed. The root `index.html`, `summary.json` and local manifest are reconstructed from independently verified native slot counts.

Only after re-inspecting the whole workroom can the original Linux native no-replace atomic publisher expose the new `lightup-human-inbox-<random>` folder. Open its local `index.html` with no web server or network. Existing source, previous inbox snapshots and ciphertext inputs are never overwritten or deleted. A rejected staging directory is cleaned; success exit **2**, HOLD exit **3**.

## Required trust boundaries

Encryption and HMAC authenticate only **possession of the existing shared key**, not the actual sender, original source record, current customer authorization, compliance retention, evidence validity or remediation proof. A stolen team key can forge alternate inboxes; no recipient identity system, cryptographic key escrow, remote deletion, automatic revocation or network transport is implemented. The local counts are *not unique cases and never verified fixes*. No active scans, execution, native Apply, consent mutations, grants or customer data extraction occur.

Release remains **DRAFT/HOLD** until the existing original source-owner, exact-head hosted and permanent named VPS CI, independent security/privacy/browser/crypto review, original #177/#182/#829, separately authenticated current client/operator consent including action-time revocation and explicit HUMAN GO are all satisfied. This add-on cannot replace those gates or authorize main merge/deployment.
