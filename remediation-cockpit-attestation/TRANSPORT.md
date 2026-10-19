# Encrypted one-file PRIVATE HUMAN Cockpit delivery

This add-on uses the **existing** source-free Evidence Cockpit from original held [PR #1661](https://github.com/Zennay/Lightup/pull/1661), plus a detached HMAC receipt created using `attest.py seal`. It copies **only** the independently admitted anonymous workload summaries; it does not transport original evidence, finding IDs, private HUMAN notes or customer source packets.

## Prerequisites

On trusted Linux devices: Python 3.11+ and a locally approved `cryptography` installation with `AESGCM`. The original native publisher requires Linux `renameat2(RENAME_NOREPLACE)`. Keep the `cryptography` dependency confined to this offline companion—LightUp's base runtime and `pyproject.toml` remain unchanged. Do not let the CLI fetch packages or network resources.

Prepare the original source-free `cockpit/` through the original source owner's workflow. Create a separate 32-byte secret with `attest.py new-key`, then use `attest.py seal` to produce its owner-private detached `cockpit-receipt.json`. All parent directories must exist and be owned by the local operator with `0700` permissions. Key, receipt and encrypted output must be unique owner-private `0600` regular files. Supply literal absolute paths.

## One-command sender (no detached receipt file needed)

If no prior detached HMAC receipt exists, the preferred direct command takes the already-generated original native anonymous cockpit and creates the HMAC receipt **inside the authenticated encrypted package**, without writing an extra plaintext receipt to disk:

```sh
python3 remediation-cockpit-attestation/transport.py send \
  --cockpit "$HOME/private-lightup-workroom/cockpit" \
  --key-file "$HOME/private-lightup-handoff/team-secret.key" \
  --output "$HOME/private-lightup-handoff/operator-cockpit.ltpack"
```

Native admission occurs twice around file reads. The receiver uses the exact same `receive` command. This does NOT add sender identity, authorization or trusted client evidence. Use `pack` below only when reusing a previously signed detached receipt; that path verifies the existing receipt before wrapping it.

## Sender — validated cockpit to one encrypted file

```sh
python3 remediation-cockpit-attestation/transport.py pack \
  --cockpit "$HOME/private-lightup-workroom/cockpit" \
  --receipt "$HOME/private-lightup-handoff/cockpit-receipt.json" \
  --key-file "$HOME/private-lightup-handoff/team-secret.key" \
  --output "$HOME/private-lightup-handoff/operator-cockpit.ltpack"
```

The sender first runs the unchanged native full source-free cockpit admission and HMAC verification, reads the strictly enumerated canonical file inventory, repeats source checks, then encrypts the original manifest, HTML, anonymous JSON files and detached receipt into **one fresh AES-256-GCM package**. Separate HMAC-derived encryption key, random 96-bit nonce, versioned authenticated header and a bounded canonical payload are used. Outputs are exclusive, owner-private `0600`; nothing is overwritten or uploaded.

Transfer **only the encrypted `.ltpack` file** through an approved private route. The **32-byte shared secret must be given to the intended recipient using a separate human-approved trusted channel**. Never put the secret inside or alongside the encrypted file.

## Recipient — decrypt and independently admit the original product

```sh
python3 remediation-cockpit-attestation/transport.py receive \
  --input "$HOME/received-private-lightup/operator-cockpit.ltpack" \
  --key-file "$HOME/received-private-lightup-keys/team-secret.key" \
  --output-parent "$HOME/received-private-lightup"
```

The recipient authenticates the AEAD envelope, canonical schema and HMAC receipt **before writing decrypted files**. It materializes the original source-free files under a fresh `0700` private staging directory, then calls the original unchanged `read_cockpit.inspect` for every manifest checksum, HUMAN count, privacy disclaimer and deterministic HTML reconstruction. Only after native admission can the existing owner-native `renameat2(RENAME_NOREPLACE)` publication promote a unique complete `0700` folder.

The command prints the resulting private directory; it contains `cockpit/index.html` and sibling `receipt.json`. The receipt never enters the strict native cockpit inventory. The offline index may then be opened locally by the authorized human recipient. A rejected incomplete staged directory is cleaned and no previous workroom is modified. Successful work returns exit code **2**; HOLD returns **3**.

## Optional: receive several separately encrypted cockpits together

When several PRIVATE HUMAN operators independently send `.ltpack` deliveries encrypted under the same already distributed team key, use the [private HUMAN Inbox workflow](INBOX.md). It produces one owner-private offline browser index with individual native source-free cockpit links; prior inbox snapshots can be preserved while adding a later delivery through `extend.py`. All original source contexts and HUMAN workloads remain separate and unverified.

## Boundaries

- The `cryptography` package must be deliberately installed in an approved environment. This companion deliberately does not modify core package dependencies or download anything.
- Encrypted delivery gives ciphertext confidentiality only with a separately protected uncompromised key. Both authentication and encryption derive domain-separated keys from the same shared root secret. That secret **does not identify the sender or client**. A holder can create alternative envelopes; this is not a PKI or recipient-access-control system.
- No automatic key expiry, distributed revocation, storage erasure or transport channel is provided. Rotation using `attest.py rotate` does not revoke prior receipts/ciphertext already copied.
- Anonymous cockpit counts are local HUMAN coordination only; they are not findings, verified fixes, retests, signed evidence provenance or customer authorization.
- Source-owner and independent security/privacy/crypto/browser review, exact-head hosted and permanent named VPS CI, #177/#182/#829, authentic current separate client/operator consent with action-time revocation and explicit HUMAN GO remain required before any release. The module is **DRAFT/HOLD, Incubate M3/M7 PLAN/LAB ONLY**, with no network scans, active scope changes, grants, native Apply, main merge or deployment.
