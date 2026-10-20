# LightUp offline software custody signatures — DRAFT/HOLD

An independent **new-only** signing and recipient workflow for the original PRIVATE
software-only.zip produced by the **held** remediation-integrated-workspace/ source
branch. This folder changes no original receiver, evidence, scanner, grant, CI,
tenant or worker-owned source file. It is not included in the original portable
ZIP and does not require the original product to adopt the signer.

## What is actually authenticated?

Ed25519 verifies that **these exact ZIP bytes** were signed by a holder of the
private signing key corresponding to a **separately trusted public-key fingerprint**.
The signer produces a small canonical JSON sidecar containing the exact ZIP SHA-256,
byte length, purpose, schema and domain-separated 64-byte signature.

The receiver must obtain the public key **and its SHA-256 DER/SPKI fingerprint through
a trustworthy, separate channel**; a fingerprint supplied inside an untrusted
handoff is not trust. SHA-256 here identifies exact bytes; the digital signature,
not the unsigned digest, is the authenticity check.

This does NOT authenticate the original GitHub/source owner, ensure actual client
or operator identity, verify consent, confer permission to scan/apply, or satisfy
security review, exact-head CI, remediation or release gates. A signer could sign
an unsafe or unapproved ZIP. The original source-lock receiver is a **second**
independent gate and still yields REVIEW_ONLY / DRAFT/HOLD.

## Dependencies

Requires Python 3.11+ and an independently installed cryptography package.
For a disposable, local offline venv install from a previously approved and
available package source using requirements.txt. This tool **never installs**
packages, contacts a package index or accesses targets by itself.

## Owner: create an encrypted keypair locally

    python3 remediation-package-signatures/offline_signatures.py keygen \
      --directory /ABSOLUTE/PRIVATE/PATH/new-signing-keys

The key directory must be fresh; private and public files are created without
overwrite at mode 0600 inside a new mode 0700 directory. The private key is
encrypted with the interactively entered passphrase (at least 12 characters);
it is never accepted in command arguments, logs or ENV. Preserve it securely
and share **only the public key and a separately verified fingerprint**.

## Owner: sign an existing original software-only ZIP

First run the original offline build in a separate owner-only area.
Never bundle customer evidence/credentials in the software archive.

    python3 remediation-package-signatures/offline_signatures.py sign \
      --archive /ABSOLUTE/PRIVATE/PATH/software-only.zip \
      --private-key /ABSOLUTE/PRIVATE/PATH/new-signing-keys/signing-private.pem \
      --receipt /ABSOLUTE/PRIVATE/PATH/software-only.lusig.json

The receipt is published as a **new** 0600 file; overwrite, existing path and
symbolic-link input are refused. Only previously built regular local ZIP bytes
up to 32 MiB are admitted. Signing makes no release assertion.

## Recipient: verify signature (without extracting)

    python3 remediation-package-signatures/offline_signatures.py verify \
      --archive /ABSOLUTE/PRIVATE/PATH/software-only.zip \
      --receipt /ABSOLUTE/PRIVATE/PATH/software-only.lusig.json \
      --trusted-public-key /ABSOLUTE/PRIVATE/PATH/signing-public.pem \
      --trusted-fingerprint 64-lowercase-hex-trusted-out-of-band

A successful verification prints VERIFIED for the exact signed ZIP **only** and
exits **2 = REVIEW_ONLY**, intentionally not a release-success 0. Every HOLD
(including changed ZIP, malformed receipt, changed key, forged signature or
unexpected digest) exits **3** and produces no extracted files.

## Recipient: one command verify → original atomic source-only receive

Use an **already-present original, unchanged repository source checkout** and
a fresh output directory under an owner-private parent. The original native
receiver enforces its own pinned source inventory, owner-only ZIP inputs, 0700
directory / 0600 files, atomic no-overwrite publication, and local inspection.

    python3 remediation-package-signatures/verified_receive.py \
      --archive /ABSOLUTE/PRIVATE/PATH/software-only.zip \
      --receipt /ABSOLUTE/PRIVATE/PATH/software-only.lusig.json \
      --trusted-public-key /ABSOLUTE/PRIVATE/PATH/signing-public.pem \
      --trusted-fingerprint 64-lowercase-hex-trusted-out-of-band \
      --output-dir /ABSOLUTE/PRIVATE/PATH/fresh-received-suite

This invokes signature verification **before** original receiver ZIP parsing
and publication, then invokes original installed source-lock inspection.
The two verifiers are independent; neither authenticates contemporary customer
identity or consent. No private key crosses to the recipient. No network.

## Limits and operational risks

- Password/key loss cannot be recovered; do not store the private PEM in Git.
- A passphrase protects keys at rest but not a compromised host or memory.
- The locally verified public key requires **out-of-band origin validation**.
- Self-signed receipts, even if cryptographically valid, do not imply independent
  code review or security approval.
- The ZIP signature binds complete compressed bytes, not semantic correctness;
  original receiver checks original member inventory and pinned source bytes.
- A modified upstream integrated studio needs its **own** original receiver
  review, lock and compatible signer/recipient composition. Do not silently
  restack or absorb currently claimed upstream source.
- Only use on source-only offline software. Do not include real client evidence,
  secret material or private HUMAN notes in this signature receipt workflow.
- No QA/regression/test suites are shipped or run here.

**Posture:** Notion INCUBATE, M3/M7 PLAN/LAB ONLY, DRAFT/HOLD. Hosted
and permanently registered exact-head VPS CI, independent privacy/security/crypto
review, original source-owner sign-off, #177/#182/#829 where applicable,
separately authenticated current client and operator consent with use-time
revocation, and explicit HUMAN GO remain unchanged release requirements.
