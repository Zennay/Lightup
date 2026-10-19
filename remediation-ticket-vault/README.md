# LightUp PRIVATE HUMAN Ticket Vault

**Incubate / M3–M7 · PLAN/LAB ONLY · DRAFT/HOLD. No main merge, deployment, scan, grant, authorized remediation, verified retest or release.**

This entirely new, independent `remediation-ticket-vault/` module protects confidential **already produced HUMAN ticket exports** at rest and during private handoff. It complements, but does **not** modify or take over, [offline Ticket Desk #1651](https://github.com/Zennay/Lightup/pull/1651), native original Casework #1568, or original encrypted human source owners #1647–#1649. It can consume a locally downloaded PRIVATE ticket `.md`, ticket bundle `.md`, historical SOURCE HOLD `.md`, or HUMAN workspace checkpoint `.json` as opaque UTF-8 bytes. It never claims to authenticate that content.

## Working operations

Requires local Python 3.11+ and maintained `cryptography`:

```sh
python3 -m pip install 'cryptography>=42,<49'
```

For a no-terminal workflow, **[open the one-file offline browser vault](standalone.html)** or use `index.html` from this intact checkout. All cryptography runs through browser WebCrypto using the **same documented v1 container fields** as the Python CLI: PBKDF2-HMAC-SHA256, AES-256-GCM, canonical authenticated metadata. Browser choices are Encrypt, Decrypt, Rotate, header-only Inspect, or **Memory-only PRIVATE Review**. The one-file distribution embeds only locally hashed JavaScript under a literal CSP with `connect-src 'none'`; there is no upload, localStorage or cookie. The browser deliberately creates a private downloaded file only after the operator confirms the local action. Its separate read-only PRIVATE Review decrypts a single **up to 256 KiB** text handoff to `textContent` in local memory after a separate viewer acknowledgement, without writing a plaintext file. Forget, another source selection or switching operations clears the visible material; previously observed text, screenshots or browser extensions remain outside its control; it cannot enforce filesystem 0600 permissions or inspect the recipient directory, so protect downloads manually. WebCrypto availability depends on a supported secure browser context; use the CLI if it is unavailable. Cryptographic interoperation and browser deployment remain subject to independent security/privacy review, not release certification.

Use an already trusted private workstation and owner-private directory. An original browser download is often group/world readable. Create an actual owner-controlled **0700** private destination directory (not a symlink), move the file there, and **make the input owner-only before invoking the vault**; the CLI refuses unsafe input modes, symlinks, hardlinks and cross-user ownership, and will not publish into a non-private or symlink output directory.

```sh
mkdir -p /trusted/private\nchmod 700 /trusted/private\nchmod 600 /trusted/private/LightUp-PRIVATE-ticket-bundle.md

# Seal; interactive private TTY prompts for a new passphrase twice.
python3 remediation-ticket-vault/vault.py seal \
  --input /trusted/private/LightUp-PRIVATE-ticket-bundle.md \
  --output /trusted/private/human-ticket-handoff.ltv

# Inspect only envelope format, NOT authenticated contents or client authority:
python3 remediation-ticket-vault/vault.py inspect \
  --input /trusted/private/human-ticket-handoff.ltv

# Retrieve plaintext ONLY after independently approved local storage and recipients:
python3 remediation-ticket-vault/vault.py open \
  --input /trusted/private/human-ticket-handoff.ltv \
  --output /trusted/private/human-ticket-restored.md \
  --ack-private-plaintext

# Rotate into a DIFFERENT newly created encrypted artifact, using old then
# a new passphrase, without ever writing plaintext to disk:
python3 remediation-ticket-vault/vault.py rotate \
  --input /trusted/private/human-ticket-handoff.ltv \
  --output /trusted/private/human-ticket-rotated.ltv
```

The operator must keep the passphrase in a genuinely approved separate secret manager. **Lost passphrase = no recovery.** Passphrases are only accepted via a private interactive TTY and are never read from CLI arguments, environment variables or network. New passphrases require at least 14 characters; this is not proof of adequate entropy.

## Concrete integrity and privacy behavior

- **AES-256-GCM authenticated ciphertext**, fresh 128-bit random salt and 96-bit random nonce, PBKDF2-HMAC-SHA256 with 600,000 iterations; both header and encrypted content authenticated as associated data. This is local encryption, **not an authentic sender signature, real identity, consent, grant, original-source authentication, or verified remediation**.
- V1 `.ltv` file layout: fixed binary magic, big-endian 2-byte bounded canonical JSON encryption header, authenticated AES-GCM ciphertext. **Visible header is intentionally anonymous**: version, KDF, iteration count, cipher and random salt/nonce only; no original finding IDs, tenant, client, case title, owner, source hash or path. Filename remains the operator's responsibility.
- Encrypted internal payload embeds a canonical metadata envelope with original UTF-8 type (`.md` or `.json`), exact SHA-256 and byte count, and all security/consent/execution/retest/release authority flags literally `false`. These internal claims are descriptive only; the original content is not parsed, reviewed, verified or declared safe to publish.
- Bounded input (4 MiB plaintext), bounded ciphertext, exact JSON key-set and duplicate rejection, no-follow owner/private regular-file input (`0600` or stricter), no ambiguous/partial reads, mandatory OS `O_NOFOLLOW` support and owner-controlled `0700` output directory, no overwrite, no symlink destination, atomic-to-new-file ownership/permission `0600`, file sync, no leftover final file on write failure.
- **`seal`:** creates only a distinct encrypted file; does not delete the source plaintext. **`open`:** emits new plaintext `0600` only after explicit `--ack-private-plaintext` and successful AEAD/tag/digest/content-type checks. **`rotate`:** emits a separate newly encrypted file from in-memory decrypted content, preserving the old encrypted file; no plaintext intermediates. **`inspect`:** anonymous structural header details only and explicitly states that ciphertext authentication has not occurred.
- All work is completely offline. Does not import LightUp database, network clients, filesystem secrets or authorization implementation, and never issues a GitHub issue, grant, scan or retest command. Does not modify any existing LightUp source-owner, CI, tests or QA file.

**Handling:** encrypted file names and directory metadata may themselves disclose context; choose neutral names. An encrypted `.ltv` sent through an unapproved channel does **not** authorize recipients. Existing source plaintext remains until independently and securely disposed of under the recipient's information handling policy. New decrypted plaintext is sensitive.

**Release posture:** Notion `Incubate / M3-M7 PLAN/LAB ONLY / DRAFT-HOLD`. Main merge or deployment would still require full original hosted plus permanently registered named VPS exact-head CI, original owner and independent security/privacy/cryptography review, issues #177/#182/#829, genuine separate authenticated current client/operator consent including at-use revocation and explicit HUMAN GO. Local encryption, hashes or warnings never stand in for a security grant.
