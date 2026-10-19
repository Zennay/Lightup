# LightUp · Encrypted Authenticated Casework Handoff

**DRAFT/HOLD · Notion Incubate / M3–M7 PLAN-LAB ONLY.** This is a working source-integrated candidate, **not** production permission, an autonomous scanner, a security verdict, proof of remediation, a real retest or durable client/operator consent.

## The product

One deliberate private-terminal operation performs the complete existing authenticated LightUp finding selection and a **new encrypted Casework handoff** without ever writing an interim plaintext report to the filesystem:

**Current original LightUp account sign-in → original tenant/client and exact engagement selectors → original five-column redacted findings CSV → strict whole-batch Unicode and size admission → original unchanged standalone Casework HTML builder → encrypted in-memory JSON envelope → AES-256-GCM → one new exclusive owner-private `.ltv` file.**

The default restored HTML is the original full self-contained [Casework application from #1568](https://github.com/Zennay/Lightup/pull/1568). Its existing original Casework capabilities (owners, deadlines, bulk changes, source refresh, offline planning) remain untouched. The encryption implementation comes from the existing complete [PRIVATE HUMAN Ticket Vault #1652](https://github.com/Zennay/Lightup/pull/1652) copied byte-for-byte into this **separate branch** above the independently frozen [Ticket Desk #1651](https://github.com/Zennay/Lightup/pull/1651) commit `8b09b7d19da90664092d8e0301aa88408ccdb014`. Neither upstream branch is modified or claimed.

This code adds **only** `remediation-secure-export/` and retains the six original `remediation-ticket-vault/` artifacts copied unchanged. It does not modify `src/lightup/`, existing tests, existing CI, finding evidence, scopes, scanner, tenant data, original Casework files or any other active worker scope.

## Setup

Use a machine/workstation permitted to access your **existing legitimate LightUp database** and client, with Python and the original source checkout:

```sh
python3 -m pip install 'cryptography>=42,<49'
mkdir -p /trusted/private/lightup
chmod 700 /trusted/private/lightup
```

The directory must be owned by the current user and be `0700` or stricter. Both account credentials and new/existing vault passphrases are entered **only interactively in a private TTY**. Never supply secrets in terminal arguments, environment variables or chat. The original persisted user/role/client/grant semantics are **not widened**.

**Existing original CSV source fix composition:** this independent candidate also physically absorbs exact original guarded Unicode/whole-batch CSV source from held [PR #1611](https://github.com/Zennay/Lightup/pull/1611) `7e667173c0b2653600c51d4f0a6c6f56230acf2e` (original `finding_export_service.py` plus canonical checked-export modules) without changing that source owner's branch. The normal authenticated service now uses the original guarded producer as well as the independent additional final handoff validator. This does **not** by itself close #1182/#1193 or provide release approval; the existing source-owner tests and CI gates remain.

### 1. Authenticate and create a new encrypted private Casework, directly

```sh
PYTHONPATH=src python3 remediation-secure-export/secure_export.py export \
  --db /trusted/private/original-lightup.sqlite \
  --email original-operator@example.org \
  --client-id EXISTING_AUTHORIZED_CLIENT_ID \
  --engagement-id EXISTING_APPROVED_ENGAGEMENT_ID \
  --output /trusted/private/lightup/casework-private.ltv
```

The original LightUp account password is requested securely and the existing `DomainStore.authenticate`, `context_for_user`, `render_client_findings_csv` and source-owner `_bundle_workspace` are called **without modification**, including original exact tenant/engagement constraints, original redaction and source-owner HTML. An additional *this-route-only* whole-batch check refuses unexpected columns, duplicate/empty IDs, invalid severities/retest labels, excessively large findings, Unicode controls, bidi/format, line and paragraph separators, and NFKC compatibility forms which would create spreadsheet formula prefixes. It **does not close original issue #1182 across other export routes**; the original producer owners continue to own that integration.

Nothing is written until all original authorization/source admission and full HTML bundling finish **in memory**. A new `.ltv` file is published with the original vault `0600` exclusive/no-follow mechanism in a trusted owner-only directory. The original plaintext `findings.csv` and `casework.html` **are never created during this operation**.

### Recommended: recheck current access AND exact original source before restoring

This is a **new stronger opt-in** route. It does not simply trust an older exported report or a passphrase: it uses the original persisted LightUp account authentication again, resolves the current exact tenant/client/engagement through original `render_client_findings_csv`, applies the guarded original exporter and this route's whole-batch checks, recomputes original CSV SHA-256 and count, then decrypts the snapshot and **requires both current source identities and exact current original CSV content to match** the encrypted old snapshot. If the source changed, an account was revoked, or the client/engagement does not match, **no HTML file is published**. This is *not* genuine client consent or approval to assess a target; it checks only the original currently supported account/tenant/source read authority.

```sh
PYTHONPATH=src python3 remediation-secure-export/secure_export.py open-current \\
  --db /trusted/private/original-lightup.sqlite \\
  --email original-operator@example.org \\
  --client-id EXISTING_AUTHORIZED_CLIENT_ID \\
  --engagement-id EXISTING_APPROVED_ENGAGEMENT_ID \\
  --input /trusted/private/lightup/casework-private.ltv \\
  --output /trusted/private/lightup/casework-current.html \\
  --ack-private-html
```

Both original account and ciphertext passphrase are supplied privately on a live terminal. An old encrypted snapshot **is never silently rebased** to changed findings. Use the original fresh `export` workflow to create a new encrypted snapshot when the source changes. This feature does not alter any original grant, consent, scanner or target code.

### Optional: encrypt the fully populated original Ticket Desk instead

The same authenticated and exact engagement-scoped export can now produce the **complete original source-owned Ticket Desk browser application** with the original summary already loaded (inert base64, opened locally in browser memory). This does not call any new API or bypass the original export. It uses the exact byte-pinned standalone product from held [Ticket Desk PR #1651](https://github.com/Zennay/Lightup/pull/1651) at SHA256 `c5e8c7bd97ba4384fb63e443bd2f9bc155fe39f562633274af071e927122ac3d`, verifies the original embedded CSP hashes, and appends only one separately hash-pinned local source-import bootstrap without weakening `connect-src 'none'`. Unknown original source updates fail closed until reviewed.

```sh
PYTHONPATH=src python3 remediation-secure-export/secure_export.py export \\
  --db /trusted/private/original-lightup.sqlite \\
  --email original-operator@example.org \\
  --client-id EXISTING_AUTHORIZED_CLIENT_ID \\
  --engagement-id EXISTING_APPROVED_ENGAGEMENT_ID \\
  --app ticketdesk \\
  --output /trusted/private/lightup/ticketdesk-private.ltv

# The same open / open-current / inspect / rotate commands also handle Ticket Desk.
PYTHONPATH=src python3 remediation-secure-export/secure_export.py open-current \\
  --db /trusted/private/original-lightup.sqlite \\
  --email original-operator@example.org \\
  --client-id EXISTING_AUTHORIZED_CLIENT_ID \\
  --engagement-id EXISTING_APPROVED_ENGAGEMENT_ID \\
  --input /trusted/private/lightup/ticketdesk-private.ltv \\
  --output /trusted/private/lightup/ticketdesk-private.html \\
  --ack-private-html
```

After approved decryption, open the private HTML locally in a modern browser. The original Ticket Desk source parser then applies its normal full CSV and SHA checks to the memory-loaded source, and the HUMAN ticket editor, private checkpoint, historical HOLD and offline ticket exports work as in the original unchanged app. The decrypted HTML is **not** an authenticated live dashboard: original credentials, consent, token and session are not carried into it. This workflow only avoids an intermediate plaintext export at encryption time; a human-confirmed `open` deliberately creates a sensitive plaintext HTML on disk. Generic standalone Vault browser readers may show an internal JSON envelope instead of the reconstructed original HTML; use this secure-export CLI.

### 2. Privately inspect an authenticated encrypted source — no plaintext file

```sh
PYTHONPATH=src python3 remediation-secure-export/secure_export.py inspect \\
  --input /trusted/private/lightup/casework-private.ltv
```

After your passphrase is entered privately, this validates the original full authenticated AES-GCM ciphertext, the entire source-bound HTML/checksum envelope and all literal false-authority fields, then shows **only original record count and HTML byte size**. It never prints client IDs, engagement, source digests, finding names/titles, owners or evidence, and never writes a decrypted file. This is a local integrity-checked copy only; any client authorization or consent may since have been revoked.

### 3. Rotate to a new confidential vault without any plaintext file

```sh
PYTHONPATH=src python3 remediation-secure-export/secure_export.py rotate \\
  --input /trusted/private/lightup/casework-private.ltv \\
  --output /trusted/private/lightup/casework-rotated.ltv
```

The complete original Casework envelope and unchanged HTML are authenticated in memory before choosing the replacement passphrase. The new key must differ; the original ciphertext remains intact, the new file is exclusive owner-private `0600`, and no intermediate cleartext file is written.

### 4. Later, explicitly retrieve original PRIVATE Casework HTML

```sh
PYTHONPATH=src python3 remediation-secure-export/secure_export.py open \
  --input /trusted/private/lightup/casework-private.ltv \
  --output /trusted/private/lightup/casework-restored.html \
  --ack-private-html
```

After the encrypted vault tag, content type and all original JSON metadata are validated, a **new private 0600 HTML** is created locally. It contains confidential original finding IDs/titles and human planning surface; the saved report is an **offline, unsigned, potentially stale source snapshot**. It is not a new account session or evidence of current consent, grant, client identity, verified fix, retest, or security/production release. Do not share a decrypted HTML by public URL.

### 5. Generic original vault CLI operations

```sh
python3 remediation-ticket-vault/vault.py inspect \
  --input /trusted/private/lightup/casework-private.ltv

python3 remediation-ticket-vault/vault.py rotate \
  --input /trusted/private/lightup/casework-private.ltv \
  --output /trusted/private/lightup/casework-rotated.ltv
```

Rotating produces a new encrypted `.ltv` with a new key and a fresh nonce/salt, without writing the original HTML or JSON as plaintext. The original vault is retained. `inspect` reads format parameters only and **does not authenticate ciphertext**.

The dedicated `secure_export.py inspect/rotate` commands above perform **full original Casework envelope** checks before output, unlike generic vault `inspect` which only reads an unauthenticated anonymous header.

The original [standalone offline HUMAN Ticket Desk](../remediation-ticket-drafts/standalone.html) and [standalone encrypted vault browser](../remediation-ticket-vault/standalone.html) remain separately available. Browser vault apps might show the internal JSON envelope instead of reconstructed HTML; use this dedicated `open` command to restore the original Casework page safely.

## Exact original interfaces and security boundaries

- **Original source-owner authenticated export**: `src/lightup/remediation_handoff_cli.py` and `src/lightup/finding_export_service.py` are unchanged. They resolve the current authenticated role and original tenant/engagement. The extra normalization check is *after*, not a replacement for, their existing permission decision.
- **Original private vault implementation**: `remediation-ticket-vault/vault.py` copied directly from PR #1652; the new route calls its encryption and file-admission helpers without rewriting cipher, KDF, key storage, permission or rotation rules. PBKDF2-HMAC-SHA256 600,000 + AES-256-GCM with header additional data, fresh random salt/nonce and exact authenticated envelope.
- **Opaque internal JSON** (visible only after successful decryption): `lightup.encrypted_authenticated_casework_handoff` v1, original exact CSV SHA-256 and row count, self-declared client/engagement labels (not an identity attestation), SHA-256/size and base64 original owner-built HTML, and all stored release/consent/execution/verification flags strictly **false**.
- **No plaintext intermediary**: source authorized summary, full HTML and JSON envelope exist in volatile process memory until encrypted publication. Like all application memory, memory may be subject to OS swap, process dumps or administrator inspection; this is **not** a secure enclave or guaranteed memory zeroization.
- **No authority transfer**: decrypting old authorized material does not revalidate ongoing operator/client permission or action-time revocation. Before any later actual assessment, independent genuine authenticated client/operator consent and valid grant must be confirmed by the original separate LightUp gates.
- **No live activity**: no network/target assessment, active probes, client file mutation, issue creation, remediation execution, scanner access or verified finding/retest conclusion.
- **No QA work**: no testsuites or regression code added or run. Direct syntax/build inspections are permitted; existing mandatory CI and security/crypto/privacy approval are preserved.

## Release hold

The new encrypted direct-export integration stays **draft/HOLD** until original source-owner acceptance, exact-head hosted plus permanently registered named VPS CI, independent crypto/privacy and tenant-authentication review (including cross-CLI interoperability and scope provenance), existing #177/#182/#829, genuine separate current client/operator approval with action-time revocation and **explicit HUMAN GO**. No main merge or deployment while any original release gate is outstanding.
