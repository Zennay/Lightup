# LightUp PRIVATE AES-256-GCM export (DRAFT/HOLD)

This new opt-in encrypted-at-rest workflow is separate from the original browser [Handoff Vault #1640](https://github.com/Zennay/Lightup/pull/1640). **The formats are not interchangeable.** It does not change any existing authentication, consent, scanner, QA/CI or production entrypoint.

## Product: directly encrypted original authorized findings

Run in a real interactive terminal with an existing, separately authorized LightUp account, client and engagement. The source selection is authenticated using the original `DomainStore` and existing guarded tenant CSV exporter from parent PR #1611. The original fully validated, canonical private ZIP is created **in process memory**; only encrypted ciphertext is atomically written, mode 0600, to a new `.lue` destination. No plaintext ZIP or partial ciphertext is persisted by this flow.

```sh
python -m lightup.private_export_encrypted create --db /private/domain.sqlite \
  --email existing-operator@example.invalid --client-id AUTHORIZED_CLIENT \
  --engagement-id EXISTING_ENGAGEMENT --output /private/source.lue --ack-private-handling
```

The optional Python dependency is `cryptography`, intentionally installed by the operator in their isolated environment (`python -m pip install cryptography`). Missing dependency fails closed. Each envelope uses **AES-256-GCM**, fresh independent random **16-byte salt and 12-byte nonce**, **scrypt** password derivation (N=32768,r=8,p=1, output 32 bytes), and authenticated version/header/salt/nonce as AAD. Passphrases are entered interactively with `getpass` twice on creation (16–256 characters); length alone does not ensure entropy. The encrypted package contains the sensitive original labels, source digest, finding information and remediation text. SHA-256 of ciphertext is only an **unsigned local checksum**, not an issuer signature or identity/consent proof. Do not place passwords on command lines or in project files.

## Offline lifecycle: source stays encrypted until explicitly opened

```sh
python -m lightup.private_export_encrypted inspect /private/source.lue --ack-private-handling
python -m lightup.private_export_encrypted report /private/source.lue --output /private/aggregate.html --ack-private-handling
python -m lightup.private_export_encrypted workdesk /private/source.lue --output /private/workdesk.html --ack-private-handling --ack-original-identifiers
python -m lightup.private_export_encrypted compare /private/old.lue /private/new.lue --output /private/continuity.html --ack-private-handling --ack-same-real-client
python -m lightup.private_export_encrypted rotate /private/source.lue --output /private/new-key.lue --ack-private-handling
```

Each open authenticates and decrypts strictly in memory, then reuses the original full canonical ZIP/CSV/manifest admission, not an unsafe generic ZIP parser. Failed passphrases, invalid AES tag, malformed version or modified source are refused. `inspect` prints only count aggregates and makes no plaintext files. `report` creates an **unencrypted** ID-free 0600 HTML aggregate; small counts can remain identifying. `workdesk` creates **unencrypted**, original-ID-bearing 0600 interactive HUMAN HTML; optional `--resume PRIVATE.json` requires the original exact source digest and full original ID membership. Local browser-exported workplan JSON is **also plaintext until separately protected**. The two-input `compare` accepts different passphrases, requires independently confirmed same real client/engagement (declared labels alone are not verification), creates a private ID-free HTML and **never calls a disappeared record fixed**. `rotate` decrypts, revalidates, then re-seals exactly the original private ZIP with a new passphrase/nonce/salt, creating a separate ciphertext file without deleting the old copy.

The existing interactive `python -m lightup.private_export_console` now offers these six ciphertext workflows as menu options 8–13 alongside its original seven offline source-bound options. Console confirmation and ZIP labels are **not** proof of authorization or independent client consent. Operators must independently verify the correct recipient, transport, client and engagement, and protect every generated plaintext HTML/JSON.

**Still HOLD:** Notion `Incubate` / M3/M7 PLAN/LAB ONLY DRAFT/HOLD; original parent PR #1611 hosted CI RED from outdated unchecked-export expectations; exact-head hosted and permanently registered VPS CI, original source owners, independent security/privacy, authentic separate current client/operator consent and at-use revocation, #177/#182/#829, and explicit HUMAN GO remain mandatory before any merge or production use. No real customer data, targets, scans, retests, remedial executions or new QA suites were performed.
