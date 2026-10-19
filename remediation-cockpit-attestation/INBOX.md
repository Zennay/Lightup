# PRIVATE encrypted HUMAN Inbox — team reception and immutable continuity

**LightUp Incubate · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** This tool is an offline, non-authorizing companion to the original source-free Evidence Cockpit on held PR #1661 and keyed/encrypted companion PR #1662. It **does not import source evidence, customer names, client authorization, findings, private notes or verified remediation state**. All reported totals are local HUMAN follow-up counts, *not unique cases or proven fixes*.

The product is useful when a HUMAN coordinator receives multiple independently prepared `.ltpack` ciphertexts, rather than one existing combined original cockpit. It validates every encrypted delivery, constructs each original cockpit separately, and publishes **one index.html** linking to every separately admitted original source-free cockpit. No finding rows are merged across clients or source revisions. Exact repeated source-free manifests fail closed instead of double-counting identical delivered summaries.

## Receive 1–12 encrypted packets as one private workroom

Each input must already exist as a `0600` owner-private encrypted `.ltpack`, created using the original `transport.py send` or `pack`. The current team must **separately possess the same 32-byte shared key** at a trusted `0600` path; it must never accompany the ciphertext. The output parent must already be a trusted local absolute directory with owner `0700` permissions. Python 3.11+ on Linux and locally approved `cryptography` are required; nothing is downloaded automatically.

```sh
python3 remediation-cockpit-attestation/inbox.py receive-many \
  --package "$HOME/private-incoming/operator-01.ltpack" \
  --package "$HOME/private-incoming/operator-02.ltpack" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --output-parent "$HOME/private-incoming"
```

The command prints the newly atomically published `lightup-human-inbox-<random>/` path. Open its **`index.html` locally**, not over the web. The root presents a source-free count-only list and links to `slot-01/cockpit/index.html`, `slot-02/cockpit/index.html`, etc. Individual original cockpits, along with their detached HMAC `receipt.json`, remain in separate private slot folders. Every source-free cockpit is independently checked against native original checksum, privacy disclaimer, stage-count and HTML reconstruction logic.

The command decrypts/authenticates each AEAD envelope and HMAC **before** placing any member in a fresh private temporary workroom. The original native publisher enforces no-overwrite atomic per-cockpit publication, and the *entire complete receiving workroom* uses the original exclusive Linux `renameat2(RENAME_NOREPLACE)` publication after native inspection of **every** member and regenerated root HTML/JSON. Failure cleans only the newly created temporary workroom; it does not touch existing inputs, previous inboxes or any original source.

To independently read an already published inbox using its original private key:

```sh
python3 remediation-cockpit-attestation/inbox.py inspect \
  --inbox "$HOME/private-incoming/lightup-human-inbox-EXACT-PRINTED-ID" \
  --key-file "$HOME/private-secrets/team-secret.key"
```

Inspection checks all original HMAC/native receipts, every individual original cockpit, the exact root inventory, source-free manifest SHA records and independently regenerated root summary/HTML. **No new credential, consent, cryptographic identity or verdict is conferred.**

## Add later packets without ever editing the earlier workroom

When 1–11 further packets arrive, create a **new** complete workroom snapshot. All prior slot members are separately reopened, admitted and copied into a fresh private staging directory; newly arrived encrypted packets are also independently admitted. The old directory is read-only to this workflow, never deleted or overwritten. New and old input contents must fit the total **12-slot limit**. Duplicate exact source-free manifests are rejected to prevent a fake duplicated workload count.

```sh
python3 remediation-cockpit-attestation/extend.py \
  --inbox "$HOME/private-incoming/lightup-human-inbox-OLD-ID" \
  --package "$HOME/private-incoming/operator-03.ltpack" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --output-parent "$HOME/private-incoming"
```

The command prints a **new** privately published inbox path with a new HTML index, original old slots preserved as copies and additional slot(s) appended. Use `inbox.py inspect` on either old or new workroom. The source-free digest inventory identifies **local anonymous manifest byte copies**, never authenticated original customer evidence. A locally self-declared source slot or snapshot position is not a proven chronology.

## Portable encrypted whole-inbox forwarding

Once a complete source-free HUMAN inbox has been independently admitted, it can be transferred as **one encrypted `.ltinbox` ciphertext** with [PORTABLE.md](PORTABLE.md) using `portable_inbox.py send` and `portable_inbox.py receive`. The receiving operator must have the same separately trusted 32-byte team key. The original per-slot source-free HMAC receipts and native HTML/JSON files are reconstructed into a brand-new independent private 0700 folder before new index publication. No original source evidence or client identity is forwarded. The old team inbox stays intact.

## Operator assignments and due dates for this inbox

For human follow-up coordination against an **already admitted original inbox**, use [COORDINATION.md](COORDINATION.md). It creates new encrypted 0600 per-slot owner, stage, urgency, date and local note snapshots, an offline private HTML board, anonymous tentative calendar and exact-original-prefix carry when this inbox is extended. A complete private inbox plus its HUMAN plan can also be sealed and reopened together as a portable workroom, never modifying these original source-free cockpit files.

## PRIVACY: internal manifest inventory is not an anonymous export

The workroom's private `summary.json` **contains linkable SHA-256 digests of source-free manifests** for native local duplicate detection, exact source-free slot continuity and original inbox admission. It is **PRIVATE integrity inventory**, not safe to describe as a fully anonymous external report. Keep it inside the trusted owner-only workroom. For a fresh true **counts-only** 0600 JSON that contains *no* slot digests, owner names, original source references, notes, due dates or per-case links, use:

```sh
python3 remediation-cockpit-attestation/inbox.py export-counts \
  --inbox "$HOME/private-incoming/lightup-human-inbox-EXACT-ID" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --output "$HOME/private-incoming/inbox-counts-only.json"
```

When working from a **complete PRIVATE HUMAN workroom** with encrypted slot planning, `workroom_control.py export-counts` additionally aggregates anonymous stage and due-slot totals without revealing dates/aliases/notes. Even source-free aggregate counts remain PRIVATE unless an authorized human decides they may be shared; these counts prove no customer consent, fix or source evidence identity.

## Absolute boundaries

This capability is private **HUMAN workflow bookkeeping** only. It does not infer unique clients, original finding identities, real evidence validity, remediation quality, active test permission, grant, current client consent, review approval, retest, release readiness or risk. A copied shared secret can authenticate alternate packages; HMAC/AEAD do not establish independently authenticated human sender identity. Unencrypted HTML only exists in already owner-private `0700` folders with `0600` files; keep devices trusted and secrets distributed via an independent human-approved channel. There is no archive/network/upload/scan target functionality or deletion of original material.

The entire companion remains **DRAFT/HOLD** pending all *existing* original source-owner, hosted + named VPS exact-head CI, independent security/privacy/browser/crypto review, original #177/#182/#829 authorization lineage, separately current genuine client/operator consent and action-time revocation, and an explicit HUMAN GO. Never merge to main or deploy by virtue of a locally admitted source-free count-only inbox.
