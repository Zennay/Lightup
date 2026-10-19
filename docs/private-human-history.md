# LightUp · PRIVATE encrypted HUMAN workplan history

**Incubate · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** This standalone addition consumes the original, unchanged authenticated LightUp encrypted finding source (`.lue`) and its exact-source HUMAN workplan snapshots (`.lun`) already created on the held parent [PR #1647](https://github.com/Zennay/Lightup/pull/1647). Its files are **add-only**, and it does not change the original owner exchange, Handoff Vault, production CLI, permissions, scanner or the parent operator console.

## Operator product

The product shows **human coordination history**, not technical remediation. It decrypts 1–12 separately protected workplans entirely in memory, admits each against the exact original source SHA, declared client/engagement and complete original finding-ID set, and compares the operator-supplied sequence. It never silently merges human state into the original source or old plans.

The generated timeline shows:
- the count of assigned HUMAN owner aliases and counts by non-authorizing human stage per snapshot;
- record-level change counts by HUMAN stage, assigned alias, proposed follow-up date and private note, without printing original private notes;
- which critical/high source-claimed findings entered or left HUMAN attention states (**leaving attention is not fixing a finding**);
- proposed HUMAN follow-up dates already overdue at an explicit UTC `--as-of` date; this is not a security fix deadline;
- a prioritized latest HUMAN attention queue: source-claimed high/critical severity, blocked/waiting-human stages, and overdue proposed dates.

The default PRIVATE HTML and JSON contain only aggregate counts, **no original client/engagement identity, customer name, original IDs, title, owner alias, remediation, raw evidence or private note text**. Small aggregates may still be identifying. The optional detailed HTML includes original finding ID, original title, unverified self-declared owner alias, human stage and proposed follow-up date, but **never remediation text, evidence or note content**; it requires separate explicit `--include-private-actions --ack-private-attention-ids` as well as plaintext handling confirmation.

### Direct private HTML

```sh
python -m lightup.private_export_history /private/original-source.lue \
  /private/human-v1.lun /private/human-v2.lun \
  --as-of 2026-10-19 --output /private/human-history.html \
  --ack-private-original-data --ack-plaintext-destination
```

The source and every HUMAN snapshot passphrase are prompted interactively (never supplied in CLI arguments). Source files and plans must be genuine user-authorized local copies; self-declared labels and matching cryptographic hashes are not signatures or real-world authentication. Output uses mode `0600`, atomic no-overwrite publication, scriptless HTML, a restrictive local CSP and no network calls.

For an ID-free private **machine-readable aggregate** instead:

```sh
python -m lightup.private_export_history /private/original-source.lue \
  /private/human-v1.lun /private/human-v2.lun \
  --format json --output /private/human-timeline.json \
  --ack-private-original-data --ack-plaintext-destination
```

The JSON contains literal false claims for action authorization, verified remediation and original human/client identity. Use it only for private human planning, not for permission or automatic state changes.

### Encrypted-at-rest history without a plaintext report intermediate

The separate `.luh` history format is **not interoperable** with original browser Handoff Vault [#1640](https://github.com/Zennay/Lightup/pull/1640) or parent `.lue` / `.lun`. It is a distinct AES-256-GCM envelope with random fresh salt/nonce and scrypt, authenticated metadata, and independent interactive history passphrase.

```sh
python -m lightup.private_export_history_vault create /private/original-source.lue \
  /private/human-v1.lun /private/human-v2.lun \
  --output /private/human-history.luh --ack-private-handling
python -m lightup.private_export_history_vault inspect /private/human-history.luh \
  --ack-private-handling
python -m lightup.private_export_history_vault open /private/human-history.luh \
  --output /private/human-review.html --ack-private-handling --ack-plaintext-html
python -m lightup.private_export_history_vault rotate /private/human-history.luh \
  --output /private/history-new-key.luh --ack-private-handling
```

`create` builds the report only in RAM and writes an AES-256-GCM authenticated `.luh` (no cleartext report ever saved by that creation path). `inspect` prints only aggregate counts. `open` writes an intentionally **UNENCRYPTED** private 0600 HTML file; verify the actual recipient, transport and local storage. `rotate` decrypts to memory and publishes a fresh encrypted envelope; it does **not** delete the previous ciphertext. A correct local passphrase authenticates the ciphertext, **not its human author or client**.

### One interactive foreground menu

For operators preferring a single entrypoint:

```sh
python -m lightup.private_export_history_console
```

The menu provides anonymous HTML, privacy-acknowledged original ID/owner details, ID-free JSON, direct encrypted vault creation, vault inspection, decrypted HTML and passphrase rotation. All prompts execute in the foreground; no background process, persistence, remote network, password storage, target scan, scope grant, evidence collection, retest or automatic remediation runs.

**HOLD is unchanged:** parent #1647 and original guarded-export parent #1611 remain draft and dependent on hosted and permanently registered VPS exact-head CI, source-owner acceptance, independent security/privacy/crypto review, current independently authenticated client/operator consent, revocation-at-use, #177/#182/#829 and explicit HUMAN GO. No main merge or production release. Python source and CLI syntax may be inspected without writing or running a QA suite. No real customer evidence or targets are included or exercised in this feature delivery.

## NEW: proposed HUMAN follow-up calendar (ICS; no approved change windows)

The independent [`private_export_history_calendar.py`](../src/lightup/private_export_history_calendar.py) projects only the **latest original encrypted source + one exact-source encrypted HUMAN plan** into a private local RFC-5545 all-day calendar. This is *not* a remediation/change window, security deadline, scan, retest or approval. It never calls calendar APIs; human operators manually review and import events. All exports are newly created 0600 **UNENCRYPTED** `.ics` files, atomic no-overwrite, bounded 512 KiB, UTF-8/CRLF with RFC-5545 line folding at 75 octets, strict text escaping, `TRANSP:TRANSPARENT`, `STATUS:TENTATIVE`. Proposed HUMAN due dates may not reflect actual remediation commitments.

**Default aggregate privacy mode:** one all-day event for each date, with only the **count** of human-proposed follow-ups on that date; no client/engagement identity, finding ID, title, source SHA, owner alias, asset, remedy, evidence or HUMAN notes. This reduces disclosure but small counts/dates can still identify a customer. Each manual export uses fresh opaque event IDs: *reimporting the same export can create duplicate events*; a human must prevent duplicates.

```sh
python -m lightup.private_export_history_calendar \
  /private/original-source.lue /private/latest-human.lun \
  --output /private/human-followups.ics --ack-unencrypted-calendar
```

**Explicit private per-finding mode:** one event per original finding with a proposed date, including original title, original finding ID, original source-claimed severity, HUMAN stage and **self-declared** owner alias. No remedy, target, notes or raw evidence is included, and none of those labels is authenticated as real client/operator identity. Use only after independently checking the intended PRIVATE calendar and recipient; unlike the aggregate export, this option intentionally includes original identity-bearing fields.

```sh
python -m lightup.private_export_history_calendar \
  /private/original-source.lue /private/latest-human.lun \
  --output /private/human-followups-private.ics \
  --include-private-events --ack-private-records --ack-unencrypted-calendar
```

The standalone foreground history console now includes aggregate calendar **menu 8** and explicit private calendar **menu 9**, separate from the concurrently owned original PR #1647 console. The calendar is NOT automatically encrypted or transmitted, and it cannot assert that a fix is due, done, safe, authorized or tested.
