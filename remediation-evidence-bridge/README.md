# LightUp · Authenticated PRIVATE Evidence Ledger Bridge

**Release posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This product is a source-bound, **human-only offline evidence coordination** interface, not an authority decision, a test of any third-party system, confirmation of any vulnerability, remediation proof, client consent, an authorization grant or permission to execute anything.

## Delivered product

The branch combines **unchanged original owner products**, not forks:

1. Original authenticated client-and-exact-engagement findings CSV from `remediation-secure-export/secure_export.py` using the normal `DomainStore` account/role, tenant and engagement checks. The existing original source-owner Unicode and batch CSV guard is retained. No direct SQLite bypass.
2. Unchanged original `remediation-artifact-ledger/` files copied from the original Artifact Ledger draft, including the original Casework parser SHA pin, offline Evidence Artifact Ledger, human artifact SHA-256 tracking, original Evidence Review/Casework context, human owner request board and offline owner response.
3. New standalone `remediation-evidence-bridge/bridge.py`. The secure source is never written as a temporary CSV or unencrypted HTML during **export**, and the complete original current-source CSV is carried inside one owner-only 0600 AES-GCM `.ltv`. The original immutable ledger HTML is **rebuilt on every export/open** and checked against its pinned SHA-256. Only one CSP-SHA-pinned, no-network local preload script is appended; the original human features, original source and original CSS/JS are left intact.
4. **Private human workflow:** `open` explicitly decrypts into a newly created owner-only offline HTML; the browser locally imports the original CSV and the self-declared context; users then link their own *local* evidence files by byte SHA-256, add human reviewer notes, request clarifications and prepare PRIVATE source-bound handoffs. Evidence bytes are not sent to the app or stored in the ledger; only local fingerprints and human metadata are remembered in browser memory.
5. **Extra sensitive reopening:** `open-current` requires a new real original LightUp login, read permission for the exact client and engagement, and **exact CSV byte SHA-256 and finding-count match** before creating HTML. It does not grant action permission or obtain client consent.
6. `inspect` decrypts and displays only total finding count without names, IDs or artifacts; `rotate` securely re-encrypts to a new owner-private `.ltv` without ever materializing plaintext. Existing vault `seal/open` implementation is reused unchanged.

All archive metadata flags `authenticated, source_authorized, assessment_authorized, grant, client_consent, operator_consent, execution, scan, retest_verified, release` are explicitly **false**. Export-time authenticated source selection is documented separately from authority claims. A human stage/attachment hash is not evidence that anything has been fixed or retested.

## Usage on an already authorized local LightUp workstation

Prerequisites: the pinned original candidate branch, Python and its existing dependencies (including `cryptography`), a real existing LightUp account, a client/engagement to which that account has original read access, and an owner-owned 0700 **private destination directory**. Passwords and passphrases are entered interactively on a real private TTY only. Never put client credentials or secret material in shell arguments, chat, environment variables, CI variables or documentation.

```sh
# Existing and already-authorized local LightUp data; no network discovery, no scanning.
PYTHONPATH=src python3 remediation-evidence-bridge/bridge.py export \
  --db /path/to/already-existing-lightup.sqlite \
  --email operator@example.invalid \
  --client-id EXISTING_CLIENT_ID --engagement-id EXISTING_ENGAGEMENT_ID \
  --output /trusted/private/lightup/evidence-ledger-original.ltv

# Inspect encrypted original source without writing any decrypted file.
PYTHONPATH=src python3 remediation-evidence-bridge/bridge.py inspect \
  --input /trusted/private/lightup/evidence-ledger-original.ltv

# Human-approved PRIVATE plaintext on disk (sensitive, 0600, never public):
PYTHONPATH=src python3 remediation-evidence-bridge/bridge.py open \
  --input /trusted/private/lightup/evidence-ledger-original.ltv \
  --output /trusted/private/lightup/evidence-ledger-review.html \
  --ack-private-html

# Stronger fresh-source gate: re-authenticate and require exact CURRENT original CSV.
PYTHONPATH=src python3 remediation-evidence-bridge/bridge.py open-current \
  --db /path/to/already-existing-lightup.sqlite \
  --email operator@example.invalid \
  --client-id EXISTING_CLIENT_ID --engagement-id EXISTING_ENGAGEMENT_ID \
  --input /trusted/private/lightup/evidence-ledger-original.ltv \
  --output /trusted/private/lightup/evidence-ledger-current-review.html \
  --ack-private-html

# Rotate existing ciphertext without writing a plaintext intermediate.
PYTHONPATH=src python3 remediation-evidence-bridge/bridge.py rotate \
  --input /trusted/private/lightup/evidence-ledger-original.ltv \
  --output /trusted/private/lightup/evidence-ledger-rotated.ltv
```

Open the private HTML only on a trusted workstation without browser extensions or cloud file synchronization that could exfiltrate file contents. Browser import occurs from the local original CSV embedded into the **explicitly decrypted** HTML, without network requests, DNS, browser persistence, grants or scanner invocations. The main ledger remains unchanged: the original source is imported as **unverified source-reported findings**, and all local evidence fingerprints and follow-ups are HUMAN-only records. Private exports in the browser require their original separate human confirmation and recipient checks.

## New: privacy-minimal encrypted source-claim briefing

The companion `brief.py` reads the existing encrypted authenticated Evidence Ledger `.ltv`, admits the original source and the pinned original HTML, and produces only **aggregate original severity × source retest-label counts**. No original finding ID, title, remediation instructions, client, engagement, account, digest or attachment details are included. This is human workload planning, **not a verified vulnerability or remediation statistic**.

```sh
# View anonymous original reported severity/retest-count Markdown only, no plaintext output file.
PYTHONPATH=src python3 remediation-evidence-bridge/brief.py \
  --input /trusted/private/lightup/evidence-ledger-original.ltv \
  --format markdown

# Re-authenticated current-source counts-only CSV directly to new 0600 file.
PYTHONPATH=src python3 remediation-evidence-bridge/brief.py \
  --input /trusted/private/lightup/evidence-ledger-original.ltv \
  --current --db /path/to/already-existing-lightup.sqlite \
  --email operator@example.invalid \
  --client-id EXISTING_CLIENT_ID --engagement-id EXISTING_ENGAGEMENT_ID \
  --format csv --output /trusted/private/lightup/source-claim-counts.csv
```

Both paths require an interactive private vault passphrase. `--current` additionally requires fresh authentic LightUp account and exact original client/engagement source access; it cannot imply permission to scan, client consent, acceptance of a remediation claim or proof of a retest. The CSV contains only fixed safe enum labels and positive integer counts; the `--output` writer uses the original owner-only no-follow/0600 writer and never overwrites a destination.

## Full encrypted HUMAN collaboration with manual original-app restore

The new **`workspace.py`** carries an operator's already exported PRIVATE original Ledger **unified HUMAN workspace JSON** and the exact previously exported **authenticated encrypted Evidence Ledger `.ltv`** as one new encrypted collaboration handoff. Only original HUMAN drafts are transported; no original evidence file bytes, scan targets, grants or proof of verified fixes are included. The source and human packet must have the exact original canonical source SHA, the same real client/engagement labels, literal false authority flags and bounded original shapes.

**Seal** requires a **fresh original LightUp login and exact current authorized source** before any handoff is accepted; the selected unified-human packet must be a pre-existing owner-private regular 0600 file in a 0700 private directory. Both the original source passphrase and a new collaboration passphrase are entered privately via TTY. The old encrypted source file remains untouched.

```sh
PYTHONPATH=src python3 remediation-evidence-bridge/workspace.py seal \
  --source /trusted/private/lightup/evidence-ledger-original.ltv \
  --workspace /trusted/private/lightup/original-unified-human-workspace.json \
  --db /path/to/existing-lightup.sqlite --email operator@example.invalid \
  --client-id EXISTING_CLIENT_ID --engagement-id EXISTING_ENGAGEMENT_ID \
  --output /trusted/private/lightup/human-collaboration.ltv
```

**Open** creates a new private offline HTML file only after explicit `--ack-private-html`. It locally imports the original source and provides a **new Preview encrypted HUMAN workspace button**. A human must click the button to trigger the unchanged original Ledger's canonical-source-bound **preview**, inspect what would change, and then separately click the original **Confirm atomic PRIVATE human restore** action; the new code never calls the apply action. Nothing is automatically committed to original human records or external data.

```sh
PYTHONPATH=src python3 remediation-evidence-bridge/workspace.py open \
  --input /trusted/private/lightup/human-collaboration.ltv \
  --output /trusted/private/lightup/PRIVATE-human-review.html --ack-private-html

# Additional fresh-login and exact-current-source gate before local plaintext output:
PYTHONPATH=src python3 remediation-evidence-bridge/workspace.py open-current \
  --input /trusted/private/lightup/human-collaboration.ltv \
  --db /path/to/existing-lightup.sqlite --email operator@example.invalid \
  --client-id EXISTING_CLIENT_ID --engagement-id EXISTING_ENGAGEMENT_ID \
  --output /trusted/private/lightup/PRIVATE-human-current.html --ack-private-html

# Anonymous count-only inspect; or passphrase rotation to a NEW .ltv:
PYTHONPATH=src python3 remediation-evidence-bridge/workspace.py inspect \
  --input /trusted/private/lightup/human-collaboration.ltv
PYTHONPATH=src python3 remediation-evidence-bridge/workspace.py rotate \
  --input /trusted/private/lightup/human-collaboration.ltv \
  --output /trusted/private/lightup/human-collaboration-rotated.ltv
```

The browser's original source importer, local SHA-256 content binding, original Casework/Evidence Review import checks, stale-preview guard and explicit confirmation remain the ultimate HUMAN-only admission; encryption is **not** security evidence, identity attestation, consent, current release permission, or verified remediation.

## Source-revision continuity without silently carrying changed findings

**`revision.py`** adds a complete private *human-only* source revision workflow. When an authenticated client/engagement findings export changes, **only findings with all five original source fields literally identical** retain local HUMAN file fingerprints, optional original Casework fields and pending human requests. A changed/absent original finding is **NOT** an automatically fixed finding. All other prior HUMAN notes remain **only in the unchanged old encrypted source** and are not copied to the new source. Every new or changed finding in the revised original Casework starts at `unassigned` with blank human notes; old complete original Evidence Review is always detached because its membership is source-wide. The original file must be retained for historical human audit and re-evaluation.

```sh
# Private TTY original LightUp login required; aggregate-only preview, no new file:
PYTHONPATH=src python3 remediation-evidence-bridge/revision.py preview \
  --input /trusted/private/lightup/human-collaboration.ltv \
  --db /path/to/existing-lightup.sqlite --email operator@example.invalid \
  --client-id EXISTING_CLIENT_ID --engagement-id EXISTING_ENGAGEMENT_ID

# On deliberate approval, create one NEW 0600 encrypted, updated-original-source HUMAN workroom:
PYTHONPATH=src python3 remediation-evidence-bridge/revision.py carry \
  --input /trusted/private/lightup/human-collaboration.ltv \
  --db /path/to/existing-lightup.sqlite --email operator@example.invalid \
  --client-id EXISTING_CLIENT_ID --engagement-id EXISTING_ENGAGEMENT_ID \
  --output /trusted/private/lightup/new-original-human-workroom.ltv \
  --ack-preserve-original
```

This is **human source-claim continuity**, not scan/verified-fix/retest evidence or authorization. The human must retain the previous original encrypted source separately; the new package is a separate artifact and is never published or applied to production.

## Original ownership and enforced gates

This integration is a **child candidate** of the original held [authenticated encrypted Casework PR #1653](https://github.com/Zennay/Lightup/pull/1653), with the [original unchanged Evidence Artifact Ledger PR #1642](https://github.com/Zennay/Lightup/pull/1642) copied as-is. All new feature code resides under `remediation-evidence-bridge/`. It does not alter the original file ownership, existing `src/lightup/`, active scope/authorization, scanner, tool runner, CI workflow or test/QA files.

Both original hosted and permanently registered named VPS **exact-head mandatory CI**, source-owner acceptance, independent security/privacy/crypto/browser review, issues #177/#182/#829, **real separate authenticated client/operator consent and action-time revocation**, and explicit **HUMAN GO** remain separate prerequisites before any merge to main, deployment or client-facing activation. The protected development draft is intentionally not a release.

No QA, regression or test suites are added or run. Native syntax, offline builder and CLI entrypoint are available for brief build/functional inspection only.
