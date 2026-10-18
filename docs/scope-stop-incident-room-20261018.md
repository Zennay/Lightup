# LightUp Scope + STOP Incident Room

Posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Never a permission, grant, consent, release, scan, or dispatch signal.

## Integrated original sources

- Authorization Casebook, pinned PR #1620 at 2fa54d6d80419f34a55ff8721860cd40008965f1.
- Emergency STOP, unchanged eight original product/docs paths pinned PR #1619 at 80a74c5d6f6b25e8f7784619fca5c58903ecd0b3.
- The original two owner branches, scope policy, domain, production handlers, CI workflows and existing tests were not modified.
- An independent composed source adds scope_incident_brief.py and an offline source-bound scope-incident-room/standalone.html.

## Usage on a trusted private workstation

Run the following using an existing original-domain SQLite file and existing authenticated LightUp account:

    PYTHONPATH=src python3 -m lightup.scope_incident_brief --database /private/domain.sqlite --email REAL_EXISTING_LOGIN --client EXACT_EXISTING_TENANT --output /private/NEW_PRIVATE.json

Original DomainStore login and lockout are retained. Client logins can read only their own tenant. Operators must explicitly select one original tenant. For more than 32 engagements in one tenant, select up to 32 exact engagement IDs using repeated --engagement flags. Invalid, duplicated or cross-tenant selection fails HOLD.

Open scope-incident-room/standalone.html locally. Import the NEW_PRIVATE.json produced by the native CLI. Filter the combined original case records and historical STOP state, update temporary human follow-up stages, and export anonymous counts. No local storage, network or source modification occurs in the browser.

Individual original products remain available: python -m lightup.auth_casebook, python -m lightup.stop_ops, python -m lightup.stop_exposure, and both individual standalone HTML consoles.

## Trust boundaries

- The source is a bounded historical composition of SEPARATE snapshots, not an atomic transaction across original modules or an action-time gate. Data may change immediately after the snapshot.
- An invalid or absent STOP ledger, a changed source grant count, unknown tenant, malformed actor or bad original records are HOLD; lack of a STOP never grants anything.
- The native CLI returns exit 2 for REVIEW_ONLY or exit 3 for HOLD, never exit 0. All authority, consent, execution and release flags are literally false.
- Only the explicit private file includes original identities; stdout includes aggregate counts only. The original casebook exclusive non-overwriting 0600 file writer is reused.
- The viewer rejects oversized inputs, duplicate JSON object keys, shape/identity/count conflicts and all asserted authority. Invalid input leaves the previous workspace untouched. Anonymous exports omit original identities and grant rows.
- Temporary human stages exist only in browser memory. Neither the room nor the CLI invokes STOP writes, model tools, scanners, grants, handlers or targets.

## Existing gates still required

Notion LightUp remains INCUBATE/DRAFT/HOLD. Original STOP PR #1619 is RED in existing Python 3.11/3.14 hosted source-contract CI; the original owner must reconcile the source-contract mismatch. There is no bypass, rerun, test modification or deploy.

No main merge or release before original source-owner approval, exact-head hosted and permanently registered named VPS CI, independent security/privacy review, separately authenticated client/operator consent with revocation at each use, and explicit HUMAN GO.

Sources: https://github.com/Zennay/Lightup/pull/1619 ; https://github.com/Zennay/Lightup/pull/1620 ; https://app.notion.com/p/3ed9e19ac9558117b639f2254fe0e165