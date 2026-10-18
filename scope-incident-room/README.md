# LightUp — Offline Scope & Incident Room

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD — NOT RELEASED**

This downloadable kit contains only two **offline HTML pages** and this guide; there is no server, network integration, scanner, original SQLite source, private token, client data, consent record, STOP writer, or runtime gate inside this kit. It does not contain, create, issue, authenticate, authorize or approve real target activity.

## Open locally

Unzip into a private directory and keep the files together. Open `standalone.html` in a browser on a trusted operator workstation. If local browser Web Crypto (SHA-256) is unavailable, basic source viewing still works, but source-bound team export/return and saved follow-up are disabled; use a local browser that supports Web Crypto on trusted offline pages. There are no external resources or fetch requests.

The operator must create an authentic **private original-domain** read-only JSON source using the held CLI in the repository, with real existing account credentials, an exact selected tenant, and the original existing local SQLite file. The CLI is **not** bundled, and is not wired to live dispatch or target work. Example command is for a held local review only:

    PYTHONPATH=src python3 -m lightup.scope_incident_brief --database /private/domain.sqlite --email EXISTING_LOGIN --client EXACT_TENANT --engagement EXACT_ENGAGEMENT --output /private/NEW_PRIVATE.json

Import the source using **Import latest private briefing**. Inspect original STOP, grant, request and risk records and optionally compare against an older original source report. Never treat missing STOP or one approved administrative request as evidence of independent consent, grant, safety or runtime permission.

## Human-only team workflow

Filter operator cases to the **minimum** original identities that the authorized reviewer needs, then **Export PRIVATE team packet**. This private file contains selected engagement IDs, original STOP/source status, original next human action and current local-only stage. Share it only by existing authorized private channels.

The team opens `team.html` from this same local folder and loads the private packet. They may update only their local human follow-up stage and bounded free-text note, supplying self-declared reviewer and team labels. They export **PRIVATE team return JSON**. The team page never reads or writes the operator's original source file or private original database.

The operator imports the private return into `standalone.html`: source identity, exact case membership, original historical details, prior local stages and source-bound packet digest must all agree or it is refused. Review **every proposed change**, independently verify sender and tenant, check the explicit acknowledgement and confirm a local-only application. The self-declared labels are not cryptographic signatures or authentication.

**Save private follow-up** saves original-SHA-bound local stage and team-note state (v2, older v1 stage-only supported). The operator can also **Refresh original source** with a newer original private export; preview first, preserve local notes only for literally unchanged original source case records and reset all changed/new/removed cases for review. No source or runtime mutation occurs.

## Strong limits and release gates

- The kit makes **NO** credential checks or original-domain request, grant, approval, revocation or STOP writes.
- Original Casebook, STOP and request-binding source reads used to generate a report may come from different read-only snapshots; they are **not** an atomic action-time revocation decision.
- The private team packet hash and digest are **not** proof of source authenticity or sender identity; only exact locally supplied bytes/selection can be compared.
- The private packet and return contain sensitive original case identifiers. Anonymous summary exports omit these; always distinguish the two.
- Existing exact-head hosted and permanently named VPS CI, independent source owner/security/privacy approval, genuine independent client + operator consent, mandatory per-use revocation and explicit **HUMAN GO** remain required before any main merge, production deploy, live scan, dispatch, grant or release.

See `docs/scope-stop-incident-room-20261018.md` in the repository for complete CLI and security boundaries. This is a held offline collaboration candidate, not a compliance certificate or authorization.
