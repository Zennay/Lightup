# LightUp Scope + STOP Incident Room

Posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Never a permission, grant, consent, release, scan, or dispatch signal.

## Integrated original sources

- Authorization Casebook, pinned original PR #1620 at fa3a260234daa1178b5f6e4fc95cbd36e12d61fd.
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
- Temporary human stages exist only in browser memory. Neither the offline room nor the read-only scope_incident_brief CLI writes STOPs or accesses tools/targets. The separate scope_ops CLI below can write original authenticated deny-only STOP after full confirmation; it cannot start or resume execution.

## Existing gates still required

Notion LightUp remains INCUBATE/DRAFT/HOLD. Original STOP PR #1619 is RED in existing Python 3.11/3.14 hosted source-contract CI; the original owner must reconcile the source-contract mismatch. There is no bypass, rerun, test modification or deploy.

No main merge or release before original source-owner approval, exact-head hosted and permanently registered named VPS CI, independent security/privacy review, separately authenticated client/operator consent with revocation at each use, and explicit HUMAN GO.

Sources: https://github.com/Zennay/Lightup/pull/1619 ; https://github.com/Zennay/Lightup/pull/1620 ; https://app.notion.com/p/3ed9e19ac9558117b639f2254fe0e165
## Historical private comparison

After importing the latest source, load a second older original private briefing for exactly the same tenant and selected engagement set. The offline caseboard highlights recorded STOP changes, stored-grant count changes and original case attention changes. A STOP that appears to disappear is an explicit HOLD warning, never authority or a restoration of service. Comparisons use only local in-memory files, enforce earlier timestamps and equal case membership, preserve the previous comparison on invalid import, and export only anonymous change counts; neither original source IDs nor private snapshots are exported. Snapshot timestamps are untrusted historical claims and never a live guarantee.

## Integrated original risk decision provenance and source case details

The three original Casebook source/UI/docs paths were integrated byte-for-byte at original exact SHA fa3a260. Original #1620 branch remains unchanged; original emergency STOP sources stay pinned at #1619 80a74c5. This includes authenticated original case lists, request/grant/risk provenance, pending risk decisions, reviewer queue, source change comparison and privacy-minimal human briefing. HELD candidate, not release.

The combined briefing and offline Incident Room surface original risk_provenance_hold and pending_risk_review counters, reject contradictory source declarations, and prioritize STOP, source HOLD and pending risk. A new private Inspect case view shows each selected original engagement's original source request status, grant/request binding and risk decision provenance. Private identifiers stay only in browser memory.

Browser-only human follow-up stages can be exported and restored bound to SHA-256 of the exact original private JSON bytes. Stage order is tied to the source record order; a different source is refused. No browser persistence/network; Web Crypto support is required only for this optional stage save/restore. Historical comparison still treats apparent disappeared STOP as HOLD, not an action-time guarantee.

## Interactive original authenticated deny-only STOP

From a trusted private foreground terminal use:

    PYTHONPATH=src python3 -m lightup.scope_ops --database /private/domain.sqlite --email EXISTING_LOGIN --client EXISTING_TENANT_ID

An original client sees its own tenant only; operators select one exact existing tenant. The real DomainStore authentication and lockout apply. The menu lists and inspects original cases and STOP/grant exposure, refreshing original role/tenant membership before every private detail. Choosing STOP requires the literal full confirmation STOP ENGAGEMENT_ID. The **unchanged original** record_authenticated_stop then independently reauthenticates at write time and checks actual tenant/role/engagement in its database transaction. This records only a deny-only STOP event, not a grant, approval, scan, worker kill, target work or resume. Cancelling the confirmation makes no write.

The new native console itself is not wired to dispatch/retry/resume. A recorded STOP does not prove running work was killed. Original exact-head hosted and permanently registered named VPS CI, original source-owner/security/privacy review, distinct authenticated client/operator consent, at-use revocation and explicit HUMAN GO remain mandatory. No main merge, deployment or live activation during HOLD.

## Original approved-request binding shortlist integrated

Six **unmodified original** product/docs paths from source-owner companion [PR #1590](https://github.com/Zennay/Lightup/pull/1590), exact source SHA 41372442e4c70a8c1a1bd9c514732cd5869dff0e, have been physically integrated into this independent HELD branch. This includes the original operator-authenticated request-binding CLI, alternative scenario evaluation, original Studio import, source-linked offline human desk, anonymized handoffs, and private guide. Original source owner is unchanged. The installed canonical approved_request_is_compatible helper has byte-identical source in both owner and this composition; no new approval decision policy was invented.

Direct original operator usage (genuine persisted operator account only):

    PYTHONPATH=src python3 -m lightup.request_binding_readiness_cli --db /private/domain.sqlite --email EXISTING_OPERATOR --engagement-id EXISTING_ENGAGEMENT --client-id EXISTING_TENANT --asset canonical.example --risk 2 --output /private/NEW_PRIVATE_SHORTLIST.html

This original command requires a foreground password and uses an original readonly SQLite source transaction after authenticating. One, zero or multiple historical administratively approved candidate requests are explicitly REVIEW_ONLY/HOLD, not real permission. Alternative 2-8 scenarios, Studio proposal imports and private source-bound candidate follow-up are fully supported by the original copied module and described in docs/request-binding-readiness-desk.md.

The new integrated scope_ops menu now includes [B]inding shortlist for a selected existing engagement, requiring explicit 1-80 canonical proposed literals and risk 1-4. It invokes the **unchanged original source-owner request matching routine**, rechecks the live persisted operator role and tenant inside the original readonly source snapshot and prints only candidate counts and standardized nonauthorizing refusal reasons. It does not expose source request IDs/labels by default and never issues a grant, consent, scan, target action, release or runtime permit. The separate [S]TOP action remains the original authenticated, explicitly confirmed deny-only writer. A human may review a shortlist and choose STOP, but no shortlist result can trigger STOP automatically.

**Release still held**: exact new integrated source HEAD is not original full CI green, named VPS evidence remains required; independent real client/operator consent, original write-time source grants and runtime revocation, security/privacy/source-owner approval and HUMAN GO still gate main merge/deploy/active execution. Historical request matches or STOP absence never grant rights.
## Private source-linked request candidate dossier

The original authenticated scope_incident_brief CLI now accepts --proposal-engagement EXACT_ENGAGEMENT, repeated --proposed-asset CANONICAL_LITERAL and --proposed-risk 1..4. An original operator may produce one bound private Casebook + STOP + request-binding review file:

    PYTHONPATH=src python3 -m lightup.scope_incident_brief --database /private/domain.sqlite --email EXISTING_OPERATOR --client EXACT_TENANT --engagement EXACT_ENGAGEMENT --proposal-engagement EXACT_ENGAGEMENT --proposed-asset canonical.example --proposed-risk 2 --output /private/NEW_PRIVATE.json

Original request matching is by the already-installed source-owner routine in a new read-only original SQLite snapshot. The exact original tenant/operator is rechecked, and original request-ID, decision status, risk, total grants and bound/legacy proportions must agree with the earlier Casebook and STOP sources or the optional candidate preview is HOLD. Request IDs used solely for cross-snapshot comparison are not put into the candidate preview; candidate status is only historical administrative matching, never consent, a grant or execution permission. The exact private source is written as a NEW exclusive 0600 file; stdout remains aggregates-only, with REVIEW_ONLY or HOLD exit, never a permission signal.

In offline scope-incident-room/standalone.html the Inspect panel shows original request-binding candidate status, source mismatch reason counts, unsigned selection/source digests and historical source drift for that engagement. Proposed target literals remain local input only and are NEVER contacted or included in anonymous exports. Earlier private comparisons require matching original tenant, selection and proposal identity; they cannot imply revocation.

## Historical STOP event timeline and private handoff

The combined original report now records at most 12 recently persisted original STOP events per selected engagement: original private event identity, actor role and source timestamp plus a truncation flag. Any disagreement between independently sampled original STOP exposure and original persisted history results in HOLD; an absent ledger cannot be mistaken for no events. Older private exports lacking the new timeline remain readable with timeline NOT AVAILABLE, not proof of no recorded STOP. The offline viewer highlights missing untruncated historical STOP events as HOLD for human review.

The viewer also exports a PRIVATE Markdown operator worklist with original engagement IDs, bounded source statuses and fixed human-only actions for client/operator/source owner. It explicitly confirms sensitivity: unlike the anonymous aggregate export, this private file has original case identifiers, and the viewer never emails, contacts or modifies actual sources.

The foreground original-authenticated scope_ops menu now includes [E]xport private incident, creating a NEW original 0600 private Casebook+STOP dossier for one exact selected persisted case and optionally a proposed administrative request shortlist. [B]inding remains read-only; [S]TOP still requires exact literal STOP confirmation and is deny-only, not a claim that a running job was halted.

All original owner, independent security/privacy, exact-head hosted+permanent named VPS CI, independently authenticated real client/operator consent, mandatory action-time revocation, and explicit HUMAN GO remain mandatory. INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD; not main-merged or deployed.
## Multiple original proposed alternatives within one private incident

The existing source-owner read-only 2-8 scenario comparison from request_binding_scenarios.py is now composed into this held incident workflow. Give the exact original operator and selected engagement plus --proposal-engagement EXACT_ENGAGEMENT and --scenario-file /private/ORIGINAL_SCENARIOS.json, WITHOUT single --proposed-asset/--proposed-risk options. The private JSON must follow the unchanged original source-owner schema lightup.request_binding_scenarios.v1 (exactly 2-8 nonduplicate canonical literal/risk proposals). Original scenario input is bounded, rejects symlinks and duplicate keys, and has no target/network operations.

    PYTHONPATH=src python3 -m lightup.scope_incident_brief --database /private/domain.sqlite --email EXISTING_OPERATOR --client EXACT_TENANT --engagement EXACT_ENGAGEMENT --proposal-engagement EXACT_ENGAGEMENT --scenario-file /private/ORIGINAL_SCENARIOS.json --output /private/NEW_PRIVATE.json

The source-owner engine checks all alternatives in ONE original read-only SQLite transaction. The held wrapper separately cross-checks the earlier authenticated original Casebook request IDs/status/risk and grant totals; any original source inconsistency becomes HOLD. The private preview stores only human labels, original proposed risk/asset counts, unsigned source/selection digests, original request candidate counts and adjacent human-selected matching overlap. Original target literals and request identities used internally never appear in the appended scenario preview or anonymous exports. Adjacent proposal differences are NOT chronological grants or revocation.

The offline Incident Room now shows scenario alternatives and their original matching counts alongside the original STOP/risk dossier, explicitly labeled HOLD_SCENARIOS_REQUIRE_HUMAN_SELECTION. Even one matching original administrative request is not independently authenticated consent, authorization, a stored grant, or a runtime permit. Historical comparison refuses proposals that do not have the same unsigned source-local scenario selection digest.

The interactive scope_ops menu [E]xport private incident accepts the same private original scenario JSON file path as an alternative to typing one proposed literal/risk. Existing original real authentication, exclusive mode-0600 private output, original historical source HOLD and all unchanged release gates remain in force. No QA suite, target interaction, scan, new grant, consent action or deployment is part of this workflow.
## Source-bound private team collaboration (operator + offline team viewer)

LightUp now includes TWO complementary independent offline HTML files under scope-incident-room/ that should be distributed together in the same directory. Both run locally without API, cookies, network, browser storage or original database write access:

- standalone.html: original operator imports the real authenticated private Casebook/STOP JSON, filters original cases (for example STOP/HOLD/risk), reviews historical provenance, manages human-only stages, then clicks **Export PRIVATE team packet**. Only the currently **visible filtered original cases** are included (1–32). Hidden cases, full grant/request rows and unrelated client records are never copied into this reduced-disclosure team packet.
- team.html: an independently designated human reviewer loads that private packet, sees only its original STOP/source-attention and next human action labels, records a human-only stage and bounded note (max 500 characters) for each included case, and returns **PRIVATE human-only JSON**. Reviewer/team labels are self-declared and NEVER authentication, consent or evidence.
- Back in standalone.html, original operator selects **Import PRIVATE team return**. All exact immutable case identities/source observations, per-case prior human stage, packet/source SHA-256 identity and full case ordering are checked against the *current* original source and local stages before showing a private preview. No imported stage/note is applied during this step.
- Operator reviews **every original case**, before/after stage, note and self-declared reviewer/team in a separate private review panel, verifies the human sender independently, checks an explicit acknowledgement and confirms local-only application. Immediately before application the original packet binding is recomputed. If the original source or local human stage changed during review, the entire incoming return is discarded with HOLD.
- The resulting human-only stages and unverified team notes are held in browser memory. The source-bound **Save private follow-up** now produces review schema v2, with all local team notes, source SHA-256 and original case order; **Restore** still accepts original v1 stage-only exports and new v2. The user's private saved return is intended solely for the exact original source JSON bytes; it cannot be used to restore a different original case export.
- An operator can use filters **UNVERIFIED team notes** and **Human follow-ups not documented**, plus per-original-case note preview, source-linked Inspect and backlog counters. Private Markdown handoff includes self-declared follow-up notes with explicit UNVERIFIED labeling. The anonymous aggregate export never contains original IDs, private notes or reviewer names.

**Trust boundary:** this packet protocol is bound to original **local SHA-256 content**, not signed or authenticated by a server, client or identity provider. SHA-256 and the derived packet token detect accidental source/stage/selection mismatch but do NOT authenticate the human sender, approve scope, verify independent consent, alter STOPs, issue a grant, prove target permissions or make a stored review into verified evidence. Independent human reviewer checking remains explicitly mandatory; the app makes no original domain/worker/runner writes. The team file should be shared only through independently authorized private channels under existing retention/handling policies. Keep original authentic source file owner-only. **INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD** still blocks any main merge, deploy, live scan or release until exact mandatory original hosted/permanent named VPS CI, original source-owner/security/privacy approval, real separately authenticated client/operator consent, at-use revocation and explicit HUMAN GO.
