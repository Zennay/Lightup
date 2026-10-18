# LightUp · Authenticated Approved-Request Selection Readiness Desk

**Companion to existing source-owner PR #1570 and issue #177.** This new-only standalone Python CLI never edits owner files, grant issuance, portal, production policy, runners or CI.

## Usable product

An actual persisted LightUp operator can preview whether zero, one or several real, previously administratively approved client assessment requests match a proposed engagement, set of canonical asset literals and maximum risk **without issuing any grant**. The original, pinned source-owner compatible-request predicate is used, rather than a rewritten authorization policy. Underlying assessment/grant SQL is read through a separate query-only SQLite transaction.

The private output also explains **source mismatches** without inventing independent permission policy: unapproved administrative status, original requester/reviewer tenant-role provenance, unsuitable original mode, proposed risk widening, proposed literals not covered by original request, invalid decision chronology, or an unexplained source-owner denial. The original source-owner compatible predicate remains the single true/false matching criterion. All reasons are explicitly human-only and cannot be used to override the original source.

The private output shows original request review statuses, strict mismatch versus matching candidate, historical grant-request binding row counts, legacy unbound grant counts, and current-tenant/engagement source warnings. A single match is only REVIEW_ONLY_SINGLE_CANDIDATE. Multiple matches are HOLD_AMBIGUOUS_CANDIDATES; zero is HOLD_NO_CANDIDATE.

**New integrated batch scenario workflow:** In addition to one set of --asset and --risk arguments, supply a strict --scenarios-file containing 2–8 human-proposed risk/scope alternatives for one existing engagement. The CLI runs the original canonical predicate against one shared **read-only SQLite transaction**, not multiple moving source snapshots. Original request matches are grouped by alternative and compared adjacent by record identity as matching/no-longer-matching/newly-matching. Alternative order is manually selected, **never original chronology or revocation**. The original single-proposal CLI remains supported.

The **default private HTML is now a complete source-bound offline operator workbench** (original separate actor authentication still happens before export). It shows immutable original stored decision, role, proposed risk and binding information alongside human-only searchable/filterable cases; per original request it supports locally chosen follow-up team, stage, tentative UTC date and optional private note. The operator can save a bounded **PRIVATE source-bound draft**, later restore it only against the exact same stored source revision and original proposal selection, and export anonymous aggregate JSON/CSV with no source tokens, request IDs, client/asset labels or notes. The script runs under pinned inline CSP, without network calls, cookies, browser storage or backend mutation. Human stage labels never mean granted, approved, revoked or resolved. Use `--static-html` to preserve the original script-free HTML for strictly script-disabled viewers.

Three formats: accessible script-free private HTML, private JSON, formula-escaped CSV. Output is bounded and new-only (mode 0600). Original request IDs and client/engagement labels require separate opt-in options; the default uses private pseudonyms and counters. SHA-256 selection digest is unsigned and no permission certificate.

## How to use

In a separate authorized local environment, using a genuine LightUp database and existing operator account:

    PYTHONPATH=src python3 -m lightup.request_binding_readiness_cli \
      --db /private/lightup.db --email operator@example.org \
      --engagement-id EXISTING_ID --client-id EXPECTED_CLIENT_ID \
      --asset example.org --asset 192.0.2.0/24 --risk 2 \
      --output /private/request-binding-shortlist.html

Alternative plan JSON (private, strict 2–8 entries; do not place real target details in public locations):

    {
      "format": "lightup.request_binding_scenarios.v1",
      "scenarios": [
        {"label": "Narrow host risk 1", "risk": 1, "assets": ["example.org"]},
        {"label": "Host and lab subnet", "risk": 2,
         "assets": ["example.org", "192.0.2.0/24"]}
      ]
    }

Use --scenarios-file /private/scenarios.json **instead of** --asset/--risk with exactly the same --db, --email, --engagement-id and --output options. Each scenario has one separately reported zero/one/multiple administrative match; no scenario actually issues authorization. Labels are fixed ASCII text and imported JSON rejects duplicate keys, hidden NaN and unexpected fields. If the underlying source changes later, reopen through an authenticated operator and recheck from fresh records.

The CLI requires an interactive password prompt; passwords cannot be passed as argv or env. Choose a new .json, .csv or **.md** filename for an alternative private format. The new Markdown handoff translates the original owner-evaluator mismatch reasons into fixed privacy-conscious **client, operator and security-source-owner** discussion questions and human candidate tables, with original client labels and request IDs still opt-in. It does not send messages, assign actual work or issue consent. All outputs are private mode 0600. The opt-in --include-request-ids shows real stored IDs where needed for separately authorized operator reconciliation. --include-labels shows client/engagement names.

Original DomainStore password authentication **does** mutate original sign-in bookkeeping and may use existing schema migration; only the subsequent request/grant inspection is strictly read-only. This is not a DB byte-level immutability tool.

**Original source freshness hint:** the private report now includes a separate bounded SHA-256 fingerprint of the original stored engagement, request and grant row values at read time. Unlike the proposal-selection fingerprint, this value changes when an original stored request decision/asset/risk or grant lineage row changes. The raw underlying records, requester identifiers and notes are never exported through the fingerprint itself. The digest is UNSIGNED and is not an authenticated snapshot receipt, historical chronology, consent, revocation or permission. All 2–8 proposals use one original transaction and require the same exact stored-row digest.

## Release safety

INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. A compatible administrative request is not authentic client/operator consent, a grant or live permission; the actual source owner must revalidate request provenance, tenant, scope, risk and window inside the later write transaction. This CLI cannot approve, issue/revoke a grant, create accounts, dispatch handlers, touch targets, scan, retest, deploy or release. Real authenticated independent client and operator consent including at-use revocation, independent security/privacy and original exact-head hosted + named permanent VPS CI and human GO remain mandatory.

Separate original owners: [source PR #1570](https://github.com/Zennay/Lightup/pull/1570) · [issue #177](https://github.com/Zennay/Lightup/issues/177). No QA/regression/testsuites authored or run.

## Private review output integrity

Source importer refuses malformed historical request/grant lineage identities and cross-tenant grant rows before producing an apparently valid shortlist. CSV additionally neutralizes Unicode-normalized and combining-mark-obscured spreadsheet formula prefixes when original IDs are explicitly included. This is a **safe review export** only, not a claim that the original underlying SQL tables are fully repaired or permitted for actual activation.


## Source-bound human review workflow

1. Authenticate with an existing, persisted LightUp operator. Export a new private `.html` for one original scope or a `--scenarios-file` set. The original authorization and stored request fields remain read-only.
2. Open that 0600 file locally, filter by original administrator status or source mismatch and choose a **human-only** follow-up owner and stage. Local notes are not transmitted to any party.
3. Explicitly save a PRIVATE local working draft (includes original request pseudonyms, notes and an unsigned source+proposal fingerprint). Keep it in a restricted directory. This file is **not** consent, a grant, a release certificate or an incident event.
4. For coordination beyond the authorized operator, choose anonymous aggregate JSON or CSV. Aggregates omit original record keys, request IDs, tenant/engagement labels, exact original-source fingerprints, asset literals and private notes.
5. For resumption, reopen the same original HTML source copy, import the matching PRIVATE draft; the entire import is refused on schema, source revision, proposal, row identity, authority, or value inconsistency. **No human stage is automatically carried over to changed source records.**

Data stays in browser memory until explicit file downloads. Clearing local state or closing the document does not change stored LightUp request, grant or session records. The original source must be reauthenticated and re-exported before treating it as fresh evidence.


## Source reason-driven human follow-up (offline)

The new original-source issue panel groups request-binding mismatch categories emitted by the existing canonical #1570 predicate explanation. Each group lists the fixed human question and intended client/operator/security-source-owner channel, counts both occurrence frequency across human alternatives and distinct original pseudonymous request records, and differentiates still-unreviewed versus locally escalated work. The operator may explicitly confirm **Prepare unanswered** or **Escalate unanswered** for an entire reason; this changes only local unreviewed human discussion states, never already handled cases or any original backend request/grant/consent status. Aggregate JSON includes fixed source reason categories and source-only counts, without original record IDs, names, asset details or operator notes.


## Integratie met LightUp Scope Planning Studio

De operator kan nu 1–8 originele JSON-voorstellen van de afzonderlijk gebouwde Scope Planning Studio (PR #1567) gebruiken als invoer voor deze echte, geauthenticeerde maar NIET-autoriserende request-bindingverkenning. Herhaal hiervoor --studio-proposal /private/proposal-a.json (en desgewenst --studio-proposal /private/proposal-b.json), naast de bestaande verplichte --db, --email, --engagement-id en --output parameters. --asset/--risk/--scenarios-file kunnen niet samen met Studio-import worden gebruikt.

De import leest uitsluitend een v1 DRAFT_ONLY JSON-export. Het originele operatoraccount, de opgeslagen echte engagement-eigenaar, de oorspronkelijke klantverzoeken en exact dezelfde request-compatibiliteit uit bronhouder-PR #1570 blijven leidend. De losse client_label, proposal_name en notes uit Studio zijn NIET de geauthenticeerde cliënt/tenantidentiteit en creëren geen instemming.

De vertaling weigert ongeldige/extra JSON-velden, dubbele sleutels, ontbrekende of afwijkende false authority-vlaggen, elke assetuitsluiting (kan niet stilzwijgend worden genegeerd), private lab-netwerkchecks, analysis_only, dubbele voorstellen, niet-canonieke host/IP/CIDR, onjuiste risico's en inconsistente lokale/UTC-planningstijden. De oorspronkelijke optionele Studio-draft-SHA wordt op basis van de originele v1 canonicalizer nagekeken: nog steeds uitsluitend ongetekende lokale integriteitsinformatie, NOOIT een cliëntsignatuur.

Bij 1 voorstel ontstaat de bestaande privé-operatorreview; bij 2–8 voorstellen volgt de al gebouwde gezamenlijke read-only vergelijking, met afzonderlijke menselijke opvolging, lokale werkstatus en brongebonden conceptoverdracht. De Studio-branch zelf, oorspronkelijke grant-issuer, werkende security gates, CI, echte toestemming en productie zijn niet aangepast.
