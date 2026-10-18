# LightUp · Authenticated Approved-Request Selection Readiness Desk

**Companion to existing source-owner PR #1570 and issue #177.** This new-only standalone Python CLI never edits owner files, grant issuance, portal, production policy, runners or CI.

## Usable product

An actual persisted LightUp operator can preview whether zero, one or several real, previously administratively approved client assessment requests match a proposed engagement, set of canonical asset literals and maximum risk **without issuing any grant**. The original, pinned source-owner compatible-request predicate is used, rather than a rewritten authorization policy. Underlying assessment/grant SQL is read through a separate query-only SQLite transaction.

The private output shows original request review statuses, strict mismatch versus matching candidate, historical grant-request binding row counts, legacy unbound grant counts, and current-tenant/engagement source warnings. A single match is only REVIEW_ONLY_SINGLE_CANDIDATE. Multiple matches are HOLD_AMBIGUOUS_CANDIDATES; zero is HOLD_NO_CANDIDATE.

Three formats: accessible script-free private HTML, private JSON, formula-escaped CSV. Output is bounded and new-only (mode 0600). Original request IDs and client/engagement labels require separate opt-in options; the default uses private pseudonyms and counters. SHA-256 selection digest is unsigned and no permission certificate.

## How to use

In a separate authorized local environment, using a genuine LightUp database and existing operator account:

    PYTHONPATH=src python3 -m lightup.request_binding_readiness_cli \
      --db /private/lightup.db --email operator@example.org \
      --engagement-id EXISTING_ID --client-id EXPECTED_CLIENT_ID \
      --asset example.org --asset 192.0.2.0/24 --risk 2 \
      --output /private/request-binding-shortlist.html

The CLI requires an interactive password prompt; passwords cannot be passed as argv or env. Choose new .json or .csv filename for an alternative private format. The opt-in --include-request-ids shows real stored IDs where needed for separately authorized operator reconciliation. --include-labels shows client/engagement names.

Original DomainStore password authentication **does** mutate original sign-in bookkeeping and may use existing schema migration; only the subsequent request/grant inspection is strictly read-only. This is not a DB byte-level immutability tool.

## Release safety

INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. A compatible administrative request is not authentic client/operator consent, a grant or live permission; the actual source owner must revalidate request provenance, tenant, scope, risk and window inside the later write transaction. This CLI cannot approve, issue/revoke a grant, create accounts, dispatch handlers, touch targets, scan, retest, deploy or release. Real authenticated independent client and operator consent including at-use revocation, independent security/privacy and original exact-head hosted + named permanent VPS CI and human GO remain mandatory.

Separate original owners: [source PR #1570](https://github.com/Zennay/Lightup/pull/1570) · [issue #177](https://github.com/Zennay/Lightup/issues/177). No QA/regression/testsuites authored or run.
