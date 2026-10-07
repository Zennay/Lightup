# Tenant finding CSV export

`lightup.finding_export_service.render_client_findings_csv(store, ctx, client_id,
engagement_id=None)` selects durable findings for one explicit client through
the existing DomainStore authorization methods, then uses the guarded summary
renderer added in PR #956.

The caller must authenticate first and obtain the AccessContext from its
authenticated session. The function does not accept a user-selected role,
authenticate credentials, bootstrap an operator, or create an access context.

Operators name one client explicitly; client members/admins can select only
their own client. An optional engagement filter must belong to the same
selected client. The service verifies each returned finding's client and
engagement ownership before producing output. Corrupt duplicated tenant
metadata and orphaned engagement lineage fail closed; nothing is repaired or
written. Empty output means no selected findings, not a clean bill of health.

Only summary fields leave the service. Targets, impact text, evidence IDs and
metadata are not copied into output. The shared summary renderer applies
credential-pattern redaction and spreadsheet formula guards. Operators must
still review free text before sharing.

All reads use existing domain boundaries. This service does not promise a
transactional snapshot across concurrent database changes; a future web route
must preserve session authentication, no-store headers and explicit tenant
selection. No web route or CLI authentication mechanism is introduced here.

The changes are new module/tests/docs only. Domain source, AccessContext,
existing web routes, Markdown reporting and parallel source-owner branches
remain unchanged. Standard exact-head hosted and permanent VPS validation
must pass before merge.
