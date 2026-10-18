# LightUp — authenticated emergency STOP

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a credential-backed durable emergency STOP recorder. It is not an end-to-end action-time revocation gate until original execution owners explicitly wire the veto into the runtime and independently review it.

## Record an emergency STOP

From an isolated, locally installed LightUp checkout with an existing local SQLite domain and authenticated client/member/admin or operator account:

    PYTHONPATH=src python -m lightup.revocation_stop stop \
      --database /private/path/lightup.sqlite \
      --engagement EXACT_EXISTING_ENGAGEMENT_ID \
      --email your-existing-account@example.invalid \
      --reason "Owner requested stop" \
      --receipt /private/path/NEW-stop-receipt.json

The command interactively prompts for the real persisted account password using the original DomainStore login and lockout; it never accepts a password argument. The authenticated account's persisted role and tenant are rechecked inside the STOP transaction. A client can stop only their own engagement. A real unbound operator can record STOP for selected engagements.

The first STOP creates a separate append-only event table and index inside the same SQLite write transaction as the first event; all later STOPs remain distinct historical events. No unstop, resume, authorize, dispatch, scan, target, model, or grant operation exists in this module. A requested receipt is only created at a new owner-only mode-0600 path and can never replace a prior file. Receipt creation happens AFTER the STOP commit, so receipt failure does not undo the STOP. Reasons are private DB text and never printed in stdout.

## Inspect current STOP status

    PYTHONPATH=src python -m lightup.revocation_stop status \
      --database /private/path/lightup.sqlite \
      --engagement EXACT_EXISTING_ENGAGEMENT_ID \
      --email your-existing-account@example.invalid

A freshly authenticated operator or owning client receives at most 64 history items (time, actor role, opaque event ID) with an explicit truncation marker. Valid inspections return exit 2 because inspection is never authorization; any missing table, unknown engagement or invalid actor returns HOLD and exit 3. The command never echoes actor email, customer names, private reasons, database paths or passwords.

## Future required action-time integration

The module exposes deny_only_stop_state(db_path, engagement_id=..., client_id=...) for the ORIGINAL runtime owner to install as an additional veto alongside existing canonical scope, client/operator consent, request/grant/activation, risk and tool policy. This function returns STOP_ACTIVE, NO_STOP_RECORDED or HOLD; it returns veto_execution true for STOP_ACTIVE or HOLD, and ALWAYS returns authorization_granted false, execution_allowed false, release_approved false. NO_STOP_RECORDED is not proof of authorization and is never an allow permit. The existing live runtime **does not yet call this module**. A STOP entered here does not magically stop an already running or unrelated process. No concurrency or distributed kill guarantee is claimed.

## Storage and security limits

- The source works only against an EXISTING regular domain SQLite path and refuses a final-component symlink; do not supply external, world-readable or untrusted directories.
- Persisted events include UTC timestamp, real original user ID and role, tenant, engagement, reason (at most 500 characters) and opaque STOP ID. The stop path performs tenant and current persisted role checks in a transaction.
- The private local JSON receipt is not remotely signed or cryptographically attested. A direct local SQLite administrator can modify the database; this is not a tamper-proof remote service.
- Avoid sensitive text in the --reason command-line argument because OS process listings or shell history may retain it. Omit it for sensitive incidents.
- A script calling internal functions without the authenticated CLI is NOT a substitute for a trusted server session. Real web integration must independently authenticate the session at the action instant, use explicit client/operator approval, and enforce the veto at each dispatch/retry/resume.
- No scanner, model, target interaction, production deployment, or real external consent is initiated.

## Ownership / gates

Own new-only source and documentation paths in a separate child branch based on stacked source integration candidate PR #1618. Other owner's open production modules, web routes, ToolExecutor, deployment configuration, grants, CI workflows and test files remain unmodified. No new QA, regression or test suite is authored or run.

Status **DRAFT/HOLD**. Required before merging or deploying: independent source-owner and privacy/security review, exact-head hosted and permanently registered named VPS CI, authentic separate client/operator consent with authoritative action-time revocation, original authorization and grant provenance policy, explicit human GO. This child branch is source/coordination progress, NOT production safety or release approval.
