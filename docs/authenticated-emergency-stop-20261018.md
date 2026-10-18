# LightUp — authenticated emergency STOP

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a credential-backed durable emergency STOP recorder. It is not an end-to-end action-time revocation gate until original execution owners explicitly wire the veto into the runtime and independently review it.

## Discover your engagements (authenticated inbox)

    PYTHONPATH=src python -m lightup.revocation_stop list \
      --database /private/path/lightup.sqlite \
      --email your-existing-account@example.invalid

This read-only inbox gives at most 100 actual persisted engagement IDs, their original product status, and their independent STOP state. Owning client accounts see only their own tenant; a verified operator sees authorized cross-tenant coordination inventory. It never prints client labels, contacts or reasons. A not-yet-created ledger is displayed as HOLD_LEDGER_NOT_INITIALIZED rather than misleadingly claiming an active authorization. Inbox is REVIEW_ONLY and returns exit code 2, not an execution success signal.

## Prepare an empty STOP ledger (real operator only)

An empty legacy domain SQLite will not silently be treated as permission. Before the original runtime owner opts into the separate stop_policy_adapter, a real persisted operator must deliberately install the empty STOP event table:

    PYTHONPATH=src python -m lightup.revocation_stop init \
      --database /private/path/lightup.sqlite \
      --email existing-operator@example.invalid

The original login prompt and lockout apply. Setup creates only an append-only deny ledger and index inside one SQLite transaction, checks the expected column names/types/keys, and returns LEDGER_INITIALIZED_REVIEW_ONLY. It creates no client approvals, scope, grants or execution permission. A missing, malformed or inconsistent ledger still yields HOLD in the deny-only runtime observer; an empty valid ledger remains insufficient to authorize any target. Never initialize a fresh external database or use this command as a release/runner gate.
## Record an emergency STOP

From an isolated, locally installed LightUp checkout with an existing local SQLite domain and authenticated client/member/admin or operator account:

    PYTHONPATH=src python -m lightup.revocation_stop stop \
      --database /private/path/lightup.sqlite \
      --engagement EXACT_EXISTING_ENGAGEMENT_ID \
      --email your-existing-account@example.invalid \
      --reason "Owner requested stop" \
      --receipt /private/path/NEW-stop-receipt.json

The command interactively prompts for the real persisted account password using the original DomainStore login and lockout; it never accepts a password argument. The authenticated account's persisted role and tenant are rechecked inside the STOP transaction. A client can stop only their own engagement. A real unbound operator can record STOP for selected engagements.

The credential-protected record_authenticated_stop public API authenticates an original domain user itself; callers cannot supply a claimed actor ID. The first STOP creates a separate append-only event table and index inside the same SQLite write transaction as the first event; all later STOPs remain distinct historical events. No unstop, resume, authorize, dispatch, scan, target, model, or grant operation exists in this module. A requested receipt is only created at a new owner-only mode-0600 path and can never replace a prior file. Receipt creation happens AFTER the STOP commit, so receipt failure does not undo the STOP. A new 0600 staging file is fsynced and then atomically hard-linked to the final never-overwritten destination; partial final receipts are not exposed. Reasons are private DB text and never printed in stdout.

## Inspect current STOP status

    PYTHONPATH=src python -m lightup.revocation_stop status \
      --database /private/path/lightup.sqlite \
      --engagement EXACT_EXISTING_ENGAGEMENT_ID \
      --email your-existing-account@example.invalid

A freshly authenticated operator or owning client receives at most 64 history items (time, actor role, opaque event ID) with an explicit truncation marker. Valid inspections return exit 2 because inspection is never authorization; any missing table, unknown engagement or invalid actor returns HOLD and exit 3. The command never echoes actor email, customer names, private reasons, database paths or passwords.

## Distinct-operator STOP follow-up

An authenticated operator can coordinate the emergency queue without revealing tenant IDs or reasons in terminal output:

    PYTHONPATH=src python -m lightup.stop_acknowledgment pending \
      --database /private/path/lightup.sqlite \
      --email other-operator@example.invalid

Up to 100 oldest still-unacknowledged STOP events are returned in source order (STOP ID, creation instant and role category). The command never uses target IPs, client labels, reason details or any pending scan.

A separately authenticated REAL operator, different from the original STOP actor, can record a one-time acknowledgment:

    PYTHONPATH=src python -m lightup.stop_acknowledgment ack \
      --database /private/path/lightup.sqlite \
      --email different-operator@example.invalid \
      --stop-id EXISTING_STOP_EVENT_ID

The additional table records acknowledgment identity, original STOP ID and timestamp in one database transaction, UNIQUE per STOP; it cannot remove, reverse, supersede or release the original STOP. Two different accounts are required for the acknowledgment event; this is human coordination, **not** two-party client/operator permission to execute. If the original STOP is corrupt/missing or the operator is not currently active in the original users table, the action fails HOLD without recording a false acknowledgment.

## Optional offline graphical STOP console

Open the new local stop-console/standalone.html directly in a trusted modern browser. It is a single responsive HTML/CSS/JS file, with a restrictive offline Content Security Policy; no server, network request, scanner, account password, external package or browser persistence. It shows original CLI data as declared/unverified source and never decides permission.

First export a private status artifact from the original CLI in a trusted local terminal (not a repo path). For example:

    umask 077
    PYTHONPATH=src python -m lightup.revocation_stop list \
      --database /private/path/lightup.sqlite \
      --email your-existing-account@example.invalid \
      > /private/path/NEW-engagement-inbox.json

The list and pending commands deliberately exit 2 because they only inspect. The private file contains original engagement IDs and should never be committed, publicly uploaded or emailed unencrypted. Use the graphical file chooser to import up to five real original CLI JSON exports: the authenticated engagement inbox, operator pending STOP inbox and selected status history. The desk validates bounded record shapes and literal-false authority flags, renders IDs as text rather than executable HTML, allows local filtering and prints a review brief. The exported aggregate JSON contains counts only, never private identifiers, original reasons, email addresses, timestamps or engagement labels. Import failures preserve the prior workspace. A clearly labeled fictional demo is available without any private source.

The console cannot send a STOP, acknowledge a STOP, sign in a user or resume a task. These remain native credential-protected CLI actions; the browser only displays previously obtained private source data. A correctly shaped imported JSON file is NOT authenticated evidence or permission. No source file should be trusted to override original authorization or consent policy.

## Atomic multi-engagement incident STOP

For a manually selected incident scope of 1–32 existing engagements, the new native module performs a single authenticated, all-or-nothing SQLite transaction. It first validates every engagement against the original persisted user/tenant relationships, then inserts one independent irreversible STOP per engagement. If any selected ID is invalid, inaccessible or duplicated, nothing is written.

    PYTHONPATH=src python -m lightup.stop_batch \
      --database /private/path/lightup.sqlite \
      --email original-account@example.invalid \
      --engagement FIRST_ID --engagement SECOND_ID \
      --receipt /private/path/NEW-incident-stops.json

Authentication uses existing password and lockout. A client may select only its own tenant, while a genuine operator may explicitly select multiple tenants. This is a deny-only incident intake, not a batch grant, and it never runs tools or changes the original assessment scope. The CLI prints only a bounded aggregate status; per-engagement STOP IDs appear in the optional private 0600 receipt, never public stdout. Failure to create a receipt after database commit cannot undo stops. The reason is stored privately; avoid secrets in shell arguments.

## Interactive original-account incident control room

An operator or client can use all the existing deny-only workflows in a single guided private terminal instead of constructing multiple commands:

    PYTHONPATH=src python -m lightup.stop_ops \
      --database /private/path/lightup.sqlite \
      --email original-registered-account@example.invalid

The menu authenticates with the genuine DomainStore credentials, then offers real persisted engagement inbox, bounded 1–32 engagement incident STOP, one engagement history, operator pending STOP queue, distinct-operator acknowledgment and operator-only schema initialization. It does not expose an authorization, restart, grant, scan, model or dispatch command. Batch action requires selecting listed row numbers and typing the literal STOP plus exact count; acknowledgment and ledger initialization also require explicit confirmation. Source access is tenant-rechecked, and every database mutation uses the existing authenticated source-level writer. The process ends on q or after a bounded number of interactions.

After a successfully committed batch, the operator can optionally enter a NEW private receipt destination. An exclusive atomic 0600 file may then be created. Failure to publish the file reports that the STOP is already committed; it never falsely reports cancellation. The operator controls the terminal, and any displayed private engagement/STOP IDs must not be copied to public logs or issue trackers. Account password is held in this foreground terminal process until it ends; close the process on a shared computer.
## Opt-in original tool-policy STOP integration candidate

The new src/lightup/stop_policy_adapter.py composes (rather than replaces) the original ExecutionPolicy and ToolExecutor in a separate NEW source file. The original registry, mode, risk and evidence gates remain installed. It requires the exact immutable RunContext instance and matches real authorization grant client/engagement lineage. It reads the original SQLite STOP ledger before and after the original policy decision; active or uncertain STOP yields a denied PolicyDecision. The only installed entrypoint is an explicit developer opt-in:

    from lightup.stop_policy_adapter import create_stop_aware_executor
    guarded = create_stop_aware_executor(
        database=PRIVATE_DB, run_context=original_run,
        registry=original_registry, state=original_evidence_store,
    )
    # Existing original per-call context identity is mandatory.
    # Do NOT dispatch tools merely because a STOP is absent.

This is a product source integration seam for the original runtime owners, **not a production default**. It does NOT intercept direct calls to unmodified ToolExecutor, existing handlers, live scanners, asynchronous workers, or already running tasks. Read-before/after-decision still has a time-of-check/time-of-use race before handler dispatch. The original owners must separately install an atomic action-time revocation boundary and preserve authentic client/operator consent before release.

## Read-only stored-grant exposure for a STOP engagement

A STOP event in this local module is **not** an automatic revocation of older grant rows or background jobs. Operators must therefore see whether persisted authorization_grants rows still exist for an affected engagement. The new credential-protected source inventory makes that operational gap explicit:

    PYTHONPATH=src python -m lightup.stop_exposure \
      --database /private/path/lightup.sqlite \
      --engagement EXACT_EXISTING_ENGAGEMENT_ID \
      --email original-registered-account@example.invalid

The CLI authenticates with the original DomainStore password and lockout, rechecks the real tenant role inside a read-only SQLite snapshot, requires a canonical STOP ledger, and collects a bounded maximum of 256 existing grant rows for the selected engagement. It rejects cross-tenant stored rows and marks corrupt datetime provenance HOLD. Output shows only **aggregate** stored-grant counts, legacy unbound versus request-linked grant counts, claimed current date-window count and whether a STOP is recorded. It does not print original customer names, hosts, grant IDs, tokens or grant dates. Both the terminal incident control room (menu 7) and offline STOP console can display this schema.

Count labels are explicitly **stored source declarations**, never verified live authorization. A source grant might have expired, been revoked elsewhere, or failed the original request/consent checks. In particular, a STOP_WITH_STORED_GRANTS record requires independent source-owner action and never means that our local STOP has made all existing executor instances stop. Source review exits 2 (REVIEW_ONLY); errors exit 3 (HOLD); no permission/exit 0.
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
