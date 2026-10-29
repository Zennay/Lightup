# TCP service-inventory labeval

This command scores the existing TCP service-inventory worker against an
owned loopback listener and a separately allocated closed-port control.

## Run

    PYTHONPATH=src python -m lightup.lab_service_score --db /tmp/lightup-service-score.db

After installing the package, use:

    lightup-lab-service-score --db /tmp/lightup-service-score.db

## Scoring contract

- The scorer owns a temporary TCP listener bound only to 127.0.0.1 and a
  separately allocated port expected to be closed.
- Two observations use the real registered worker through ToolExecutor in one
  lab run context.
- The open listener must be found on both observations; the closed control
  must not appear as an open service.
- Each observation must persist a distinct evidence record with the expected
  run ID, capability, source, evidence kind and explicit lab marker.
- The canonical StateStore evaluation record is written and read back; the
  producing run and evidence IDs must match.
- A successful score requires one valid finding, zero invalid or missed
  findings, stable repeat observations and evidence quality of 1.0.

A failed ground-truth, repeatability, evidence-lineage or persistence check
returns a nonzero exit code. The output contains the loopback fixture ports,
aggregate metrics, checks and record identifiers, not raw evidence payloads.

The command accepts no target override and makes no external network request.
It does not issue grants, dispatch work, authorize real targets, run
remediation, or deploy. A local score is calibration evidence only; it is not
proof of external authorization or release readiness.

## Installed offline safety gate

Run `lightup-lab-safety-canary` for one machine-readable local authentication,
refusal, loopback service/TLS/HTTP scoring and cleanup summary. Only fixed
127.0.0.1 fixtures are used; all CLI overrides are rejected. A PASS asserts
`lab_only=true` and both `external_target_authorized=false` and
`deployment_authorized=false`. No authority or external evidence is implied.

The safety gate's mandatory checks run even with optimized Python (`python -O`
or `PYTHONOPTIMIZE`); failed scorer metrics, login/scope denial or cleanup
raise a generic failure instead of falsely reporting a successful calibration.
Only the web shell's expected argument-type denial counts as a valid bind refusal.

The combined gate requires complete named scorer checklists and canonical
numeric metric types, 2/2/4 tool calls, zero policy/scope/human interventions
and zero compute cost. Missing checks, integer booleans or negative-zero cost
never satisfy PASS.

The installed canary emits one JSON result with `status=PASS` and
`passed=true` on valid local calibration. If a check or runtime step fails,
it returns exit 2 and only `status=HOLD`, `passed=false`, lab-only and
false external-target/release flags. Failure receipts omit exception contents,
private paths, run identities and evidence payloads. Invalid CLI arguments
are rejected before executing the lab.

Unknown CLI arguments are rejected with a generic error that does not echo
user-supplied target or file-path values into shared operator logs.

## Local operator session lifecycle

The fixed WSGI canary also checks an actual synthetic operator session:
a forged session cookie must redirect to login; a wrong-CSRF logout must
return 403 **without** invalidating the valid session; a correct-CSRF logout
must revoke the stored token, after which the same cookie must be denied.
The output adds three privacy-minimal booleans. No client user, real grant,
external target or production session is involved.

## Synthetic tenant boundaries

The same isolated WSGI/SQLite canary now provisions two clearly fictional
tenant identities. It verifies that tenant A can read only its own portal,
cannot read tenant B's portal or submit a request on behalf of tenant B,
and can submit one explicitly synthetic assessment *request* for itself.
The second tenant's request list must remain empty. This only validates
request admission and isolation in ephemeral local data: it does **not**
approve a request, issue a grant, authorize scanning, execute any target,
or contact an external service. A PASS receipt carries three booleans,
not client identifiers or request contents.

The synthetic client session is also denied access to the operator dashboard.
An otherwise valid request with mismatched Origin or cross-site Fetch Metadata
must be rejected before SQLite mutation, while an equivalent same-origin
request with valid CSRF is accepted as an unapproved synthetic request.

## Offline operator safety summary

The installed `lightup-lab-safety-canary --format text` command displays a
brief human-readable PASS/HOLD summary of auth/session boundaries, tenant
isolation and the three known synthetic scorer outcomes. The existing
machine-readable JSON receipt remains the default, including for CI.
Failures return code 2 in both modes, without private exception content.
The `--format` option cannot select a network target or source dataset.
Neither receipt grants any external-target, deployment or release authority.
