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

## Private, source-free offline safety-canary handoff

For an owner-private, operator-readable synthetic M1 receipt, run:

```sh
lightup-lab-safety-canary --private-report-dir /private/NEW-DIRECTORY
lightup-lab-safety-canary --verify-private-report-dir /private/NEW-DIRECTORY --format json
```

The first command runs the existing fixed-loopback canary and creates only a
**new** non-overwriting directory (0700) containing `canary.json`,
`operator.txt`, and a digest-bound `manifest.json` (0600 each). The manifest
is written last, so a missing manifest means an incomplete handoff. The
second command does **not** rerun any scorer: it performs descriptor-pinned,
no-follow, strict-schema and local byte-integrity checks, returning PASS or
HOLD. Extra files, altered bytes, unsafe authority flags, unexpected keys,
symlinks, and non-private file permissions are refused. Even with an
attacker-recomputed unsigned manifest, the full operator text must exactly
match the first-party summary reconstructed from the admitted JSON; forged
passive approval/clearance instructions are rejected by **both** the
producer (before directory creation) and the recipient. No external target
is contacted by the reader.

The manifest is **not signed**. A matching digest establishes only local
byte consistency, **not** independent source authenticity, operator identity,
consent, client authorization, security approval, or deployment clearance.
A failed save or verification exits 2 with a privacy-minimal HOLD receipt.
Creation and verification options are mutually exclusive. These offline
reports contain only first-party synthetic localhost observations.

## Exact first-party scorer contracts

The offline gate now rejects a scorer even if it claims `passed=true`
when any of its 16 canonical metrics are missing or inconsistent. The
false-positive rate must be exactly zero; assessed coverage must be one;
remediation/retest quality must be zero for fixed non-remediation fixtures;
runtime must be finite and non-negative. The top-level and persisted
evaluation run/scenario/record IDs must match. This closes a reproduced
false-PASS for a 75% false-positive rate with forged evaluation lineage.
All checks remain synthetic lab-only and confer no production authority.

## In-process loopback socket boundary

During the three fixed M1 scorers, the installed offline safety canary
temporarily restricts Python socket connect, connect_ex, bind, sendto,
sendmsg and getaddrinfo to the exact IPv4 `127.0.0.1` lab address. It
refuses wildcard binds, hostnames, IPv6 and other IPv4 destinations before
the blocked socket call reaches the OS. The boundary restores all socket
functions after success or a failed scorer. Its receipt includes
`fixed_loopback_socket_boundary_enforced=true`.

**Limit:** this is a process-wide Python socket boundary for a standalone
single-invocation CLI, not a kernel-level network namespace, egress firewall
or containment for subprocesses, raw native calls or concurrent untrusted
threads. Production or untrusted code still requires an externally enforced
isolated network. There is no external-target, deployment or grant authority.

### Direct scorer commands

The three individually installed scorers (`lightup-lab-service-score`,
`lightup-lab-tls-score`, `lightup-lab-web-score`) and their public Python
`run_lab_*_score` APIs now also enter the same temporary in-process
loopback gate. The combined canary checks them in a second, outer boundary.
Direct invocation cannot turn off the restriction with a CLI parameter.
This still is **not** a substitute for an OS egress firewall or namespace.

On direct scorer failure, the JSON CLI returns exit 2 with a fixed
`passed=false` and `error="offline fixture denied or unavailable"`; it
never echoes a private SQLite path, exception string, or rejected input.
All four installed CLIs use the same private-safe argument parser.


The socket boundary also denies `gethostbyname`, `gethostbyname_ex`,
`gethostbyaddr` and `getnameinfo`, plus nonnumeric `getfqdn` calls,
so standalone scorers do not initiate hostname or reverse-DNS lookups.
The standard HTTP fixture's numeric `getfqdn("127.0.0.1")` returns the
same literal without reverse resolution. This remains a Python in-process
restriction, not OS-level egress isolation.


### Exact scorer PASS validation on every public command

All three standalone `lightup-lab-*-score` CLIs now reuse the same canonical
`lightup.lab_score_contract.require_first_party_score` as the combined
safety gate. A source reporter cannot return exit code 0 merely by setting
`passed=true`: its full first-party check inventory, all canonical metrics
and run/scenario/record lineage must also pass. A forged 75% false-positive
rate with inconsistent run ID previously returned success from a standalone
CLI; it now returns exit 2 with the private-safe error receipt. No external
target capability or grant is introduced.

The canonical contract also requires the **exact source-defined scenario**
identifier for service inventory, TLS baseline and HTTP security headers.
A scorer cannot make a different scenario PASS merely by rewriting both
top-level and persisted scenario IDs to the same forged value. Regression
coverage exercises this swap through all three direct scorer CLI surfaces.

### First-party evidence and engine completeness

A direct scorer or the combined safety gate now admits PASS only if the saved
evaluation contains the exact first-party engine version, no external model
bindings, and exactly one distinct canonical UUIDv4 evidence ID per expected
tool observation (2 service, 2 TLS, 4 HTTP). Reproduced false-green receipts
with zero evidence, duplicate evidence and unknown engine names now fail
closed. These checks validate the source-reported evidence envelope; they do
not establish independent cryptographic provenance of persisted evidence or
grant permission to run outside fixed loopback.

### Privacy-safe HOLD diagnostics

A failed combined canary now includes a fixed `failure_stage` of `setup`,
`service`, `tls`, or `http` in its machine-readable HOLD receipt.
The optional human-readable report likewise displays only the stage name.
A failed scorer never exposes an exception message, private evidence path,
tenant identifier, target, or run ID. PASS output remains backward
compatible. The stage is for offline operator troubleshooting only and
never authorizes a skipped check or a retry against an external target.

### Fixed scope and plan provenance for the operator canary

The combined canary now verifies the full source-defined CLI scope refusal:
`scope-check 8.8.8.8` must exit 2 with exactly the expected target,
`allowed=false` boolean and `out_of_scope` reason. For the local
`plan 127.0.0.1`, the response must include the exact loopback target,
typed loopback scope and `execution_enabled=false`, with distinct
canonical capability IDs including both local service and HTTP baselines.
Mismatched targets, duplicate identifiers or integer/boolean substitution
no longer qualify as an offline calibration PASS. This does not authorize
any action against 8.8.8.8 or another external target.

The accepted plan capability list must now exactly match the current
source-defined registry's `planning` and `lab_only` capabilities, in
registration order. A synthetic injected capability, a missing registered
capability, or reordered list was previously incorrectly accepted by the
offline canary; all now produce HOLD. The plan remains non-executing even
when its complete registry list is valid.

### Bounded local policy subprocesses and visible source contracts

The fixed `scope-check` and `plan` child CLI calls now use closed stdin and
a 10-second upper time bound. A stuck child returns a generic setup HOLD
without exposing the underlying process path or exception. On PASS the JSON
receipt explicitly reports `scope_refusal_contract_verified`,
`plan_registry_contract_verified` and
`scorer_evidence_contract_verified`, with the same checks in the operator
text summary. These are offline source-integrity observations only; the
receipt still says no external-target or deployment authorization.
