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
